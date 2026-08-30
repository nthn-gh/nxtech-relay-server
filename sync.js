/**
 * NXTech POS Pro relay — Remote Monitoring Dashboard: app-facing sync API.
 *
 * Everything here is authenticated by a per-shop sync_token (issued by
 * /sync/register, sent as `Authorization: Bearer <token>`). shop_id is
 * NEVER read from a request body or query param on any of these routes --
 * resolveShopFromSyncToken() below, and ONLY that function's result, is
 * the source of truth for which shop a request belongs to. This is the
 * same "client-trusted value" bug class the app's own sale-totals audit
 * already caught once; treated here as a standing rule, not a one-time
 * check (see remote-monitoring-dashboard doc finding #2).
 *
 * remote_monitoring is self-service: unlike remote_access/mobile_data
 * (deliberately provisioned via admin.js + subscribers.json), any shop
 * with a valid signed Premium license can register here with no manual
 * step. Nothing in this file touches subscribers.js.
 */
import { randomBytes, createHash } from 'crypto'
import { db, nowIso } from './db.js'
import { verifyNxv2License } from './licenseVerify.js'
import { checkAndConsume, sweepExpired } from './rateLimiter.js'

const SYNC_TOKEN_BYTES = 32

// Registration should be rare (once per enable/re-enable) -- generous
// limit exists to bound a broken/looping client, not constrain normal use.
const REGISTER_RATE_LIMIT = 10
const REGISTER_RATE_WINDOW_MS = 60 * 60 * 1000 // per IP, 1 hour

// The app pushes every ~90s-30min (see remoteSync.service.js's backoff);
// 120/hour is comfortable headroom above that without allowing a
// compromised/buggy token to hammer the relay.
const PUSH_RATE_LIMIT = 120
const PUSH_RATE_WINDOW_MS = 60 * 60 * 1000 // per token, 1 hour
const MAX_ROWS_PER_PUSH = 500

const PAIRING_CODE_RATE_LIMIT = 20
const PAIRING_CODE_RATE_WINDOW_MS = 60 * 60 * 1000 // per shop token, 1 hour

// No 0/O/1/I/L -- avoids visual ambiguity when a human types this into a
// browser. 33^10 =~ 1.9x10^15 possible codes -- see dashboard.js for how
// the attempt cap and rate limiting bound guessing regardless.
const PAIRING_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
export const PAIRING_CODE_LENGTH = 10
export const PAIRING_CODE_TTL_MS = 15 * 60 * 1000
export const MAX_CLAIM_ATTEMPTS = 5
// How many leading characters of a WRONG guess dashboard.js's
// recordFailedClaimAttempt() uses to find the specific active code it was
// aimed at (see db.js's pairing_codes comment for why this needs plaintext
// storage). 33^4 =~ 1.19M combinations -- at this relay's realistic active-
// code count (single digits at any moment), the odds of two different
// shops' codes colliding on their first 4 characters are negligible, so a
// prefix match reliably identifies the one code a near-miss guess targeted
// without needing the guess to be fully correct.
export const PAIRING_CODE_PREFIX_LENGTH = 4

const MAX_BODY_BYTES = 256 * 1024 // 256KB -- generous for a batch of outbox rows, still bounded

export function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex')
}

function generateToken() {
  return randomBytes(SYNC_TOKEN_BYTES).toString('base64url')
}

export function generatePairingCode() {
  const bytes = randomBytes(PAIRING_CODE_LENGTH)
  let code = ''
  for (let i = 0; i < PAIRING_CODE_LENGTH; i++) {
    code += PAIRING_CODE_ALPHABET[bytes[i] % PAIRING_CODE_ALPHABET.length]
  }
  return code
}

// Shared by sync.js and dashboard.js -- collects and JSON-parses a request
// body, bounded so an oversized body can't be used to exhaust memory.
export function readJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let raw = ''
    let rejected = false
    req.on('data', (chunk) => {
      if (rejected) return
      raw += chunk
      if (Buffer.byteLength(raw) > maxBytes) {
        rejected = true
        reject(new Error('Request body too large'))
        req.destroy()
      }
    })
    req.on('end', () => {
      if (rejected) return
      if (!raw.trim()) return resolve({})
      try {
        resolve(JSON.parse(raw))
      } catch (_) {
        reject(new Error('Invalid JSON body'))
      }
    })
    req.on('error', reject)
  })
}

export function sendJson(res, status, body) {
  const data = JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(data)
}

export function getBearerToken(req) {
  const header = req.headers['authorization'] || ''
  const match = /^Bearer\s+(.+)$/i.exec(header)
  return match ? match[1].trim() : ''
}

// Only trust X-Forwarded-For when the request's own TCP connection came
// from THIS machine's loopback interface -- i.e. nginx, running on the
// same VPS, forwarding it here after its own real_ip module has already
// derived the real visitor IP from CF-Connecting-IP (see
// dashboard-web/README.md's nginx config). This relay's listen HOST
// defaults to 0.0.0.0 (deliberately -- /sync/* and /connect need to stay
// directly reachable by the desktop app, not hidden behind Cloudflare),
// so this port is NOT exclusively reached via nginx: a remote attacker can
// connect to it directly and send any X-Forwarded-For value they like.
// Trusting that header unconditionally would let them forge a fresh IP on
// every request and defeat every per-IP rate limit in this file. A
// spoofed TCP source address can't complete a real handshake over the
// public internet, so req.socket.remoteAddress itself is never forgeable
// this way -- only requests that are ACTUALLY local get the header
// trusted; everyone else's rate-limit key is their real, unspoofable peer
// address.
const LOOPBACK_ADDRESSES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1'])

export function getClientIp(req) {
  const remoteAddress = req.socket?.remoteAddress || ''
  if (LOOPBACK_ADDRESSES.has(remoteAddress)) {
    const forwarded = req.headers['x-forwarded-for']
    if (forwarded) {
      const first = String(forwarded).split(',')[0].trim()
      if (first) return first
    }
  }
  return remoteAddress || 'unknown'
}

// Looks up the shop for a sync bearer token. Returns null if the token is
// missing, unknown, or revoked -- never partial/best-effort. This is the
// ONLY function that may decide "which shop is this," for every route in
// this file.
export function resolveShopFromSyncToken(req) {
  const token = getBearerToken(req)
  if (!token) return null
  const tokenHash = sha256(token)
  const row = db
    .prepare(
      `SELECT sync_tokens.shop_id AS shop_id, shops.machine_id AS machine_id
       FROM sync_tokens
       JOIN shops ON shops.id = sync_tokens.shop_id
       WHERE sync_tokens.token_hash = ? AND sync_tokens.revoked_at IS NULL`
    )
    .get(tokenHash)
  return row || null
}

// POST /sync/register  { license_key, machine_id, shop_name }
export async function handleSyncRegister(req, res) {
  const ip = getClientIp(req)
  if (!checkAndConsume(`register:${ip}`, { limit: REGISTER_RATE_LIMIT, windowMs: REGISTER_RATE_WINDOW_MS })) {
    return sendJson(res, 429, { ok: false, error: 'Too many registration attempts. Try again later.' })
  }
  sweepExpired(REGISTER_RATE_WINDOW_MS)

  let body
  try {
    body = await readJsonBody(req)
  } catch (err) {
    return sendJson(res, 400, { ok: false, error: err.message })
  }

  const licenseKey = String(body.license_key || '').trim()
  const machineId = String(body.machine_id || '').trim()
  const shopName = String(body.shop_name || '').trim().slice(0, 200)

  if (!licenseKey || !machineId) {
    return sendJson(res, 400, { ok: false, error: 'license_key and machine_id are required.' })
  }

  // Server-side verification BEFORE anything is issued -- a tampered key
  // or a valid-but-non-Premium key must be rejected here, never trusting a
  // client-asserted tier flag (finding #4).
  const verification = verifyNxv2License(licenseKey, machineId)
  if (!verification.valid) {
    console.log(`[sync] register REJECTED machine_id=${machineId} reason=${verification.reason}`)
    // 'not_nxv2' means a syntactically legacy (v1) key was submitted --
    // worth telling the caller apart from a genuinely bad/tampered v2 key,
    // since the fix is different ("reissue as v2") not "check your key for
    // typos". Every other reason (bad_signature, machine_mismatch,
    // bad_version, malformed, error) stays under the one generic message --
    // those all mean "something about this key or its signature was wrong",
    // where a more specific reason wouldn't tell the shop anything
    // actionable and could hand a probing attacker more to work with.
    if (verification.reason === 'not_nxv2') {
      return sendJson(res, 403, {
        ok: false,
        error: 'Your license needs to be reissued to use Remote Monitoring — contact support to upgrade.',
        error_code: 'legacy_license'
      })
    }
    return sendJson(res, 403, { ok: false, error: 'License could not be verified.' })
  }
  if (verification.tier !== 'premium') {
    console.log(`[sync] register REJECTED machine_id=${machineId} tier=${verification.tier} (not premium)`)
    return sendJson(res, 403, { ok: false, error: 'Remote Monitoring requires a Premium license.' })
  }

  const now = nowIso()
  const run = db.transaction(() => {
    let shop = db.prepare('SELECT * FROM shops WHERE machine_id = ?').get(machineId)
    if (shop) {
      db.prepare('UPDATE shops SET shop_name = ?, tier = ?, last_seen_at = ? WHERE id = ?').run(
        shopName || shop.shop_name,
        verification.tier,
        now,
        shop.id
      )
    } else {
      const result = db
        .prepare('INSERT INTO shops (machine_id, shop_name, tier, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)')
        .run(machineId, shopName, verification.tier, now, now)
      shop = { id: result.lastInsertRowid }
    }

    // Rotate: revoke any existing active tokens for this shop, issue a
    // fresh one -- simplest correct behavior across enable/disable/re-enable.
    db.prepare('UPDATE sync_tokens SET revoked_at = ? WHERE shop_id = ? AND revoked_at IS NULL').run(now, shop.id)

    const rawToken = generateToken()
    db.prepare('INSERT INTO sync_tokens (shop_id, token_hash, created_at) VALUES (?, ?, ?)').run(
      shop.id,
      sha256(rawToken),
      now
    )

    return { shopId: shop.id, rawToken }
  })

  const { shopId, rawToken } = run()
  console.log(`[sync] register OK machine_id=${machineId} shop_id=${shopId} tier=${verification.tier}`)
  return sendJson(res, 200, { ok: true, sync_token: rawToken })
}

// POST /sync/push  Authorization: Bearer <sync_token>  { rows: [{entity_type, entity_id, action, payload}, ...] }
// Also used for a full-snapshot push (registration / manual "Resync now")
// -- same shape, just a larger batch; no separate endpoint needed.
export async function handleSyncPush(req, res) {
  const shop = resolveShopFromSyncToken(req)
  if (!shop) return sendJson(res, 401, { ok: false, error: 'Invalid or revoked sync token.' })

  const rateLimitKey = `push:${sha256(getBearerToken(req))}`
  if (!checkAndConsume(rateLimitKey, { limit: PUSH_RATE_LIMIT, windowMs: PUSH_RATE_WINDOW_MS })) {
    return sendJson(res, 429, { ok: false, error: 'Push rate limit exceeded.' })
  }
  sweepExpired(PUSH_RATE_WINDOW_MS)

  let body
  try {
    body = await readJsonBody(req)
  } catch (err) {
    return sendJson(res, 400, { ok: false, error: err.message })
  }

  const rows = Array.isArray(body.rows) ? body.rows : []
  if (rows.length === 0) {
    return sendJson(res, 400, { ok: false, error: 'rows must be a non-empty array.' })
  }
  if (rows.length > MAX_ROWS_PER_PUSH) {
    return sendJson(res, 400, { ok: false, error: `Too many rows in one push (max ${MAX_ROWS_PER_PUSH}).` })
  }

  const now = nowIso()
  const upsert = db.prepare(
    `INSERT INTO snapshots (shop_id, entity_type, entity_id, action, payload, updated_at)
     VALUES (@shop_id, @entity_type, @entity_id, @action, @payload, @updated_at)
     ON CONFLICT (shop_id, entity_type, entity_id) DO UPDATE SET
       action = excluded.action, payload = excluded.payload, updated_at = excluded.updated_at`
  )
  const touchShop = db.prepare('UPDATE shops SET last_seen_at = ? WHERE id = ?')

  let accepted = 0
  const run = db.transaction((rowsToInsert) => {
    for (const row of rowsToInsert) {
      const entityType = String(row.entity_type || '').trim()
      const entityId = Number(row.entity_id)
      const action = String(row.action || '').trim()
      // Malformed individual rows are skipped, not fatal to the whole
      // batch -- one bad row from a future app version shouldn't stall
      // every other row's sync.
      if (!entityType || !Number.isFinite(entityId) || !action) continue
      upsert.run({
        shop_id: shop.shop_id, // ALWAYS the token-derived shop -- row.shop_id, if a caller even sent one, is never read
        entity_type: entityType,
        entity_id: entityId,
        action,
        payload: JSON.stringify(row.payload ?? {}),
        updated_at: now
      })
      accepted++
    }
    touchShop.run(now, shop.shop_id)
  })
  run(rows)

  return sendJson(res, 200, { ok: true, accepted })
}

// POST /sync/pairing-code  Authorization: Bearer <sync_token>
// App-initiated -- the app's own Settings IPC handler is what enforces
// "Owner/Admin + password confirmation" before ever calling this; the
// relay has no notion of passwords and never sees one.
export async function handlePairingCodeGenerate(req, res) {
  const shop = resolveShopFromSyncToken(req)
  if (!shop) return sendJson(res, 401, { ok: false, error: 'Invalid or revoked sync token.' })

  const rateLimitKey = `pairing-code:${sha256(getBearerToken(req))}`
  if (!checkAndConsume(rateLimitKey, { limit: PAIRING_CODE_RATE_LIMIT, windowMs: PAIRING_CODE_RATE_WINDOW_MS })) {
    return sendJson(res, 429, { ok: false, error: 'Too many code generation attempts. Try again later.' })
  }
  sweepExpired(PAIRING_CODE_RATE_WINDOW_MS)

  const nowMs = Date.now()
  const nowStr = new Date(nowMs).toISOString()
  const expiresStr = new Date(nowMs + PAIRING_CODE_TTL_MS).toISOString()
  const rawCode = generatePairingCode()

  const run = db.transaction(() => {
    // Only one active code per shop at a time -- keeps "the" active code
    // for a shop unambiguous, and bounds pairing_codes' growth.
    db.prepare(
      `UPDATE pairing_codes SET invalidated_at = ?
       WHERE shop_id = ? AND invalidated_at IS NULL AND used_at IS NULL`
    ).run(nowStr, shop.shop_id)

    db.prepare(
      `INSERT INTO pairing_codes (code, shop_id, created_at, expires_at, attempts)
       VALUES (?, ?, ?, ?, 0)`
    ).run(rawCode, shop.shop_id, nowStr, expiresStr)
  })
  run()

  return sendJson(res, 200, { ok: true, code: rawCode, expires_at: expiresStr })
}

// GET /sync/sessions  Authorization: Bearer <sync_token>
// Feeds Settings.vue's "Linked Browser Sessions" list.
export function handleSessionsList(req, res) {
  const shop = resolveShopFromSyncToken(req)
  if (!shop) return sendJson(res, 401, { ok: false, error: 'Invalid or revoked sync token.' })

  const rows = db
    .prepare(
      `SELECT session_id, device_label, ip_address, created_at, last_active_at, expires_at
       FROM dashboard_sessions
       WHERE shop_id = ? AND revoked_at IS NULL
       ORDER BY last_active_at DESC`
    )
    .all(shop.shop_id)

  const sessions = rows.map((row) => ({
    id: row.session_id,
    device: row.device_label || 'Unknown device',
    ip_address: row.ip_address || null,
    created_at: row.created_at,
    last_active_at: row.last_active_at,
    expires_at: row.expires_at
  }))

  return sendJson(res, 200, { ok: true, sessions })
}

// POST /sync/sessions/revoke  Authorization: Bearer <sync_token>  { session_id }
export async function handleSessionRevoke(req, res) {
  const shop = resolveShopFromSyncToken(req)
  if (!shop) return sendJson(res, 401, { ok: false, error: 'Invalid or revoked sync token.' })

  let body
  try {
    body = await readJsonBody(req)
  } catch (err) {
    return sendJson(res, 400, { ok: false, error: err.message })
  }

  const sessionId = String(body.session_id || '').trim()
  if (!sessionId) return sendJson(res, 400, { ok: false, error: 'session_id is required.' })

  // Scoped to shop.shop_id (the TOKEN-derived shop) -- one shop can never
  // revoke another shop's session even by guessing/colliding a session_id.
  const now = nowIso()
  const result = db
    .prepare(
      `UPDATE dashboard_sessions SET revoked_at = ?
       WHERE shop_id = ? AND session_id = ? AND revoked_at IS NULL`
    )
    .run(now, shop.shop_id, sessionId)

  if (result.changes === 0) {
    return sendJson(res, 404, { ok: false, error: 'Session not found.' })
  }
  return sendJson(res, 200, { ok: true })
}
