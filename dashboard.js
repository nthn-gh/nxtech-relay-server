/**
 * NXTech POS Pro relay — Remote Monitoring Dashboard: browser-facing API.
 *
 * Two credential moments, neither reusable as the other:
 *   1. POST /dashboard/claim { code } -- the actual "access code" moment.
 *      No auth beyond the code itself; rate-limited and attempt-capped.
 *   2. Every /dashboard/* read route -- authenticated by the opaque
 *      session token claim issued, re-validated LIVE on every request
 *      (see resolveDashboardSession below) -- no caching of authorization
 *      state, ever.
 *
 * The session token is delivered ONLY via a Set-Cookie header (HttpOnly,
 * SameSite=Strict, Secure by default) -- never in a JSON response body.
 * This is a public website holding a shop's real financial data; a token
 * in a JSON body would force the frontend to keep it in JS-accessible
 * storage (localStorage/sessionStorage), which an XSS bug in the frontend
 * could read and exfiltrate. HttpOnly means the browser sends the cookie
 * automatically but no page script -- including an injected one -- can
 * ever read its value. The frontend's only job is `credentials: 'include'`
 * on every /dashboard/* fetch; it never touches the token itself. SameSite
 * =Strict (not Lax) because nothing in this flow needs the cookie sent on
 * a cross-site top-level navigation -- the claim happens via a same-origin
 * fetch from the link screen itself, not an external redirect landing the
 * browser on an authenticated page.
 *
 * shop_id is NEVER read from a request body/param here either -- always
 * derived from the authenticated session (finding #2, same standing rule
 * as sync.js).
 */
import { randomBytes } from 'crypto'
import { db, nowIso } from './db.js'
import { checkAndConsume, sweepExpired } from './rateLimiter.js'
import { sha256, sendJson, readJsonBody, getClientIp, MAX_CLAIM_ATTEMPTS, PAIRING_CODE_PREFIX_LENGTH } from './sync.js'

const SESSION_TOKEN_BYTES = 32
// Real absolute expiry (finding #9) -- a session is force-expired here no
// matter how active it stays. Idle timeout (below) can end it sooner.
export const SESSION_ABSOLUTE_MS = 24 * 60 * 60 * 1000 // 24h
export const SESSION_IDLE_MS = 30 * 60 * 1000 // 30 min since last request

const CLAIM_RATE_LIMIT = 10
const CLAIM_RATE_WINDOW_MS = 15 * 60 * 1000 // per IP

export const SESSION_COOKIE_NAME = 'dashboard_session'

// The real deployment (nginx serving the SPA + reverse-proxying /dashboard/*
// to this same process on localhost) is same-origin end to end, always over
// TLS -- Secure defaults on. Only reason to ever turn it off is a plain-HTTP
// local/test harness, where a browser would silently refuse to store a
// Secure cookie at all. Parsed once at startup, not per-request.
const COOKIE_SECURE = process.env.DASHBOARD_COOKIE_SECURE !== 'false'

function buildSessionCookie(token, maxAgeMs) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${token}`,
    'Path=/dashboard',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`
  ]
  if (COOKIE_SECURE) parts.push('Secure')
  return parts.join('; ')
}

function buildClearSessionCookie() {
  const parts = [`${SESSION_COOKIE_NAME}=`, 'Path=/dashboard', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0']
  if (COOKIE_SECURE) parts.push('Secure')
  return parts.join('; ')
}

function getSessionCookie(req) {
  const header = req.headers['cookie']
  if (!header) return ''
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const name = part.slice(0, eq).trim()
    if (name === SESSION_COOKIE_NAME) return decodeURIComponent(part.slice(eq + 1).trim())
  }
  return ''
}

// CORS scoped to the owner's actual domain (finding #12) -- unset in dev,
// must be configured for a real deployment. Never '*'. The real deployment
// is same-origin (nginx reverse-proxies /dashboard/* on the same host that
// serves the SPA), so this is moot there -- kept for the general case
// (e.g. a staging frontend on a different host during development), and
// correctly configured for it: a credentialed cross-origin fetch (cookies
// via `credentials: 'include'`) requires Allow-Credentials alongside a
// concrete (non-wildcard) Allow-Origin, or the browser refuses to expose
// the response and won't send the cookie in the first place.
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || ''

// Called first thing by every /dashboard/* handler below, unconditionally
// -- unlike the CORS headers past the DASHBOARD_ORIGIN check, this must
// NOT be skipped in the real (same-origin) deployment, which deliberately
// leaves DASHBOARD_ORIGIN unset. Every one of these responses carries one
// shop's real financial data; with Cloudflare in front, a response that
// somehow got cached and replayed to a different visitor would be an
// actual cross-tenant data leak, not just staleness -- so this is
// unconditional and not something either the browser, Cloudflare's edge,
// or any other intermediary is left to infer on its own.
export function applyDashboardCors(res) {
  res.setHeader('Cache-Control', 'no-store')
  if (!DASHBOARD_ORIGIN) return
  res.setHeader('Access-Control-Allow-Origin', DASHBOARD_ORIGIN)
  res.setHeader('Vary', 'Origin')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Credentials', 'true')
}

function generateSessionToken() {
  return randomBytes(SESSION_TOKEN_BYTES).toString('base64url')
}

function generateSessionId() {
  return randomBytes(8).toString('hex')
}

// Records a failed claim attempt against whichever active code(s) share
// the wrong guess's first PAIRING_CODE_PREFIX_LENGTH characters -- this is
// exactly why pairing_codes.code is stored in PLAINTEXT (see db.js): a
// hash of the guess would match nothing (the avalanche effect destroys any
// correlation with a similar-but-wrong stored value), forcing the old
// "penalize every active code" workaround that let a wrong guess against
// shop A degrade shop B's unrelated code. A guess that got the first few
// characters right (the realistic case: someone reading/typing their OWN
// code and fumbling a later character) prefix-matches ONLY that code; a
// guess unrelated to any active code (random/attacker) prefix-matches
// nothing and touches no row at all. Any code that reaches
// MAX_CLAIM_ATTEMPTS is invalidated immediately. Combined with the per-IP
// rate limit above, this is the "hard attempt cap that invalidates the
// code" from finding #1.
function recordFailedClaimAttempt(guessedCode) {
  const now = nowIso()
  const prefix = String(guessedCode || '').slice(0, PAIRING_CODE_PREFIX_LENGTH)
  if (!prefix) return

  const candidates = db
    .prepare(
      `SELECT code, attempts FROM pairing_codes
       WHERE code LIKE ? AND invalidated_at IS NULL AND used_at IS NULL AND expires_at > ?`
    )
    .all(`${prefix}%`, now)

  const run = db.transaction(() => {
    for (const row of candidates) {
      const attempts = row.attempts + 1
      if (attempts >= MAX_CLAIM_ATTEMPTS) {
        db.prepare('UPDATE pairing_codes SET attempts = ?, invalidated_at = ? WHERE code = ?').run(
          attempts,
          now,
          row.code
        )
      } else {
        db.prepare('UPDATE pairing_codes SET attempts = ? WHERE code = ?').run(attempts, row.code)
      }
    }
  })
  run()
}

// POST /dashboard/claim  { code }
export async function handleDashboardClaim(req, res) {
  applyDashboardCors(res)
  const ip = getClientIp(req)
  if (!checkAndConsume(`claim:${ip}`, { limit: CLAIM_RATE_LIMIT, windowMs: CLAIM_RATE_WINDOW_MS })) {
    return sendJson(res, 429, { ok: false, error: 'Too many attempts. Please wait and try again.' })
  }
  sweepExpired(CLAIM_RATE_WINDOW_MS)

  let body
  try {
    body = await readJsonBody(req)
  } catch (err) {
    return sendJson(res, 400, { ok: false, error: err.message })
  }

  const code = String(body.code || '').trim().toUpperCase()
  if (!code) return sendJson(res, 400, { ok: false, error: 'code is required.' })

  const now = nowIso()
  const row = db
    .prepare(
      `SELECT * FROM pairing_codes
       WHERE code = ? AND invalidated_at IS NULL AND used_at IS NULL AND expires_at > ?`
    )
    .get(code, now)

  if (!row) {
    recordFailedClaimAttempt(code)
    return sendJson(res, 401, { ok: false, error: 'Invalid or expired code.' })
  }

  const rawSessionToken = generateSessionToken()
  const sessionId = generateSessionId()
  const expiresAt = new Date(Date.now() + SESSION_ABSOLUTE_MS).toISOString()
  const deviceLabel = String(req.headers['user-agent'] || '').slice(0, 300) || 'Unknown device'

  // Single-use: re-check-and-mark-used inside one transaction, so two
  // concurrent claims of the same code can't both succeed.
  const run = db.transaction(() => {
    const stillValid = db
      .prepare('SELECT code FROM pairing_codes WHERE code = ? AND used_at IS NULL AND invalidated_at IS NULL')
      .get(code)
    if (!stillValid) return false

    db.prepare('UPDATE pairing_codes SET used_at = ? WHERE code = ?').run(now, code)
    db.prepare(
      `INSERT INTO dashboard_sessions
         (token_hash, session_id, shop_id, created_at, expires_at, last_active_at, device_label, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(sha256(rawSessionToken), sessionId, row.shop_id, now, expiresAt, now, deviceLabel, ip)
    return true
  })

  if (!run()) {
    return sendJson(res, 401, { ok: false, error: 'Invalid or expired code.' })
  }

  console.log(`[dashboard] claim OK shop_id=${row.shop_id} ip=${ip}`)
  res.setHeader('Set-Cookie', buildSessionCookie(rawSessionToken, SESSION_ABSOLUTE_MS))
  return sendJson(res, 200, { ok: true, expires_at: expiresAt })
}

// Re-validated on EVERY call, never cached (finding #9): existence,
// not-revoked, absolute expiry, and idle timeout since last activity are
// all checked live against the DB. On success, slides last_active_at
// forward -- the idle window renews on activity; the absolute expiry does
// not (a session can't be kept alive forever just by staying active).
function resolveDashboardSession(req) {
  const token = getSessionCookie(req)
  if (!token) return null

  const tokenHash = sha256(token)
  const row = db.prepare('SELECT * FROM dashboard_sessions WHERE token_hash = ?').get(tokenHash)
  if (!row) return null
  if (row.revoked_at) return null

  const now = Date.now()
  if (new Date(row.expires_at).getTime() <= now) return null
  if (now - new Date(row.last_active_at).getTime() > SESSION_IDLE_MS) return null

  db.prepare('UPDATE dashboard_sessions SET last_active_at = ? WHERE token_hash = ?').run(
    new Date(now).toISOString(),
    tokenHash
  )
  return { shopId: row.shop_id, sessionId: row.session_id }
}

const ENTITY_TYPES = new Set(['sale', 'job_order', 'inventory', 'expense', 'daily_closing'])
const DEFAULT_LIST_LIMIT = 100

// GET /dashboard/:entityType -- basic, unfiltered "current snapshot" list.
// Real pagination/date-range filtering (matching the app's own Reports
// screens) is scoped as a follow-up -- this proves the auth/shop_id-
// derivation plumbing is correct end-to-end, which is the security-
// critical part for this step.
export function handleDashboardEntityList(req, res, entityType) {
  applyDashboardCors(res)
  if (!ENTITY_TYPES.has(entityType)) {
    return sendJson(res, 404, { ok: false, error: 'Unknown entity type.' })
  }

  const session = resolveDashboardSession(req)
  if (!session) return sendJson(res, 401, { ok: false, error: 'Invalid, expired, or revoked session.' })

  const rows = db
    .prepare(
      `SELECT entity_id, action, payload, updated_at FROM snapshots
       WHERE shop_id = ? AND entity_type = ?
       ORDER BY updated_at DESC
       LIMIT ?`
    )
    .all(session.shopId, entityType, DEFAULT_LIST_LIMIT)

  const data = rows.map((row) => ({
    entity_id: row.entity_id,
    action: row.action,
    updated_at: row.updated_at,
    ...JSON.parse(row.payload)
  }))

  return sendJson(res, 200, { ok: true, data })
}

// OPTIONS preflight for /dashboard/* -- browsers send this before the
// actual GET/POST when Authorization or a non-simple method is involved.
export function handleDashboardOptions(req, res) {
  applyDashboardCors(res)
  res.writeHead(204)
  res.end()
}
