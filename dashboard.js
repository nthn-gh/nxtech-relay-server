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
 * Multi-branch: a browser can hold several claimed sessions at once (one
 * per shop/branch), each as its OWN cookie -- dashboard_session_<session_id>
 * -- rather than one shared cookie holding several tokens. Claiming or
 * forgetting one branch never reads-modifies-writes another branch's
 * cookie, so there's no shared mutable state to race on between tabs/
 * concurrent claims. Every data request names which claimed session it
 * wants via the X-Dashboard-Session header; the relay derives the expected
 * cookie name from that id directly (no scanning/guessing) and validates
 * the resolved row's own session_id actually matches what was asked for.
 *
 * The session token itself is delivered ONLY via Set-Cookie (HttpOnly,
 * SameSite=Strict, Secure by default) -- never in a JSON response body.
 * This is a public website holding a shop's real financial data; a token
 * in a JSON body would force the frontend to keep it in JS-accessible
 * storage (localStorage/sessionStorage), which an XSS bug in the frontend
 * could read and exfiltrate. HttpOnly means the browser sends the cookie
 * automatically but no page script -- including an injected one -- can
 * ever read its value, which is also why the frontend can't clear a
 * revoked/stale cookie itself; see handleDashboardForget below for the
 * only way that actually happens. SameSite=Strict (not Lax) because
 * nothing in this flow needs the cookie sent on a cross-site top-level
 * navigation -- the claim happens via a same-origin fetch from the link
 * screen itself, not an external redirect landing the browser on an
 * authenticated page.
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
// matter how active it stays.
//
// 60 days, not a shorter "active use" window, by deliberate choice: this is
// a read-only monitoring dashboard an owner checks occasionally (once a day
// or less), not a continuously-open app, so a short idle-based expiry (the
// old SESSION_IDLE_MS = 30 min, removed below) killed the session on
// essentially every realistic visit and forced a fresh pairing code far
// more often than the 24h absolute cap ever did. The owner should only need
// to generate a new code roughly every 60 days, not every time they check.
//
// This intentionally trades security posture for that convenience: a lost
// or stolen device that's still logged in stays valid for up to 60 days
// unless manually revoked. The existing Settings session list + Revoke
// button (see handleDashboardSessionsList/handleDashboardForget-adjacent
// revoke path) is the actual mitigation for that now -- make sure owners
// know it's there.
export const SESSION_ABSOLUTE_MS = 60 * 24 * 60 * 60 * 1000 // 60 days

const CLAIM_RATE_LIMIT = 10
const CLAIM_RATE_WINDOW_MS = 15 * 60 * 1000 // per IP

// One cookie per claimed session, named by that session's own (non-secret)
// display id -- e.g. dashboard_session_a1b2c3d4e5f6a7b8. Replaces the old
// single dashboard_session cookie.
export const SESSION_COOKIE_PREFIX = 'dashboard_session_'

// The real deployment (nginx serving the SPA + reverse-proxying /dashboard/*
// to this same process on localhost) is same-origin end to end, always over
// TLS -- Secure defaults on. Only reason to ever turn it off is a plain-HTTP
// local/test harness, where a browser would silently refuse to store a
// Secure cookie at all. Parsed once at startup, not per-request.
const COOKIE_SECURE = process.env.DASHBOARD_COOKIE_SECURE !== 'false'

function buildSessionCookie(sessionId, token, maxAgeMs) {
  const parts = [
    `${SESSION_COOKIE_PREFIX}${sessionId}=${token}`,
    'Path=/dashboard',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`
  ]
  if (COOKIE_SECURE) parts.push('Secure')
  return parts.join('; ')
}

function buildClearSessionCookie(sessionId) {
  const parts = [`${SESSION_COOKIE_PREFIX}${sessionId}=`, 'Path=/dashboard', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0']
  if (COOKIE_SECURE) parts.push('Secure')
  return parts.join('; ')
}

// Every dashboard_session_* cookie on the request, as sessionId -> token.
// Used by claim (to find a same-shop session to replace) and by the
// sessions-list endpoint (to resolve everything the browser is currently
// holding).
function getAllSessionCookies(req) {
  const header = req.headers['cookie']
  const result = new Map()
  if (!header) return result
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const name = part.slice(0, eq).trim()
    if (name.startsWith(SESSION_COOKIE_PREFIX)) {
      result.set(name.slice(SESSION_COOKIE_PREFIX.length), decodeURIComponent(part.slice(eq + 1).trim()))
    }
  }
  return result
}

// Just the one cookie a per-request route actually needs, by the session id
// the caller specified -- avoids parsing every cookie on the request when
// only one is relevant (entity list, forget).
function getSessionCookieById(req, sessionId) {
  const header = req.headers['cookie']
  if (!header) return ''
  const targetName = `${SESSION_COOKIE_PREFIX}${sessionId}`
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const name = part.slice(0, eq).trim()
    if (name === targetName) return decodeURIComponent(part.slice(eq + 1).trim())
  }
  return ''
}

// Which claimed session a request is for -- the browser may hold several,
// so every data/forget route needs to be told which one. Never trusted on
// its own: resolveDashboardSession still has to find a cookie under this
// exact id AND validate the row it resolves to actually owns that id.
function getRequestedSessionId(req) {
  const header = req.headers['x-dashboard-session']
  return header ? String(header).trim() : ''
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
  // X-Dashboard-Session added for the branch switcher -- every data call
  // now sends it, so a cross-origin preflight needs it explicitly allowed
  // or the browser rejects the request before it ever reaches here.
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Dashboard-Session')
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

// True only for a cookie that would ALSO pass every check
// resolveDashboardSession itself applies (not revoked, not expired,
// session_id actually matches) -- a stale/dead cookie for the same shop
// doesn't count as "already claimed" and doesn't need any special handling,
// it just won't match here and gets left alone.
function findLiveSessionForShop(existingCookies, shopId) {
  for (const [existingSessionId, existingToken] of existingCookies) {
    const row = db
      .prepare(
        'SELECT session_id, shop_id, revoked_at, expires_at FROM dashboard_sessions WHERE token_hash = ?'
      )
      .get(sha256(existingToken))
    if (!row || row.session_id !== existingSessionId) continue
    if (row.revoked_at) continue
    if (new Date(row.expires_at).getTime() <= Date.now()) continue
    if (row.shop_id === shopId) return existingSessionId
  }
  return null
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

  // Not one cookie per claim -- one cookie per branch. If this browser
  // already holds a live session for the SAME shop this code belongs to,
  // that one gets replaced (revoked server-side, its cookie cleared),
  // rather than accumulating a second cookie for the same branch.
  const existingCookies = getAllSessionCookies(req)
  const existingSessionIdForShop = findLiveSessionForShop(existingCookies, row.shop_id)

  let shopName = ''
  const run = db.transaction(() => {
    // Single-use: re-check-and-mark-used inside one transaction, so two
    // concurrent claims of the same code can't both succeed.
    const stillValid = db
      .prepare('SELECT code FROM pairing_codes WHERE code = ? AND used_at IS NULL AND invalidated_at IS NULL')
      .get(code)
    if (!stillValid) return false

    db.prepare('UPDATE pairing_codes SET used_at = ? WHERE code = ?').run(now, code)

    if (existingSessionIdForShop) {
      db.prepare('UPDATE dashboard_sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL').run(
        now,
        existingSessionIdForShop
      )
    }

    db.prepare(
      `INSERT INTO dashboard_sessions
         (token_hash, session_id, shop_id, created_at, expires_at, last_active_at, device_label, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(sha256(rawSessionToken), sessionId, row.shop_id, now, expiresAt, now, deviceLabel, ip)

    const shop = db.prepare('SELECT shop_name FROM shops WHERE id = ?').get(row.shop_id)
    shopName = shop?.shop_name || ''
    return true
  })

  if (!run()) {
    return sendJson(res, 401, { ok: false, error: 'Invalid or expired code.' })
  }

  console.log(
    `[dashboard] claim OK shop_id=${row.shop_id} ip=${ip}${existingSessionIdForShop ? ' (replaced this browser\'s prior session for the same shop)' : ''}`
  )
  // Both in one response when replacing: clear the old branch's cookie AND
  // set the new one, so the stale one doesn't linger inert in the browser
  // the way a Settings-side revoke unavoidably does (that path has no HTTP
  // response of its own to piggyback a Set-Cookie on -- this one does).
  const cookies = existingSessionIdForShop
    ? [buildClearSessionCookie(existingSessionIdForShop), buildSessionCookie(sessionId, rawSessionToken, SESSION_ABSOLUTE_MS)]
    : [buildSessionCookie(sessionId, rawSessionToken, SESSION_ABSOLUTE_MS)]
  res.setHeader('Set-Cookie', cookies)
  return sendJson(res, 200, { ok: true, session_id: sessionId, shop_name: shopName, expires_at: expiresAt })
}

// Re-validated on EVERY call, never cached (finding #9): existence,
// not-revoked, and absolute expiry are all checked live against the DB.
// No idle timeout as of the 60-day change above -- last_active_at is still
// recorded on every successful check (kept for future "last seen" surfacing
// / debugging), it just no longer gates access. A session can't be kept
// alive past its absolute expiry just by staying active, and (as of the
// 60-day change) can't be force-expired early by going quiet either.
//
// requestedSessionId decides WHICH of the browser's possibly-several
// cookies to look at -- derived straight into an expected cookie name, no
// scanning. The extra row.session_id === requestedSessionId check isn't
// really load-bearing (the cookie name IS the trust boundary; HttpOnly
// means page script can't make the browser send a cookie it doesn't
// actually have), but it's cheap and matches this codebase's standing
// habit of not trusting a client-supplied id without checking it against
// what the server itself derived.
function resolveDashboardSession(req, requestedSessionId) {
  if (!requestedSessionId) return null
  const token = getSessionCookieById(req, requestedSessionId)
  if (!token) return null

  const tokenHash = sha256(token)
  const row = db.prepare('SELECT * FROM dashboard_sessions WHERE token_hash = ?').get(tokenHash)
  if (!row) return null
  if (row.session_id !== requestedSessionId) return null
  if (row.revoked_at) return null

  const now = Date.now()
  if (new Date(row.expires_at).getTime() <= now) return null

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

  const session = resolveDashboardSession(req, getRequestedSessionId(req))
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

// GET /dashboard/sessions -- every dashboard_session_* cookie present on
// the request, resolved exactly like a normal data request would (same
// revoked/expired/idle checks, no caching), returning only the ones still
// actually valid. This is what the frontend uses to render the branch
// switcher on load -- it never trusts its own remembered state across a
// reload, it re-derives the truth from the cookies + DB every time.
export function handleDashboardSessionsList(req, res) {
  applyDashboardCors(res)
  const cookies = getAllSessionCookies(req)
  const sessions = []
  for (const sessionId of cookies.keys()) {
    const session = resolveDashboardSession(req, sessionId)
    if (!session) continue
    const shop = db.prepare('SELECT shop_name FROM shops WHERE id = ?').get(session.shopId)
    sessions.push({ session_id: session.sessionId, shop_name: shop?.shop_name || '' })
  }
  return sendJson(res, 200, { ok: true, sessions })
}

// POST /dashboard/forget  { session_id }
// Clears ONE branch's cookie. This is the only way a revoked/stale
// session's cookie actually leaves the browser -- page script can't touch
// an HttpOnly cookie itself, so both the switcher's explicit "remove
// branch" action and the frontend's own reaction to a 401 for one branch
// go through this. Deliberately doesn't require the session to still be
// valid or even exist -- forgetting an already-revoked/expired/unknown
// session is the normal case this exists for, so it never touches
// dashboard_sessions at all, just clears whatever cookie was named.
export async function handleDashboardForget(req, res) {
  applyDashboardCors(res)
  let body
  try {
    body = await readJsonBody(req)
  } catch (err) {
    return sendJson(res, 400, { ok: false, error: err.message })
  }
  const sessionId = String(body.session_id || '').trim()
  if (!sessionId) return sendJson(res, 400, { ok: false, error: 'session_id is required.' })

  res.setHeader('Set-Cookie', buildClearSessionCookie(sessionId))
  return sendJson(res, 200, { ok: true })
}

// OPTIONS preflight for /dashboard/* -- browsers send this before the
// actual GET/POST when Authorization or a non-simple method is involved.
export function handleDashboardOptions(req, res) {
  applyDashboardCors(res)
  res.writeHead(204)
  res.end()
}
