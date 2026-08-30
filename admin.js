/**
 * NXTech POS Pro — Remote Access admin API
 *
 * A loopback-only HTTP control plane for the subscriber whitelist. It lets you
 * add, list, grant/revoke individual features (kill-switch per feature), and
 * remove shops without touching the relay process or hand-editing
 * subscribers.json. Used for manual GCash-confirmed entitlement grants — no
 * payment processor, so this IS the billing UI (via curl/SSH).
 *
 * Security model: this server binds to 127.0.0.1 ONLY and requires a static
 * bearer token on every request except /health. It is meant to be reached over
 * SSH/loopback by the operator, never exposed publicly. Do not bind 0.0.0.0.
 *
 * Endpoints (all require `Authorization: Bearer <ADMIN_TOKEN>` except /health):
 *   GET    /health                      -> { ok: true }                (no auth)
 *   GET    /subscribers                 -> { subscribers: [...] }      (each has `features: { remote_access, mobile_data }`)
 *   POST   /subscribers                 -> body { machineId, label, features: { remote_access?, mobile_data? }, notes }
 *                                          { ok: true, subscriber } | 400 { ok:false, error }
 *   PATCH  /subscribers/:machineId      -> body { feature: 'remote_access'|'mobile_data', active }
 *                                          { ok: true, machineId, feature, active } | 400 { ok:false, error } | 404 { ok:false }
 *   DELETE /subscribers/:machineId      -> { ok: true } | 404 { ok:false }
 */

import http from 'http'
import { addOrUpdate, setActive, remove, listAll, KNOWN_FEATURES } from './subscribers.js'

const ADMIN_PORT = Number(process.env.ADMIN_PORT || 3001)
const ADMIN_HOST = '127.0.0.1'
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ''

function log(...args) {
  console.log(new Date().toISOString(), ...args)
}

function sendJson(res, status, body) {
  const data = JSON.stringify(body)
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(data)
}

// Collects a request body and parses it as JSON. Resolves {} for an empty
// body; rejects on malformed JSON so the caller can return 400.
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
      // Guard against unbounded bodies on a loopback admin port.
      if (raw.length > 1_000_000) {
        reject(new Error('Body too large'))
        req.destroy()
      }
    })
    req.on('end', () => {
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

function isAuthorized(req) {
  const header = req.headers['authorization'] || ''
  const expected = `Bearer ${ADMIN_TOKEN}`
  return ADMIN_TOKEN.length > 0 && header === expected
}

// Validates an optional `features` object from a POST body. Missing/null is
// valid (subscribers.js's addOrUpdate() defaults every feature to false in
// that case) — but if present, every key must be a known feature name and
// every value must be an actual boolean. Never silently coerces a wrong-typed
// value; rejects instead, so a malformed request can't accidentally grant
// something unspecified.
function validateFeaturesBody(features) {
  if (features === undefined || features === null) {
    return { valid: true, features: {} }
  }
  if (typeof features !== 'object' || Array.isArray(features)) {
    return { valid: false, error: 'features must be an object' }
  }
  for (const key of Object.keys(features)) {
    if (!KNOWN_FEATURES.includes(key)) {
      return { valid: false, error: `Unknown feature '${key}'. Known features: ${KNOWN_FEATURES.join(', ')}` }
    }
    if (typeof features[key] !== 'boolean') {
      return { valid: false, error: `features.${key} must be a boolean` }
    }
  }
  return { valid: true, features }
}

const adminServer = http.createServer(async (req, res) => {
  let parsed
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    return sendJson(res, 400, { ok: false, error: 'Bad request' })
  }
  const pathname = parsed.pathname

  // Health is unauthenticated so you can probe that the admin server is up.
  if (req.method === 'GET' && pathname === '/health') {
    return sendJson(res, 200, { ok: true })
  }

  // Everything else requires the bearer token.
  if (!isAuthorized(req)) {
    return sendJson(res, 401, { ok: false, error: 'Unauthorized' })
  }

  // GET /subscribers
  if (req.method === 'GET' && pathname === '/subscribers') {
    return sendJson(res, 200, { subscribers: listAll() })
  }

  // POST /subscribers
  if (req.method === 'POST' && pathname === '/subscribers') {
    let body
    try {
      body = await readJsonBody(req)
    } catch (err) {
      return sendJson(res, 400, { ok: false, error: err.message })
    }
    const { machineId, label, features, notes } = body
    if (!machineId) {
      return sendJson(res, 400, { ok: false, error: 'machineId is required' })
    }
    const validation = validateFeaturesBody(features)
    if (!validation.valid) {
      return sendJson(res, 400, { ok: false, error: validation.error })
    }
    const subscriber = addOrUpdate({ machineId, label, features: validation.features, notes })
    log(`[admin] upsert subscriber machineId=${machineId} features=${JSON.stringify(subscriber.features)}`)
    return sendJson(res, 200, { ok: true, subscriber })
  }

  // PATCH /subscribers/:machineId
  if (req.method === 'PATCH' && pathname.startsWith('/subscribers/')) {
    const machineId = decodeURIComponent(pathname.slice('/subscribers/'.length))
    let body
    try {
      body = await readJsonBody(req)
    } catch (err) {
      return sendJson(res, 400, { ok: false, error: err.message })
    }
    const { feature, active } = body
    if (!KNOWN_FEATURES.includes(feature)) {
      return sendJson(res, 400, {
        ok: false,
        error: `feature must be one of: ${KNOWN_FEATURES.join(', ')}`
      })
    }
    const found = setActive(machineId, feature, active === true)
    if (!found) {
      return sendJson(res, 404, { ok: false, error: 'Not found' })
    }
    log(`[admin] setActive machineId=${machineId} feature=${feature} active=${active === true}`)
    return sendJson(res, 200, { ok: true, machineId, feature, active: active === true })
  }

  // DELETE /subscribers/:machineId
  if (req.method === 'DELETE' && pathname.startsWith('/subscribers/')) {
    const machineId = decodeURIComponent(pathname.slice('/subscribers/'.length))
    const found = remove(machineId)
    if (!found) {
      return sendJson(res, 404, { ok: false, error: 'Not found' })
    }
    log(`[admin] remove machineId=${machineId}`)
    return sendJson(res, 200, { ok: true })
  }

  return sendJson(res, 404, { ok: false, error: 'Not found' })
})

export function startAdminServer() {
  if (!ADMIN_TOKEN) {
    log('[admin] WARNING: ADMIN_TOKEN is not set — admin API will reject every request')
  }
  adminServer.listen(ADMIN_PORT, ADMIN_HOST)
  return adminServer
}
