/**
 * NXTech POS Pro — Remote Access admin API
 *
 * A loopback-only HTTP control plane for the subscriber whitelist. It lets you
 * add, list, deactivate (kill-switch), reactivate, and remove shops without
 * touching the relay process or hand-editing subscribers.json.
 *
 * Security model: this server binds to 127.0.0.1 ONLY and requires a static
 * bearer token on every request except /health. It is meant to be reached over
 * SSH/loopback by the operator, never exposed publicly. Do not bind 0.0.0.0.
 *
 * Endpoints (all require `Authorization: Bearer <ADMIN_TOKEN>` except /health):
 *   GET    /health                      -> { ok: true }                (no auth)
 *   GET    /subscribers                 -> { subscribers: [...] }
 *   POST   /subscribers                 -> body { machineId, label, active, notes }
 *                                          { ok: true, subscriber }
 *   PATCH  /subscribers/:machineId      -> body { active }
 *                                          { ok: true } | 404 { ok:false }
 *   DELETE /subscribers/:machineId      -> { ok: true } | 404 { ok:false }
 */

import http from 'http'
import { addOrUpdate, setActive, remove, listAll } from './subscribers.js'

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
    const { machineId, label, active, notes } = body
    if (!machineId) {
      return sendJson(res, 400, { ok: false, error: 'machineId is required' })
    }
    const subscriber = addOrUpdate({ machineId, label, active, notes })
    log(`[admin] upsert subscriber machineId=${machineId} active=${active === true}`)
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
    const found = setActive(machineId, body.active === true)
    if (!found) {
      return sendJson(res, 404, { ok: false, error: 'Not found' })
    }
    log(`[admin] setActive machineId=${machineId} active=${body.active === true}`)
    return sendJson(res, 200, { ok: true })
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
