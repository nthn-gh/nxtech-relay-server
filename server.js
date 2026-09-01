/**
 * NXTech POS Pro — Remote Access relay server
 *
 * A tiny, stateless (in-memory only) WebSocket pairing/relay.
 *
 * Two peers — a shop PC ("host") and an owner's remote device ("client") —
 * each open an OUTBOUND WebSocket to this server using the SAME pairing code.
 * Once both sides are present the server forwards raw frames between them in
 * both directions. Neither peer needs an inbound/public port, so it works
 * behind NAT/CGNAT.
 *
 * This server NEVER inspects or stores the relayed payloads. It knows nothing
 * about the POS database, sessions, or auth — those all live on the host. The
 * pairing code is a transport-layer rendezvous secret only; it is NOT a login
 * credential (the host still validates the POS session token inside every
 * forwarded request).
 *
 * Endpoints:
 *   GET  /health                            -> { ok: true, activePairings: N }
 *   WS   /connect?code=<code>&role=host|client
 *   POST /mobile-upload?code=<code>&fileName=<name>  -> stage a file for the
 *        Host paired on <code>, notify it over the existing WS connection.
 *        Body is the raw file bytes; Content-Type is used as the mimeType.
 *   GET  /mobile-upload/:uploadToken        -> one-time fetch of a staged
 *        file's bytes (Host-initiated, over a plain HTTPS request).
 *   GET  /track/:jobId/:slug?code=<code>    -> Mobile Data QR Job Order
 *        Tracking. This relay does NOT render the tracking page itself — it
 *        forwards jobId+slug to the paired Host over the existing WS
 *        connection and proxies back whatever HTML the Host renders
 *        (reusing the exact same template the LAN tracking route uses).
 *        See pendingTrackRequests below.
 *   GET  /?code=<code>                      -> public Loyalty Points lookup
 *        phone-entry form (meant to be reached via a dedicated
 *        points.nxtech.online subdomain pointed at this same process).
 *   POST /lookup?code=<code>                -> the actual phone lookup,
 *        body is x-www-form-urlencoded phone=<value>. Same Host-round-trip
 *        proxy pattern as /track (see pendingPointsRequests below), plus an
 *        IP+code rate limit (rateLimiter.js) since this endpoint has no
 *        other access control — a phone number alone is not a secret.
 */

import http from 'http'
import { WebSocketServer } from 'ws'
import { randomBytes } from 'crypto'
import { isActive } from './subscribers.js'
import { startAdminServer } from './admin.js'
import { checkAndConsume, sweepExpired } from './rateLimiter.js'
import { getDbFileSizeBytes, pruneOldSnapshots } from './db.js'
import {
  handleSyncRegister,
  handleSyncPush,
  handlePairingCodeGenerate,
  handleSessionsList,
  handleSessionRevoke
} from './sync.js'
import { handleDashboardClaim, handleDashboardEntityList, handleDashboardOptions, handleDashboardForget, handleDashboardSessionsList } from './dashboard.js'

const PORT = Number(process.env.PORT || process.env.RELAY_PORT || 8787)
const HOST = process.env.HOST || '0.0.0.0'
const HEARTBEAT_MS = Number(process.env.HEARTBEAT_MS || 30000)
const MAX_CODE_LENGTH = 128

// URL slug (what a dashboard client requests) -> internal entity_type
// (what the app's outbox / this relay's snapshots table actually store).
const DASHBOARD_ENTITY_ROUTES = {
  sales: 'sale',
  'job-orders': 'job_order',
  inventory: 'inventory',
  expenses: 'expense',
  'daily-closing': 'daily_closing'
}

// How often pruneOldSnapshots() (12-month rolling retention, db.js) runs.
// Daily is more than enough for a bound that only matters over months.
const SNAPSHOT_PRUNE_INTERVAL_MS = 24 * 60 * 60 * 1000

// code -> { host: ws|null, client: ws|null }
const pairings = new Map()

// Mobile Data mode file upload staging — in-memory only, deliberately not
// persisted anywhere (matches this relay's existing "never inspects or
// stores the relayed payloads" posture; this is the one narrow exception,
// and only ever holds a file for a few minutes at most before the Host
// claims it or the TTL discards it).
// uploadToken -> { code, fileName, fileSize, mimeType, data: Buffer, timer }
const stagedUploads = new Map()
const MOBILE_UPLOAD_MAX_BYTES = 25 * 1024 * 1024 // 25MB
const MOBILE_UPLOAD_TTL_MS = 5 * 60 * 1000 // 5 minutes

// Mobile Data QR Job Order Tracking — a phone's GET /track request is held
// open (its `res` kept here) while we wait for the paired Host to answer
// over the existing WS connection. Deliberately a SEPARATE Map from
// `pairings` (additive only — this must never change pairings' existing
// shape/keying, which the Received Files Mobile Data path also depends on).
// id -> { res, timer, code }
const pendingTrackRequests = new Map()
const TRACK_PATH_RE = /^\/track\/(\d+)\/([a-f0-9]{12})$/
const TRACK_REQUEST_TIMEOUT_MS = 8000
// Two caps, not one: per-code protects one shop's single Host WS connection
// from being buried under its own customers' polling; global protects this
// relay's overall memory if something is broadly wrong (e.g. many hosts
// simultaneously unresponsive). Both are generous relative to the current
// scale (~5 subscribers) — they exist to bound a broken/stuck Host, not to
// constrain normal traffic.
const MAX_PENDING_TRACK_PER_CODE = 5
const MAX_PENDING_TRACK_GLOBAL = 100

// Public Loyalty Points lookup (phone number entry) — a PARALLEL SIBLING to
// the tracking pending-map above, not a shared pool. pendingTrackRequests'
// caps/dispatch are hardcoded to "track" throughout this file (entry shape
// has no `type` discriminator, the WS handler matches on the literal string
// 'track_response'), so sharing the same Map/caps would need a refactor of
// that existing code — out of this feature's risk budget. Copy-and-rename
// instead, exactly mirroring pendingTrackRequests' shape and constants.
// id -> { res, timer, code }
const pendingPointsRequests = new Map()
const POINTS_REQUEST_TIMEOUT_MS = 8000
const MAX_PENDING_POINTS_PER_CODE = 5
const MAX_PENDING_POINTS_GLOBAL = 100

// Rate limit for the actual phone lookup (not page views of the static
// form) — IP+code keyed, so one IP hammering one shop's code is limited
// independently of that same IP trying a different shop's code. Generous
// enough for a customer who mistypes their number a couple of times;
// tight enough to meaningfully blunt casual phone-number enumeration.
const POINTS_LOOKUP_RATE_LIMIT = 5
const POINTS_LOOKUP_RATE_WINDOW_MS = 5 * 60 * 1000 // 5 minutes
const POINTS_LOOKUP_MAX_BODY_BYTES = 1024

function log(...args) {
  console.log(new Date().toISOString(), ...args)
}

// Pairing codes are transport secrets — log only a short prefix so entries can
// be correlated without exposing the full code.
function maskCode(code) {
  return `${String(code || '').slice(0, 4)}...`
}

function activePairingCount() {
  // A pairing is "active" when both ends are currently connected.
  let n = 0
  for (const pair of pairings.values()) {
    if (pair.host && pair.client) n++
  }
  return n
}

function peerRole(role) {
  return role === 'host' ? 'client' : 'host'
}

// nginx (see README.md's documented reverse-proxy config) already sets
// X-Forwarded-For on every request; this Node process just never read it
// before now. Takes the FIRST address in the (possibly comma-separated)
// header, since that's the original client — everything after it is
// intermediate proxies. Falls back to the raw socket address (useful when
// testing without nginx in front, and a defensive fallback if the header is
// ever absent in production).
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (forwarded) {
    const first = String(forwarded).split(',')[0].trim()
    if (first) return first
  }
  return req.socket?.remoteAddress || 'unknown'
}

function cleanupPairing(code) {
  const pair = pairings.get(code)
  if (pair && !pair.host && !pair.client) {
    pairings.delete(code)
  }
}

// ---------------------------------------------------------------------------
// HTTP server (health check + WS upgrade entry point)
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/health' || req.url.startsWith('/health?'))) {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    // monitoringDbBytes is basic disk-usage visibility for the Remote
    // Monitoring snapshot store (finding #7) -- not a full alerting
    // pipeline, just enough to notice unbounded growth from the same
    // /health an operator (or uptime monitor) already polls.
    res.end(
      JSON.stringify({
        ok: true,
        activePairings: activePairingCount(),
        monitoringDbBytes: getDbFileSizeBytes()
      })
    )
    return
  }

  // ---------------------------------------------------------------------
  // Remote Monitoring Dashboard -- app-facing sync API (sync.js). Own
  // credential family (sync_token), entirely separate from the pairing
  // code above (see module header comments in sync.js/dashboard.js).
  // ---------------------------------------------------------------------
  if (req.method === 'POST' && req.url.startsWith('/sync/register')) {
    handleSyncRegister(req, res)
    return
  }
  if (req.method === 'POST' && req.url.startsWith('/sync/push')) {
    handleSyncPush(req, res)
    return
  }
  if (req.method === 'POST' && req.url.startsWith('/sync/pairing-code')) {
    handlePairingCodeGenerate(req, res)
    return
  }
  if (req.method === 'GET' && req.url.startsWith('/sync/sessions')) {
    handleSessionsList(req, res)
    return
  }
  if (req.method === 'POST' && req.url.startsWith('/sync/sessions/revoke')) {
    handleSessionRevoke(req, res)
    return
  }

  // ---------------------------------------------------------------------
  // Remote Monitoring Dashboard -- browser-facing API (dashboard.js).
  // ---------------------------------------------------------------------
  if (req.method === 'OPTIONS' && req.url.startsWith('/dashboard/')) {
    handleDashboardOptions(req, res)
    return
  }
  if (req.method === 'POST' && req.url.startsWith('/dashboard/claim')) {
    handleDashboardClaim(req, res)
    return
  }
  if (req.method === 'POST' && req.url.startsWith('/dashboard/forget')) {
    handleDashboardForget(req, res)
    return
  }
  // Branch switcher's own listing -- must be checked before the generic
  // /dashboard/:entityType fallback below, since 'sessions' isn't (and
  // must never become) one of DASHBOARD_ENTITY_ROUTES' slugs.
  if (req.method === 'GET' && req.url.startsWith('/dashboard/sessions')) {
    handleDashboardSessionsList(req, res)
    return
  }
  // /dashboard/:entityType -- basic snapshot list, one route per known
  // entity type (URL uses the app's own naming; DASHBOARD_ENTITY_ROUTES
  // maps the URL slug to the internal entity_type stored in `snapshots`).
  if (req.method === 'GET' && req.url.startsWith('/dashboard/')) {
    const slug = req.url.split('?')[0].slice('/dashboard/'.length)
    const entityType = DASHBOARD_ENTITY_ROUTES[slug]
    if (entityType) {
      handleDashboardEntityList(req, res, entityType)
      return
    }
  }

  // Mobile Data QR Job Order Tracking. req.url carries the query string
  // (?code=...), so match against the pathname only.
  if (req.method === 'GET' && TRACK_PATH_RE.test(req.url.split('?')[0])) {
    handleTrackRequest(req, res, req.url.split('?')[0])
    return
  }

  // Checked BEFORE the plain '/mobile-upload' file-upload route below —
  // '/mobile-upload-link' also starts with '/mobile-upload', so the more
  // specific route must win or it would never be reached.
  if (req.method === 'POST' && req.url.startsWith('/mobile-upload-link')) {
    handleMobileUploadLink(req, res)
    return
  }

  if (req.method === 'POST' && req.url.startsWith('/mobile-upload')) {
    handleMobileUpload(req, res)
    return
  }

  if (req.method === 'GET' && req.url.startsWith('/mobile-upload/')) {
    handleMobileUploadFetch(req, res)
    return
  }

  // Phone-facing upload form — GET /mobile-upload (with no trailing path
  // segment; the check above already claimed /mobile-upload/<token>).
  if (req.method === 'GET' && req.url.startsWith('/mobile-upload')) {
    handleMobileUploadPage(req, res)
    return
  }

  // Public Loyalty Points lookup — the actual phone lookup (rate-limited).
  if (req.method === 'POST' && req.url.startsWith('/lookup')) {
    handlePointsLookup(req, res)
    return
  }

  // Points-lookup phone-entry form, served at the bare root so
  // points.nxtech.online/?code=<code> is the clean customer-facing URL —
  // this relay has no other route at '/' today, and nginx can point either
  // relay.nxtech.online or a dedicated points.nxtech.online at this same
  // process (see relay-server/README.md's deployment section for adding a
  // new server_name + cert).
  if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/?'))) {
    handlePointsFormPage(req, res)
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ ok: false, error: 'Not found' }))
})

function sendMobileJson(res, status, body, closeConnection) {
  const headers = { 'Content-Type': 'application/json' }
  if (closeConnection) headers.Connection = 'close'
  res.writeHead(status, headers)
  res.end(JSON.stringify(body))
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// The phone-facing upload page for Mobile Data mode. Deliberately NOT a
// native <form enctype="multipart/form-data"> submission — POST
// /mobile-upload expects the raw file bytes as the entire request body
// (Content-Type = the file's own mime type), matching what
// receivedFiles.service.js's single-element preparedFiles array expects on
// the Host side. A plain multipart form post would not match that contract,
// so this uses a small vanilla-JS fetch() to send the File object's raw
// bytes directly, with the result shown in-page (no navigation/reload).
function mobileUploadPageHtml(code) {
  const safeCode = escapeHtml(code)
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Send a File</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#f8fafc;margin:0;padding:32px 16px;color:#0f172a}
.card{max-width:420px;margin:0 auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:18px;margin:0 0 16px}
.data-note{font-size:13px;color:#475569;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;margin-bottom:16px}
input[type=file]{width:100%;padding:12px;border:1px dashed #94a3b8;border-radius:8px;margin-bottom:16px;box-sizing:border-box;background:#f8fafc}
input[type=text]{width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:12px;box-sizing:border-box;font-size:15px}
button{width:100%;padding:14px;background:#2563eb;color:#fff;border:0;border-radius:8px;font-size:16px;font-weight:600}
button:disabled{opacity:.6}
.divider{text-align:center;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin:18px 0 14px}
.status{font-size:14px;margin-top:12px}
.status.error{color:#dc2626}
.status.ok{color:#16a34a;font-weight:600}
</style></head><body>
<div class="card">
  <h1>Send a file to the shop</h1>
  <div class="data-note">Use your phone's Mobile Data for this — you do NOT need to be on the shop's Wi-Fi.</div>
  ${!code ? '<div class="status error">Invalid or missing link. Ask staff for a new QR code.</div>' : ''}
  <input type="file" id="fileInput" multiple ${code ? '' : 'disabled'}>
  <button id="uploadBtn" ${code ? '' : 'disabled'}>Upload</button>
  <div id="status" class="status"></div>
  <div class="divider">or</div>
  <input type="text" id="linkInput" maxlength="255" placeholder="Paste a Canva, Drive, or Dropbox link" ${code ? '' : 'disabled'}>
  <button id="linkBtn" ${code ? '' : 'disabled'}>Send Link</button>
  <div id="linkStatus" class="status"></div>
</div>
<script>
(function () {
  var code = ${JSON.stringify(String(code || ''))}
  // Mirrors receivedFiles.service.js's MAX_FILES_PER_UPLOAD (LAN mode's
  // per-submission cap) — kept as a plain client-side constant since this
  // is a separate project with no shared module to import it from.
  var MAX_FILES = 10
  var btn = document.getElementById('uploadBtn')
  var input = document.getElementById('fileInput')
  var statusEl = document.getElementById('status')

  function uploadOne(file) {
    return fetch('/mobile-upload?code=' + encodeURIComponent(code) + '&fileName=' + encodeURIComponent(file.name), {
      method: 'POST',
      headers: { 'Content-Type': file.type || 'application/octet-stream' },
      body: file
    })
      .then(function (res) { return res.json().then(function (data) { return { ok: res.ok, data: data } }) })
      .then(function (result) {
        if (result.ok && result.data && result.data.ok) return { name: file.name, success: true }
        return { name: file.name, success: false, error: (result.data && result.data.error) || 'please try again.' }
      })
      .catch(function (err) {
        return { name: file.name, success: false, error: err.message }
      })
  }

  // Sequential, not concurrent — one request finishes (or fails) before the
  // next starts, so the relay never has to hold more than one file's worth
  // of memory pressure per submission at a time, matching the 25MB-per-file
  // design's assumption. Each file's request is genuinely independent (not
  // one atomic multipart body like the LAN path), so a later failure does
  // NOT stop or undo earlier successes — every file gets its own outcome,
  // reported in a per-file summary at the end. Retroactively "undoing" an
  // already-staged-and-claimed upload on the relay if a later file fails
  // would need new relay-side machinery for no real benefit here.
  async function uploadAll(files) {
    var results = []
    for (var i = 0; i < files.length; i++) {
      statusEl.className = 'status'
      statusEl.textContent = 'Uploading ' + (i + 1) + ' of ' + files.length + '…'
      var result = await uploadOne(files[i])
      results.push(result)
    }
    return results
  }

  btn.addEventListener('click', function () {
    var files = input.files
    if (!files || files.length === 0) {
      statusEl.className = 'status error'
      statusEl.textContent = 'Please choose a file first.'
      return
    }
    if (files.length > MAX_FILES) {
      statusEl.className = 'status error'
      statusEl.textContent = 'Too many files. Max ' + MAX_FILES + ' files per upload.'
      return
    }
    btn.disabled = true
    uploadAll(files).then(function (results) {
      btn.disabled = false
      var succeeded = results.filter(function (r) { return r.success }).length
      var failed = results.filter(function (r) { return !r.success })
      if (failed.length === 0) {
        statusEl.className = 'status ok'
        statusEl.textContent = (results.length > 1 ? results.length + ' files sent!' : 'File sent!') +
          ' Staff can now see ' + (results.length > 1 ? 'them' : 'it') + ' on the counter screen. You can close this page.'
      } else {
        statusEl.className = 'status error'
        var summary = succeeded + ' of ' + results.length + ' file(s) sent. Failed: ' +
          failed.map(function (r) { return r.name + ' (' + r.error + ')' }).join('; ')
        statusEl.textContent = summary
      }
    })
  })

  var linkBtn = document.getElementById('linkBtn')
  var linkInput = document.getElementById('linkInput')
  var linkStatusEl = document.getElementById('linkStatus')

  linkBtn.addEventListener('click', function () {
    var link = linkInput.value.trim()
    if (!link) {
      linkStatusEl.className = 'status error'
      linkStatusEl.textContent = 'Please paste a link first.'
      return
    }
    linkBtn.disabled = true
    linkStatusEl.className = 'status'
    linkStatusEl.textContent = 'Sending…'
    fetch('/mobile-upload-link?code=' + encodeURIComponent(code), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ link: link })
    })
      .then(function (res) { return res.json().then(function (data) { return { ok: res.ok, data: data } }) })
      .then(function (result) {
        linkBtn.disabled = false
        if (result.ok && result.data && result.data.ok) {
          linkStatusEl.className = 'status ok'
          linkStatusEl.textContent = 'Link sent! Staff can now see it on the counter screen.'
          linkInput.value = ''
        } else {
          linkStatusEl.className = 'status error'
          linkStatusEl.textContent = (result.data && result.data.error) || 'Could not send link.'
        }
      })
      .catch(function (err) {
        linkBtn.disabled = false
        linkStatusEl.className = 'status error'
        linkStatusEl.textContent = err.message
      })
  })
})()
</script>
</body></html>`
}

// GET /mobile-upload?code=<code> — the phone-facing form page.
function handleMobileUploadPage(req, res) {
  let parsed
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    res.writeHead(400, { 'Content-Type': 'text/html' })
    return res.end('Bad request')
  }
  const code = (parsed.searchParams.get('code') || '').trim()
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(mobileUploadPageHtml(code))
}

// POST /mobile-upload?code=<code>&fileName=<name>
function handleMobileUpload(req, res) {
  let parsed
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    return sendMobileJson(res, 400, { ok: false, error: 'Bad request' }, true)
  }

  const code = (parsed.searchParams.get('code') || '').trim()
  const fileName = (parsed.searchParams.get('fileName') || 'upload').trim().slice(0, 255)

  if (!code || code.length > MAX_CODE_LENGTH) {
    // Nothing read from the body yet — safe to reject and close without
    // buffering anything.
    req.destroy()
    return sendMobileJson(res, 400, { ok: false, error: 'code is required' }, true)
  }

  // Immediate rejection, BEFORE accepting any request body, if no Host is
  // currently connected on this code — the exact same condition the
  // existing HOST_UNAVAILABLE relay-error already tests for WS traffic.
  const pair = pairings.get(code)
  const hostWs = pair && pair.host
  if (!hostWs || hostWs.readyState !== hostWs.OPEN) {
    req.destroy()
    return sendMobileJson(
      res,
      503,
      { ok: false, error: 'No Host is currently connected for this code.' },
      true
    )
  }

  const mimeType = String(req.headers['content-type'] || 'application/octet-stream')
    .split(';')[0]
    .trim()

  const chunks = []
  let received = 0
  let rejected = false

  req.on('data', (chunk) => {
    if (rejected) return
    received += chunk.length
    // Enforced incrementally as bytes arrive, not only after the full body
    // is buffered — a request that exceeds the cap is aborted immediately,
    // it is never allowed to finish buffering first.
    if (received > MOBILE_UPLOAD_MAX_BYTES) {
      rejected = true
      sendMobileJson(
        res,
        413,
        { ok: false, error: `File is too large. Max ${Math.floor(MOBILE_UPLOAD_MAX_BYTES / (1024 * 1024))}MB.` },
        true
      )
      req.destroy()
      return
    }
    chunks.push(chunk)
  })

  req.on('error', () => {})

  req.on('end', () => {
    if (rejected) return

    const data = Buffer.concat(chunks)
    if (data.length === 0) {
      return sendMobileJson(res, 400, { ok: false, error: 'No file data received.' }, true)
    }

    const uploadToken = randomBytes(16).toString('hex')
    const entry = { code, fileName, fileSize: data.length, mimeType, data, timer: null }
    entry.timer = setTimeout(() => {
      if (stagedUploads.get(uploadToken) === entry) {
        stagedUploads.delete(uploadToken)
        log(
          `[mobile-upload] staged upload ${uploadToken.slice(0, 8)}... expired unclaimed (code=${maskCode(code)})`
        )
      }
    }, MOBILE_UPLOAD_TTL_MS)
    stagedUploads.set(uploadToken, entry)

    // Notify the Host over its EXISTING WS connection — a new message type,
    // synthesized by the relay itself, same "self-answered, not forwarded"
    // category as the existing 'entitlement' message.
    try {
      hostWs.send(
        JSON.stringify({
          type: 'incoming_file',
          uploadToken,
          fileName,
          fileSize: data.length,
          mimeType
        })
      )
    } catch (_) {}

    log(
      `[mobile-upload] staged ${data.length} bytes for code=${maskCode(code)}, token=${uploadToken.slice(0, 8)}...`
    )
    sendMobileJson(res, 200, { ok: true, message: 'File sent to shop.' })
  })
}

// GET /mobile-upload/:uploadToken — one-time retrieval, Host-initiated.
function handleMobileUploadFetch(req, res) {
  const uploadToken = decodeURIComponent(req.url.slice('/mobile-upload/'.length).split('?')[0])
  const entry = stagedUploads.get(uploadToken)

  if (!entry) {
    return sendMobileJson(res, 404, { ok: false, error: 'Upload not found or already claimed/expired.' })
  }

  // Remove BEFORE sending the response body — a second concurrent/retried
  // fetch for the same token must not also be able to claim it. Relying
  // solely on the TTL would leave a window where a legitimately-claimed
  // file could still be fetched again.
  stagedUploads.delete(uploadToken)
  clearTimeout(entry.timer)

  log(
    `[mobile-upload] serving staged upload ${uploadToken.slice(0, 8)}... (${entry.fileSize} bytes) to Host`
  )

  res.writeHead(200, {
    'Content-Type': entry.mimeType,
    'Content-Length': entry.fileSize,
    // Header values must be ASCII; encode in case of a non-ASCII filename.
    'X-File-Name': encodeURIComponent(entry.fileName)
  })
  res.end(entry.data)
}

// POST /mobile-upload-link?code=<code> — body is JSON { link: '<url>' }.
// This relay NEVER validates the link's scheme/shape (matching the file
// path's "never inspects the relayed payload" posture, see file header) —
// it only forwards the raw string to the Host over the existing WS
// connection. All real validation (isValidHttpUrl's http:/https: scheme
// check) happens Host-side, inside submitLink(), exactly like a LAN
// submission.
const MOBILE_LINK_MAX_BODY_BYTES = 4 * 1024

function handleMobileUploadLink(req, res) {
  let parsed
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    return sendMobileJson(res, 400, { ok: false, error: 'Bad request' }, true)
  }

  const code = (parsed.searchParams.get('code') || '').trim()

  if (!code || code.length > MAX_CODE_LENGTH) {
    req.destroy()
    return sendMobileJson(res, 400, { ok: false, error: 'code is required' }, true)
  }

  const pair = pairings.get(code)
  const hostWs = pair && pair.host
  if (!hostWs || hostWs.readyState !== hostWs.OPEN) {
    req.destroy()
    return sendMobileJson(
      res,
      503,
      { ok: false, error: 'No Host is currently connected for this code.' },
      true
    )
  }

  const chunks = []
  let received = 0
  let rejected = false

  req.on('data', (chunk) => {
    if (rejected) return
    received += chunk.length
    if (received > MOBILE_LINK_MAX_BODY_BYTES) {
      rejected = true
      sendMobileJson(res, 413, { ok: false, error: 'Request too large.' }, true)
      req.destroy()
      return
    }
    chunks.push(chunk)
  })

  req.on('error', () => {})

  req.on('end', () => {
    if (rejected) return

    let linkUrl = ''
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf-8'))
      linkUrl = String(body.link || '').trim()
    } catch (_) {
      linkUrl = ''
    }

    if (!linkUrl) {
      return sendMobileJson(res, 400, { ok: false, error: 'No link provided.' }, true)
    }

    // Sibling to 'incoming_file' — a new message type synthesized by
    // forwarding the phone's submission over the Host's existing WS
    // connection.
    try {
      hostWs.send(JSON.stringify({ type: 'incoming_link', linkUrl }))
    } catch (_) {}

    log(`[mobile-upload-link] forwarded link for code=${maskCode(code)}`)
    sendMobileJson(res, 200, { ok: true, message: 'Link sent to shop.' })
  })
}

// ---------------------------------------------------------------------------
// Mobile Data QR Job Order Tracking
// ---------------------------------------------------------------------------

function sendTrackHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(html)
}

// Deliberately NOT the same page as the Host's "not found" (invalid slug)
// state — that's the Host's call to make (it owns getPublicJobOrderStatus's
// not-found decision), proxied back verbatim. This page is this relay's OWN
// concern only: no Host connected, no answer within the timeout, or the
// concurrency cap was hit. Styled to match the Host-rendered tracking pages
// (jobOrderTrackingServer.js's pageShell) even though this relay can't
// import that module directly (separate deployable package, no shared
// module boundary) — so a customer sees one consistent visual language
// regardless of which page they land on.
function unreachablePageHtml() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shop Unreachable</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0f172a;margin:0;padding:32px 16px;color:#0f172a;min-height:100vh;box-sizing:border-box}
.card{max-width:420px;margin:0 auto;background:#fff;border-radius:16px;padding:28px 24px;box-shadow:0 8px 24px rgba(0,0,0,.25);text-align:center}
.msg{font-size:15px;color:#334155;line-height:1.5}
</style></head><body><div class="card"><div class="msg">We couldn't reach the shop right now. Please try again in a bit.</div></div></body></html>`
}

// Same visual language as unreachablePageHtml() — a distinct message so a
// customer who's just retrying too fast isn't told "the shop is
// unreachable" (misleading; the shop is fine, they just need to wait).
function tooManyAttemptsPageHtml() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Please Wait</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0f172a;margin:0;padding:32px 16px;color:#0f172a;min-height:100vh;box-sizing:border-box}
.card{max-width:420px;margin:0 auto;background:#fff;border-radius:16px;padding:28px 24px;box-shadow:0 8px 24px rgba(0,0,0,.25);text-align:center}
.msg{font-size:15px;color:#334155;line-height:1.5}
</style></head><body><div class="card"><div class="msg">Too many attempts. Please wait a few minutes and try again.</div></div></body></html>`
}

function countPendingTrackForCode(code) {
  let n = 0
  for (const entry of pendingTrackRequests.values()) {
    if (entry.code === code) n++
  }
  return n
}

// Called when a 'track_response' arrives from the Host (see the connection
// message handler below) OR when a pending request's timeout fires —
// whichever happens first wins; the other becomes a no-op via the Map
// lookup (an already-resolved/timed-out id is simply absent).
function resolveTrackRequest(id, status, html) {
  const entry = pendingTrackRequests.get(id)
  if (!entry) return
  clearTimeout(entry.timer)
  pendingTrackRequests.delete(id)
  sendTrackHtml(entry.res, Number(status) || 200, String(html || ''))
}

// GET /track/:jobId/:slug?code=<code>
function handleTrackRequest(req, res, pathname) {
  const match = TRACK_PATH_RE.exec(pathname)
  // The caller only routes matching paths here; kept as a defensive
  // fallback in case that ever changes.
  if (!match) {
    res.writeHead(404, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: false, error: 'Not found' }))
  }
  const [, jobId, slug] = match

  let parsedUrl
  try {
    parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    return sendTrackHtml(res, 400, unreachablePageHtml())
  }
  const code = (parsedUrl.searchParams.get('code') || '').trim()

  if (!code || code.length > MAX_CODE_LENGTH) {
    return sendTrackHtml(res, 400, unreachablePageHtml())
  }

  const pair = pairings.get(code)
  const hostWs = pair && pair.host
  if (!hostWs || hostWs.readyState !== hostWs.OPEN) {
    // No Host at all — respond immediately, no need to wait out the timeout.
    return sendTrackHtml(res, 503, unreachablePageHtml())
  }

  if (
    pendingTrackRequests.size >= MAX_PENDING_TRACK_GLOBAL ||
    countPendingTrackForCode(code) >= MAX_PENDING_TRACK_PER_CODE
  ) {
    log(`[track] rejecting request for code=${maskCode(code)} — concurrency cap reached`)
    return sendTrackHtml(res, 503, unreachablePageHtml())
  }

  const id = randomBytes(8).toString('hex')
  const timer = setTimeout(() => {
    log(`[track] request ${id.slice(0, 8)}... timed out waiting for Host (code=${maskCode(code)})`)
    resolveTrackRequest(id, 503, unreachablePageHtml())
  }, TRACK_REQUEST_TIMEOUT_MS)

  pendingTrackRequests.set(id, { res, timer, code })

  try {
    hostWs.send(JSON.stringify({ type: 'track_request', id, jobId, slug }))
  } catch (_) {
    clearTimeout(timer)
    pendingTrackRequests.delete(id)
    return sendTrackHtml(res, 503, unreachablePageHtml())
  }
}

// ---------------------------------------------------------------------------
// Public Loyalty Points lookup (phone number entry)
// ---------------------------------------------------------------------------

function sendPointsHtml(res, status, html, closeConnection) {
  const headers = { 'Content-Type': 'text/html; charset=utf-8' }
  if (closeConnection) headers.Connection = 'close'
  res.writeHead(status, headers)
  res.end(html)
}

// The phone-entry form page. A plain native <form method="POST"> submission
// (unlike mobile-upload's fetch()-based page) — the results ARE a full
// rendered HTML document from the Host (or this relay's own error page), so
// a normal form POST + browser navigation is simplest: no client-side JS
// needed at all, nothing to keep in sync with a JSON response shape.
function pointsLookupFormHtml(code) {
  const safeCode = escapeHtml(code)
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Check Your Points</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#f8fafc;margin:0;padding:32px 16px;color:#0f172a}
.card{max-width:420px;margin:0 auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:18px;margin:0 0 16px}
input[type=tel]{width:100%;padding:14px;border:1px solid #cbd5e1;border-radius:8px;margin-bottom:16px;box-sizing:border-box;font-size:16px}
button{width:100%;padding:14px;background:#2563eb;color:#fff;border:0;border-radius:8px;font-size:16px;font-weight:600}
.status{font-size:14px;color:#dc2626;margin-top:12px}
</style></head><body>
<div class="card">
  <h1>Check your points balance</h1>
  ${!code ? '<div class="status">Invalid or missing link. Ask staff for the correct link.</div>' : `
  <form method="POST" action="/lookup?code=${encodeURIComponent(code)}">
    <input type="tel" name="phone" inputmode="numeric" maxlength="20" placeholder="09XXXXXXXXX" required>
    <button type="submit">Check My Points</button>
  </form>
  `}
</div>
</body></html>`
}

// GET /?code=<code>
function handlePointsFormPage(req, res) {
  let parsed
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    res.writeHead(400, { 'Content-Type': 'text/html' })
    return res.end('Bad request')
  }
  const code = (parsed.searchParams.get('code') || '').trim()
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(pointsLookupFormHtml(code))
}

function countPendingPointsForCode(code) {
  let n = 0
  for (const entry of pendingPointsRequests.values()) {
    if (entry.code === code) n++
  }
  return n
}

// Sibling to resolveTrackRequest() — same "first resolver wins, the other is
// a no-op via the Map lookup" pattern.
function resolvePointsRequest(id, status, html) {
  const entry = pendingPointsRequests.get(id)
  if (!entry) return
  clearTimeout(entry.timer)
  pendingPointsRequests.delete(id)
  sendPointsHtml(entry.res, Number(status) || 200, String(html || ''))
}

// POST /lookup?code=<code>, body is application/x-www-form-urlencoded
// phone=<value> (matching the plain <form> above — no JSON parsing needed).
function handlePointsLookup(req, res) {
  let parsedUrl
  try {
    parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    return sendPointsHtml(res, 400, unreachablePageHtml())
  }
  const code = (parsedUrl.searchParams.get('code') || '').trim()

  if (!code || code.length > MAX_CODE_LENGTH) {
    // Nothing read from the body yet — respond and let the connection close
    // itself via the Connection: close header, same as mobile-upload's
    // equivalent early-rejection paths. Explicitly destroying the request
    // stream HERE (before any body bytes have arrived) raced with writing
    // the response on the same socket and surfaced as a client-side
    // "socket hang up" instead of a clean 400 during testing — the
    // Connection: close header achieves the same "don't keep this
    // connection around" goal without that race.
    return sendPointsHtml(res, 400, unreachablePageHtml(), true)
  }

  // Rate limit BEFORE any Host round-trip work — cheap early rejection,
  // keyed on IP+code so this is independent per (caller, shop) pair.
  const ip = getClientIp(req)
  const rateLimitKey = `${ip}:${code}`
  if (!checkAndConsume(rateLimitKey, { limit: POINTS_LOOKUP_RATE_LIMIT, windowMs: POINTS_LOOKUP_RATE_WINDOW_MS })) {
    log(`[points] rate limit exceeded for ip=${ip}, code=${maskCode(code)}`)
    return sendPointsHtml(res, 429, tooManyAttemptsPageHtml(), true)
  }
  sweepExpired(POINTS_LOOKUP_RATE_WINDOW_MS)

  // Presence gate — identical to /track and /mobile-upload: respond
  // immediately if no Host is connected, never wait out the 8s timeout for
  // a shop that plainly isn't reachable right now.
  const pair = pairings.get(code)
  const hostWs = pair && pair.host
  if (!hostWs || hostWs.readyState !== hostWs.OPEN) {
    return sendPointsHtml(res, 503, unreachablePageHtml(), true)
  }

  if (
    pendingPointsRequests.size >= MAX_PENDING_POINTS_GLOBAL ||
    countPendingPointsForCode(code) >= MAX_PENDING_POINTS_PER_CODE
  ) {
    log(`[points] rejecting request for code=${maskCode(code)} — concurrency cap reached`)
    return sendPointsHtml(res, 503, unreachablePageHtml(), true)
  }

  const chunks = []
  let received = 0
  let rejected = false

  req.on('data', (chunk) => {
    if (rejected) return
    received += chunk.length
    if (received > POINTS_LOOKUP_MAX_BODY_BYTES) {
      rejected = true
      req.destroy()
      sendPointsHtml(res, 413, unreachablePageHtml(), true)
      return
    }
    chunks.push(chunk)
  })

  req.on('error', () => {})

  req.on('end', () => {
    if (rejected) return

    let phone = ''
    try {
      const body = new URLSearchParams(Buffer.concat(chunks).toString('utf-8'))
      phone = String(body.get('phone') || '').trim()
    } catch (_) {
      phone = ''
    }

    const id = randomBytes(8).toString('hex')
    const timer = setTimeout(() => {
      log(`[points] request ${id.slice(0, 8)}... timed out waiting for Host (code=${maskCode(code)})`)
      resolvePointsRequest(id, 503, unreachablePageHtml())
    }, POINTS_REQUEST_TIMEOUT_MS)

    pendingPointsRequests.set(id, { res, timer, code })

    try {
      hostWs.send(JSON.stringify({ type: 'points_request', id, phone }))
    } catch (_) {
      clearTimeout(timer)
      pendingPointsRequests.delete(id)
      sendPointsHtml(res, 503, unreachablePageHtml())
    }
  })
}

// noServer so we can validate the query string before accepting the upgrade.
// perMessageDeflate is explicitly disabled (not just left at its default) so
// a future 'ws' version bump can't silently change this and reintroduce a
// client/server compression-negotiation mismatch — the desktop app's Host
// connector matches this explicitly too. See relayHostClient.service.js.
const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false })

server.on('upgrade', (req, socket, head) => {
  let parsed
  try {
    parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch (_) {
    socket.destroy()
    return
  }

  if (parsed.pathname !== '/connect') {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n')
    socket.destroy()
    return
  }

  const code = (parsed.searchParams.get('code') || '').trim()
  const role = (parsed.searchParams.get('role') || '').trim()
  const machineId = (parsed.searchParams.get('machineId') || '').trim()

  if (!code || code.length > MAX_CODE_LENGTH || (role !== 'host' && role !== 'client')) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n')
    socket.destroy()
    return
  }

  // Subscription gate: only the host is checked. Clients carry no machineId —
  // if the host is blocked the client simply never gets a peer. The full
  // machineId is logged here (not masked) as the operator's audit trail.
  //
  // This only decides whether the connection is allowed to open at all — it
  // is an OR across features (either one is enough to open the socket).
  // WHICH capability an open connection may actually use is enforced
  // separately, at the application layer on the Host itself (per-request,
  // not here) — the relay stays a blind pipe and does not distinguish
  // remote_access traffic from mobile_data traffic once connected.
  //
  // Computed explicitly (not short-circuited) so both booleans are available
  // to send to the Host as its post-connection entitlement signal — see the
  // 'entitlement' message in the 'connection' handler below.
  const remoteAccessActive = role === 'host' ? isActive(machineId, 'remote_access') : false
  const mobileDataActive = role === 'host' ? isActive(machineId, 'mobile_data') : false
  if (role === 'host' && !remoteAccessActive && !mobileDataActive) {
    log(`[relay] BLOCKED host machineId=${machineId} — no active subscription (remote_access or mobile_data)`)
    const payload = JSON.stringify({
      code: 'SUBSCRIPTION_INACTIVE',
      message: 'No active subscription (Remote Access or Mobile Data) for this device. Contact NXTech support.',
    })
    socket.write(
      'HTTP/1.1 403 Forbidden\r\n' +
        'Content-Type: application/json\r\n' +
        'Connection: close\r\n' +
        `Content-Length: ${Buffer.byteLength(payload)}\r\n` +
        '\r\n' +
        payload
    )
    socket.destroy()
    return
  }

  if (role === 'host') {
    log(`[relay] ALLOWED host machineId=${machineId}`)
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.code = code
    ws.role = role
    ws.machineId = machineId
    ws.remoteAccessActive = remoteAccessActive
    ws.mobileDataActive = mobileDataActive
    wss.emit('connection', ws, req)
  })
})

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------
wss.on('connection', (ws) => {
  const { code, role } = ws
  ws.isAlive = true
  ws.on('pong', () => {
    ws.isAlive = true
  })

  let pair = pairings.get(code)
  if (!pair) {
    pair = { host: null, client: null }
    pairings.set(code, pair)
  }

  // Only one socket per role per code. A reconnecting peer replaces the stale
  // one (e.g. host app restarted) — close the previous socket cleanly.
  const existing = pair[role]
  if (existing && existing !== ws) {
    log(`[${maskCode(code)}] replacing existing ${role} connection`)
    try {
      existing.close(4000, 'Replaced by a newer connection')
    } catch (_) {}
  }
  pair[role] = ws

  const peer = pair[peerRole(role)]
  log(
    `[${maskCode(code)}] ${role} connected` +
      (peer ? ` (paired with ${peerRole(role)})` : ` (waiting for ${peerRole(role)})`)
  )

  // Tell the Host exactly which feature(s) justified this connection, once,
  // right after connect. Synthesized by the relay itself (not forwarded from
  // a peer) — Clients don't carry a machineId/entitlement, so this is
  // host-only.
  if (role === 'host') {
    try {
      ws.send(JSON.stringify({
        type: 'entitlement',
        features: { remote_access: ws.remoteAccessActive, mobile_data: ws.mobileDataActive }
      }))
    } catch (_) {}
  }

  // Forward raw frames to the peer, preserving text/binary type.
  ws.on('message', (data, isBinary) => {
    // Mobile Data QR Job Order Tracking: a 'track_response' from the Host is
    // consumed BY THIS RELAY (resolving a pending phone HTTP request held in
    // pendingTrackRequests) — it is never forwarded to a 'client' peer. This
    // is the one host->relay message type the relay actually parses and acts
    // on; every other host->relay message (WS 'response'/'event' payloads
    // for Remote Access) is untouched raw-frame forwarding, exactly as
    // before this feature.
    if (role === 'host' && !isBinary) {
      let parsed = null
      try {
        parsed = JSON.parse(data.toString())
      } catch (_) {
        parsed = null
      }
      if (parsed && parsed.type === 'track_response') {
        resolveTrackRequest(parsed.id, parsed.status, parsed.html)
        return
      }
      if (parsed && parsed.type === 'points_response') {
        // Sibling to track_response above — same "consumed by this relay,
        // never forwarded to a client peer" handling.
        resolvePointsRequest(parsed.id, parsed.status, parsed.html)
        return
      }
    }

    const current = pairings.get(code)
    const target = current ? current[peerRole(role)] : null
    if (target && target.readyState === target.OPEN) {
      target.send(data, { binary: isBinary })
    } else if (role === 'client') {
      try {
        ws.send(JSON.stringify({ type: 'relay-error', code: 'HOST_UNAVAILABLE' }))
      } catch (_) {}
    }
  })

  ws.on('close', () => {
    const current = pairings.get(code)
    if (current && current[role] === ws) {
      current[role] = null
    }
    log(`[${maskCode(code)}] ${role} disconnected`)
    cleanupPairing(code)
    // A Host disconnecting mid-flight means it can no longer answer any
    // 'track_request' already sent to it on this code — resolve those now
    // rather than making the waiting phone(s) sit out the full 8s timeout.
    if (role === 'host') {
      for (const [id, entry] of pendingTrackRequests) {
        if (entry.code === code) {
          resolveTrackRequest(id, 503, unreachablePageHtml())
        }
      }
      // Same cleanup, sibling map — a Host disconnecting mid-flight can't
      // answer any 'points_request' already sent to it either.
      for (const [id, entry] of pendingPointsRequests) {
        if (entry.code === code) {
          resolvePointsRequest(id, 503, unreachablePageHtml())
        }
      }
    }
  })

  ws.on('error', (err) => {
    log(`[${maskCode(code)}] ${role} socket error: ${err.message}`)
  })
})

// ---------------------------------------------------------------------------
// Heartbeat: drop dead connections without killing healthy idle ones.
// ---------------------------------------------------------------------------
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      log(`[${maskCode(ws.code)}] terminating dead ${ws.role} connection`)
      ws.terminate()
      continue
    }
    ws.isAlive = false
    try {
      ws.ping()
    } catch (_) {}
  }
}, HEARTBEAT_MS)

wss.on('close', () => clearInterval(heartbeat))

// Remote Monitoring Dashboard: 12-month rolling retention (finding #6),
// applied only to this relay's snapshot store -- the shop's local SQLite
// database is unaffected either way. Once daily is plenty for a bound
// that only matters over months; also runs once at startup so a
// long-running process doesn't wait a full day for its first prune.
const snapshotPruneTimer = setInterval(() => {
  try {
    const dropped = pruneOldSnapshots()
    if (dropped > 0) log(`[monitoring] pruned ${dropped} snapshot row(s) older than the retention window`)
  } catch (err) {
    log(`[monitoring] snapshot prune failed: ${err.message}`)
  }
}, SNAPSHOT_PRUNE_INTERVAL_MS)
snapshotPruneTimer.unref()
try {
  pruneOldSnapshots()
} catch (err) {
  log(`[monitoring] initial snapshot prune failed: ${err.message}`)
}

server.listen(PORT, HOST, () => {
  log(`Relay server listening on ${HOST}:${PORT} (heartbeat ${HEARTBEAT_MS}ms)`)
})

// Loopback-only admin API for managing the subscriber whitelist.
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 3001)
startAdminServer()
log(`Admin server listening on 127.0.0.1:${ADMIN_PORT}`)

function shutdown(signal) {
  log(`Received ${signal}, shutting down...`)
  clearInterval(heartbeat)
  clearInterval(snapshotPruneTimer)
  for (const ws of wss.clients) {
    try {
      ws.close(1001, 'Server shutting down')
    } catch (_) {}
  }
  // Staged uploads are in-memory only and were never going to survive a
  // process exit regardless — nothing external (DB, disk) is left in an
  // inconsistent state by discarding them here. This is just operator
  // visibility (matching the log line above) plus tidy timer cleanup, not
  // a correctness requirement: process.exit() below would reclaim this
  // memory and its pending setTimeout timers either way.
  if (stagedUploads.size > 0) {
    log(`Discarding ${stagedUploads.size} pending mobile-upload staged file(s) on shutdown`)
    for (const entry of stagedUploads.values()) {
      clearTimeout(entry.timer)
    }
    stagedUploads.clear()
  }
  server.close(() => process.exit(0))
  // Force-exit if connections refuse to drain.
  setTimeout(() => process.exit(0), 5000).unref()
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
