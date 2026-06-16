import http from 'http'
import { WebSocketServer } from 'ws'
import { isActive } from './subscribers.js'
import { startAdminServer } from './admin.js'

const PORT = Number(process.env.PORT || process.env.RELAY_PORT || 8787)
const HOST = process.env.HOST || '0.0.0.0'
const HEARTBEAT_MS = Number(process.env.HEARTBEAT_MS || 30000)
const MAX_CODE_LENGTH = 128
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 3001)

const pairings = new Map()

function log(...args) {
  console.log(new Date().toISOString(), ...args)
}

function maskCode(code) {
  return `${String(code || '').slice(0, 4)}...`
}

function activePairingCount() {
  let n = 0
  for (const pair of pairings.values()) {
    if (pair.host && pair.client) n++
  }
  return n
}

function peerRole(role) {
  return role === 'host' ? 'client' : 'host'
}

function cleanupPairing(code) {
  const pair = pairings.get(code)
  if (pair && !pair.host && !pair.client) {
    pairings.delete(code)
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/health' || req.url.startsWith('/health?'))) {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, activePairings: activePairingCount() }))
    return
  }
  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ ok: false, error: 'Not found' }))
})

const wss = new WebSocketServer({ noServer: true })

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

  if (role === 'host' && !isActive(machineId)) {
    log(`[relay] BLOCKED host machineId=${machineId} — subscription inactive`)
    const payload = JSON.stringify({
      code: 'SUBSCRIPTION_INACTIVE',
      message: 'Remote access subscription is inactive. Contact NXTech support.',
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
    wss.emit('connection', ws, req)
  })
})

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

  ws.on('message', (data, isBinary) => {
    const current = pairings.get(code)
    const target = current ? current[peerRole(role)] : null
    if (target && target.readyState === target.OPEN) {
      target.send(data, { binary: isBinary })
    }
  })

  ws.on('close', () => {
    const current = pairings.get(code)
    if (current && current[role] === ws) {
      current[role] = null
    }
    log(`[${maskCode(code)}] ${role} disconnected`)
    cleanupPairing(code)
  })

  ws.on('error', (err) => {
    log(`[${maskCode(code)}] ${role} socket error: ${err.message}`)
  })
})

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

server.listen(PORT, HOST, () => {
  log(`Relay server listening on ${HOST}:${PORT} (heartbeat ${HEARTBEAT_MS}ms)`)
})

startAdminServer()
log(`Admin server listening on 127.0.0.1:${ADMIN_PORT}`)

function shutdown(signal) {
  log(`Received ${signal}, shutting down...`)
  clearInterval(heartbeat)
  for (const ws of wss.clients) {
    try {
      ws.close(1001, 'Server shutting down')
    } catch (_) {}
  }
  server.close(() => process.exit(0))
  setTimeout(() => process.exit(0), 5000).unref()
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
