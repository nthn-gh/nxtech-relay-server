// Ad-hoc smoke test for the relay. Spawns the server, pairs two clients,
// verifies bidirectional forwarding, /health counting, and that the heartbeat
// keeps idle-but-alive connections open across several ping cycles.
import { spawn } from 'child_process'
import { WebSocket } from 'ws'

const PORT = 8799
const CODE = 'smoke-test-code'
const wait = (ms) => new Promise((r) => setTimeout(r, ms))
const results = []
const check = (name, ok) => {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'} - ${name}`)
}

const srv = spawn('node', ['server.js'], {
  cwd: process.cwd(),
  env: { ...process.env, PORT: String(PORT), HEARTBEAT_MS: '500' },
  stdio: ['ignore', 'inherit', 'inherit']
})

async function getHealth() {
  const res = await fetch(`http://localhost:${PORT}/health`)
  return res.json()
}

const open = (role) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${PORT}/connect?code=${CODE}&role=${role}`)
    ws.on('open', () => resolve(ws))
    ws.on('error', reject)
  })

const nextMsg = (ws) =>
  new Promise((resolve) => ws.once('message', (d) => resolve(d.toString())))

try {
  await wait(700) // let server boot

  const h0 = await getHealth()
  check('health ok=true, 0 active pairings at start', h0.ok === true && h0.activePairings === 0)

  const host = await open('host')
  const client = await open('client')
  await wait(200)

  const h1 = await getHealth()
  check('activePairings = 1 once both connected', h1.activePairings === 1)

  // client -> host
  const hostGot = nextMsg(host)
  client.send('hello-from-client')
  check('client -> host forwarded', (await hostGot) === 'hello-from-client')

  // host -> client
  const clientGot = nextMsg(client)
  host.send('hello-from-host')
  check('host -> client forwarded', (await clientGot) === 'hello-from-host')

  // Heartbeat: stay idle across several 500ms ping cycles (~2.5s).
  let hostClosed = false
  let clientClosed = false
  host.on('close', () => (hostClosed = true))
  client.on('close', () => (clientClosed = true))
  await wait(2500)
  check('heartbeat did NOT drop idle-alive connections', !hostClosed && !clientClosed)
  check('connections still OPEN after heartbeat cycles', host.readyState === 1 && client.readyState === 1)

  // Forwarding still works after heartbeats
  const afterHb = nextMsg(host)
  client.send('still-alive')
  check('forwarding works after heartbeat cycles', (await afterHb) === 'still-alive')

  // Disconnect client; host stays, pairing drops to 0 active
  client.close()
  await wait(300)
  const h2 = await getHealth()
  check('activePairings back to 0 after client leaves', h2.activePairings === 0)
  check('host connection survives peer disconnect', host.readyState === 1)

  host.close()
  await wait(200)
} catch (err) {
  check(`unexpected error: ${err.message}`, false)
} finally {
  srv.kill()
  const failed = results.filter((r) => !r.ok)
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
  process.exit(failed.length ? 1 : 0)
}
