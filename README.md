# NXTech POS Pro — Remote Access Relay Server

A tiny, standalone WebSocket **pairing/relay** server for the optional Remote
Access add-on. It lets a shop PC ("**host**") and an owner's remote device
("**client**") exchange the POS app's normal IPC requests/responses over two
**outbound** WebSocket connections — no port forwarding, works behind NAT/CGNAT.

> This project is **independent** of the Electron POS app. It has its own
> `package.json` / `node_modules`, is excluded from the app's installer build,
> and is meant to be deployed separately on a small VPS.

## How it works

```
 Shop PC (host)                Relay (this server)              Owner device (client)
 ───────────────  outbound ws  ───────────────────  outbound ws  ──────────────────
  relayHostClient  ───────────►  /connect?code=X&     ◄───────────  relayClientConn
                                   role=host|client
                                 forwards raw frames
                                 host  <───────────►  client
```

- Both peers connect out to the relay using the **same pairing code**.
- The relay matches them by code and forwards raw frames bidirectionally.
- It is **in-memory only** — no database, no persistence.
- It **never inspects or stores** the relayed payloads.

### App-level message protocol

Most of these are forwarded opaquely — the relay does not parse them, it just
forwards every frame between the paired host and client — but for reference,
the app exchanges JSON messages of these types:

- `{ type: "request",  id, channel, payload }` — Client → Host: run an IPC channel.
- `{ type: "response", id, result | error }` — Host → Client: reply to a request, correlated by `id`.
- `{ type: "event",    name, payload }` — Host → Client: a forwarded main→renderer invalidation event (e.g. a sale was voided) so the Client's view refreshes live.
- `{ type: "entitlement", features: { remote_access, mobile_data } }` — **Relay → Host only**, sent once immediately after a successful connection. Unlike the three above, this one is *synthesized by the relay itself*, not forwarded from a peer — it reflects which feature(s) the subscription gate found active for this `machineId` at connect time.

Adding or changing the forwarded (request/response/event) message types
requires no change to the relay — it is transport only for those. The
`entitlement` message is the one exception: it originates at the relay, so
changing its shape or when it's sent does require a relay-side change.

### Security note

The pairing **code is a transport-layer rendezvous secret only — it is NOT a
login.** All authentication and authorization still happen on the host: the
host validates the POS session token inside every forwarded request before
touching the database. Anyone who guesses the code can only reach the host's
relay endpoint; they still cannot do anything without valid POS credentials.
Always run the relay behind `wss://` (TLS) in production so codes and payloads
are never sent in clear text.

## Endpoints

| Method | Path                                  | Description                                  |
| ------ | ------------------------------------- | -------------------------------------------- |
| `GET`  | `/health`                             | `{ "ok": true, "activePairings": N, "monitoringDbBytes": N }` |
| `WS`   | `/connect?code=<code>&role=host\|client` | Pairs by `code`, relays frames both ways. |

`activePairings` counts codes where **both** a host and a client are currently
connected.

### Remote Monitoring Dashboard (self-service, separate credential family)

A read-only web dashboard add-on, entirely separate from the pairing-code
relay above — its own SQLite database (`sync.js`/`dashboard.js`/`db.js`/
`licenseVerify.js`), never touches `subscribers.json`. Self-service: any
shop with a valid, Ed25519-signed, Premium-tier NXV2 license key can
register with no manual step here, unlike `remote_access`/`mobile_data`
above which are deliberately provisioned via the admin API.

| Method | Path                        | Auth                        | Description |
| ------ | --------------------------- | ---------------------------- | ----------- |
| `POST` | `/sync/register`            | none (verifies the license itself) | `{ license_key, machine_id, shop_name }` → verifies the NXV2 signature + Premium tier server-side, issues a per-shop `sync_token`. Registering the same `machine_id` again rotates the token (old one is revoked). |
| `POST` | `/sync/push`                | `Bearer <sync_token>`       | `{ rows: [{entity_type, entity_id, action, payload}, ...] }` → upserts each row into the snapshot store, keyed by `(shop_id, entity_type, entity_id)`. Also used for the full-snapshot push at registration/manual resync — same shape, just a bigger batch. |
| `POST` | `/sync/pairing-code`        | `Bearer <sync_token>`       | Issues a short-lived (~15 min), single-use, 10-character access code for claiming a dashboard session. Only one active code per shop — generating a new one invalidates any prior unused code. |
| `GET`  | `/sync/sessions`            | `Bearer <sync_token>`       | Lists this shop's linked dashboard sessions (for Settings' "Linked Browser Sessions" list). |
| `POST` | `/sync/sessions/revoke`     | `Bearer <sync_token>`       | `{ session_id }` → revokes one session immediately; its very next `/dashboard/*` request is rejected. |
| `POST` | `/dashboard/claim`          | none (the code IS the credential) | `{ code }` → single-use; sets an opaque session token as an `HttpOnly`/`Secure`/`SameSite=Strict` cookie (`dashboard_session`) scoped read-only to the code's shop. 5 wrong guesses invalidate whichever code(s) are currently active. Response body never contains the token. |
| `GET`  | `/dashboard/sales`<br>`/dashboard/job-orders`<br>`/dashboard/inventory`<br>`/dashboard/expenses`<br>`/dashboard/daily-closing` | `dashboard_session` cookie | Basic (unfiltered, most-recent-100) snapshot list for the session's own shop. Pagination/date-range filtering is a follow-up. |

`shop_id` is never accepted from a request body or query param on any of
these routes — every one derives it strictly from the authenticated
token/session record. Dashboard sessions are opaque random tokens stored
(hashed) in SQLite and re-validated live on every request, not JWTs — a
JWT can't be revoked before its own expiry without a separate blocklist,
which just re-adds the complexity a DB-backed session avoids.

**Why a cookie, not a JSON token**: this is a public website holding a
shop's real financial data. A token handed back in the response body would
force the frontend to keep it in JS-accessible storage (localStorage/
sessionStorage), which an XSS bug anywhere in the frontend could read and
exfiltrate. An `HttpOnly` cookie is invisible to page script entirely — the
browser attaches it automatically, so the frontend's only job on every
`/dashboard/*` call is `fetch(url, { credentials: 'include' })`, no manual
token handling at all. `SameSite=Strict` (not `Lax`) because nothing in
this flow needs the cookie sent on a cross-site top-level navigation — the
claim happens via a same-origin fetch from the link screen itself, never
an external redirect landing the browser on an already-authenticated page.

**IP trust behind Cloudflare**: `getClientIp()` (sync.js), used to key
every per-IP rate limit in this file, only trusts an `X-Forwarded-For`
header when the request reaching this relay came from `127.0.0.1`/`::1`
— i.e. from nginx, running on the same VPS, after its own `real_ip`
module has already derived the real visitor IP from Cloudflare's
`CF-Connecting-IP` header (see `dashboard-web/README.md`'s nginx config).
This relay's own listen `HOST` defaults to `0.0.0.0` because `/connect`
and `/sync/*` need to stay directly reachable by the desktop app, not
hidden behind Cloudflare — so this port is never exclusively reached via
nginx, and a direct request could otherwise set `X-Forwarded-For` to
anything to dodge rate limiting. Any non-loopback connection's real,
unspoofable TCP peer address is used instead, regardless of what headers
it sends.

**Caching**: every `/dashboard/*` response carries `Cache-Control:
no-store`, set unconditionally in `applyDashboardCors()` (before, not
after, the `DASHBOARD_ORIGIN` check — the real same-origin deployment
deliberately leaves that unset). With Cloudflare's edge in front, a
cached personalized response served to a different visitor would be an
actual cross-tenant data leak, not just staleness.

**Backup**: `monitoring.db` (see `MONITORING_DB_PATH` below) is not the
system of record — a shop's local SQLite database is — but losing it still
blanks every dashboard until a resync, so back it up like any other stateful
file on the VPS (e.g. a nightly `cp`/`sqlite3 .backup` into your existing
backup rotation). `GET /health`'s `monitoringDbBytes` gives basic disk-usage
visibility for that same rotation to watch.

## Configuration

Via environment variables:

| Variable       | Default     | Description                                                                                   |
| -------------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `PORT`         | `8787`      | TCP port the relay (WS pairing) listens on.                                                     |
| `HOST`         | `0.0.0.0`   | Relay bind address.                                                                              |
| `HEARTBEAT_MS` | `30000`     | Ping interval; dead sockets are dropped.                                                         |
| `ADMIN_PORT`   | `3001`      | Port the admin API (`admin.js`) listens on — always bound to `127.0.0.1` only, never public.     |
| `MONITORING_DB_PATH` | `./monitoring.db` | Path to the Remote Monitoring Dashboard's SQLite database.                                |
| `DASHBOARD_ORIGIN`   | *(none)*    | The dashboard website's origin, ONLY when it's served from a different origin than this relay (e.g. a staging frontend during development). Sent as `Access-Control-Allow-Origin` (with `Access-Control-Allow-Credentials: true`, required for the session cookie to work cross-origin) on every `/dashboard/*` response. The production deployment is same-origin (nginx serves the built SPA and reverse-proxies `/dashboard/*` to this same process), where this is moot — leave unset there. Never set to `*` (incompatible with credentialed requests regardless). |
| `DASHBOARD_COOKIE_SECURE` | `true` | Whether the `dashboard_session` cookie gets the `Secure` attribute. Leave at the default for any real deployment (always HTTPS). Set to `false` only for a local/plain-HTTP test harness — a browser silently refuses to store a `Secure` cookie over plain HTTP, which would otherwise make the whole flow look broken in dev. |
| `ADMIN_TOKEN`  | *(none)*    | Bearer token required on every admin API request except `/health`. **Effectively required**, not truly optional — if unset, the admin API logs a warning at startup and rejects every authenticated request with 401. |

## Run locally

```bash
cd relay-server
npm install
npm start
# -> Relay server listening on 0.0.0.0:8787 (heartbeat 30000ms)
```

Health check:

```bash
curl http://localhost:8787/health
# {"ok":true,"activePairings":0}
```

### Manual test with wscat

Install once: `npm i -g wscat`. Then open two terminals:

```bash
# Terminal 1 — host
wscat -c "ws://localhost:8787/connect?code=test123&role=host"

# Terminal 2 — client
wscat -c "ws://localhost:8787/connect?code=test123&role=client"
```

Type a message in either terminal and it appears in the other. `curl /health`
now reports `"activePairings":1`. Leave them idle past 30s to confirm the
heartbeat keeps the (healthy) connections alive. Close one terminal and the
other stays open, waiting for its peer to reconnect with the same code.

### Automated smoke test (app message protocol)

From the main app repo root there's a one-shot smoke test that pairs a
host + client and verifies request → response and event forwarding (the exact
protocol the app uses). It reads `RELAY_URL` from `.env`, or takes an override:

```bash
# Uses RELAY_URL from .env, generated TEST- code
npm run smoke:relay

# Explicit code and relay URL
node scripts/relay-smoke-test.js TEST-mycode wss://relay.nxtech.online
```

It prints PASS/FAIL per check and exits non-zero on failure — handy for
verifying a freshly deployed relay.

## Deployment (VPS, `wss://` via nginx + Let's Encrypt)

The app should connect to `wss://relay.example.com/connect` — TLS is terminated
by nginx, which reverse-proxies to the Node process on `127.0.0.1:8787`.

### 1. Install the app

```bash
sudo mkdir -p /opt/nxtech-relay
sudo cp -r relay-server/* /opt/nxtech-relay/
cd /opt/nxtech-relay
npm install --omit=dev
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nxtech-relay || true
sudo chown -R nxtech-relay:nxtech-relay /opt/nxtech-relay
```

### 2. systemd unit — `/etc/systemd/system/nxtech-relay.service`

```ini
[Unit]
Description=NXTech POS Pro Remote Access Relay
After=network.target

[Service]
Type=simple
User=nxtech-relay
WorkingDirectory=/opt/nxtech-relay
Environment=PORT=8787
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node /opt/nxtech-relay/server.js
Restart=always
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

> Note `HOST=127.0.0.1` — the Node process only listens on localhost; nginx is
> the only thing exposed publicly.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nxtech-relay
sudo systemctl status nxtech-relay
```

### 3. nginx reverse proxy — `/etc/nginx/sites-available/nxtech-relay`

```nginx
server {
    listen 80;
    server_name relay.example.com;
    # Allow certbot's HTTP-01 challenge, redirect everything else to HTTPS.
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;

        # WebSocket upgrade headers
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Keep idle WS connections open well past the 30s app heartbeat.
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### 4. TLS certificate (Let's Encrypt)

```bash
sudo ln -s /etc/nginx/sites-available/nxtech-relay /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d relay.example.com
# certbot edits the server block to add/verify the certificate and sets up auto-renewal
```

### 5. Point the POS app at the relay

Build the host app with the relay URL injected at build time:

```bash
# In the POS app's .env (build-time only)
RELAY_URL=wss://relay.example.com
```

Then verify end-to-end:

```bash
curl https://relay.example.com/health
```

## Files

- `server.js` — the relay (HTTP `/health` + WS `/connect`, heartbeat, pairing, per-feature subscription gate).
- `admin.js` — loopback-only HTTP admin API (`127.0.0.1:$ADMIN_PORT`) for granting/revoking a subscriber's `remote_access`/`mobile_data` entitlement, e.g. after manually confirming a GCash payment. See the endpoint table above.
- `subscribers.js` — the subscriber whitelist module: loads/saves `subscribers.json`, per-feature `isActive()`/`setActive()`, and a one-time shape migration for records still using the old single `active` boolean.
- `subscribers.json` — the on-disk whitelist (created on first write if missing). Not committed to version control on the VPS — treat it as live subscriber data, not a fixture.
- `db.js` — Remote Monitoring Dashboard's SQLite store (`monitoring.db`, gitignored): shops, sync tokens, snapshots, pairing codes, dashboard sessions. Also the 12-month retention prune and basic disk-usage reporting.
- `licenseVerify.js` — ports the app's NXV2 (Ed25519) license signature verification. Public key only; NXV2 keys only (legacy v1 keys are rejected — see the file header for why).
- `sync.js` — app-facing Remote Monitoring API: register/push/pairing-code/sessions. Every route derives `shop_id` from the authenticated `sync_token`, never from the request.
- `dashboard.js` — browser-facing Remote Monitoring API: claim a code, read a shop's snapshot data. Every route derives `shop_id` from the authenticated `dashboard_session` HttpOnly cookie, re-validated live on every request.
- `package.json` — depends on `ws` and `better-sqlite3`.
