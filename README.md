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

### App-level message protocol (forwarded opaquely)

The relay does not parse these — it just forwards every frame between the paired
host and client — but for reference, the app exchanges JSON messages of three
types:

- `{ type: "request",  id, channel, payload }` — Client → Host: run an IPC channel.
- `{ type: "response", id, result | error }` — Host → Client: reply to a request, correlated by `id`.
- `{ type: "event",    name, payload }` — Host → Client: a forwarded main→renderer invalidation event (e.g. a sale was voided) so the Client's view refreshes live.

Adding or changing these message types requires **no change to the relay** —
it is transport only.

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
| `GET`  | `/health`                             | `{ "ok": true, "activePairings": N }`        |
| `WS`   | `/connect?code=<code>&role=host\|client` | Pairs by `code`, relays frames both ways. |

`activePairings` counts codes where **both** a host and a client are currently
connected.

## Configuration

Via environment variables:

| Variable       | Default     | Description                                                                                   |
| -------------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `PORT`         | `8787`      | TCP port the relay (WS pairing) listens on.                                                     |
| `HOST`         | `0.0.0.0`   | Relay bind address.                                                                              |
| `HEARTBEAT_MS` | `30000`     | Ping interval; dead sockets are dropped.                                                         |
| `ADMIN_PORT`   | `3001`      | Port the admin API (`admin.js`) listens on — always bound to `127.0.0.1` only, never public.     |
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
- `package.json` — depends only on `ws`.
