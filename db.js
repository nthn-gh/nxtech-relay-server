/**
 * NXTech POS Pro relay — Remote Monitoring Dashboard storage.
 *
 * A SEPARATE SQLite database from subscribers.json (which stays exactly as
 * it is, for the existing Remote Access / Mobile Data manual-entitlement
 * model). remote_monitoring is self-service: any shop with a valid signed
 * Premium license can register itself via /sync/register, with no manual
 * whitelisting step on the operator's end -- so this file owns its own
 * `shops` table rather than reusing subscribers.json's shape at all.
 *
 * This is a monitoring VIEW, explicitly not the system of record -- the
 * shop's local SQLite database (on the shop PC) remains that. Losing this
 * file is recoverable via a full resync (pushFullSnapshot on the app side),
 * not catastrophic -- but it should still be backed up and its disk usage
 * watched (see README.md's Remote Monitoring section) since its loss still
 * blanks every dashboard until a resync happens.
 */
import Database from 'better-sqlite3'
import path from 'path'
import fs from 'fs'

const DB_PATH = process.env.MONITORING_DB_PATH || path.join(process.cwd(), 'monitoring.db')

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true })

export const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

db.exec(`
  -- One row per shop that has ever self-registered for Remote Monitoring.
  -- Keyed by machine_id (the license payload's own 'm' field) -- there is
  -- no license_id in the NXV2 key format to key by instead.
  CREATE TABLE IF NOT EXISTS shops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id TEXT UNIQUE NOT NULL,
    shop_name TEXT,
    tier TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT
  );

  -- App -> relay push auth. Token is a random high-entropy value; only its
  -- SHA-256 hash is ever stored, so a leaked DB file doesn't hand over live
  -- bearer tokens directly. Re-registering the same machine_id (e.g. the
  -- shop disabled then re-enabled the feature) revokes any prior tokens for
  -- that shop and issues a fresh one -- see sync.js's registerShop().
  CREATE TABLE IF NOT EXISTS sync_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER NOT NULL REFERENCES shops(id),
    token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_sync_tokens_hash ON sync_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_sync_tokens_shop ON sync_tokens(shop_id);

  -- The actual snapshot store. One row per (shop, entity), upserted on
  -- every /sync/push -- NOT an append-only log, so storage is bounded by
  -- live entity count per shop rather than growing with every historical
  -- change. Bounded further by the 12-month rolling retention default
  -- (see pruneOldSnapshots below), applied only here -- the shop's local
  -- DB is unaffected either way.
  CREATE TABLE IF NOT EXISTS snapshots (
    shop_id INTEGER NOT NULL REFERENCES shops(id),
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (shop_id, entity_type, entity_id)
  );
  CREATE INDEX IF NOT EXISTS idx_snapshots_shop_updated ON snapshots(shop_id, updated_at);
  CREATE INDEX IF NOT EXISTS idx_snapshots_shop_type ON snapshots(shop_id, entity_type, updated_at);

  -- Short-lived (~15 min), single-use, owner-generated codes that let a
  -- browser claim a dashboard session for one shop. Stored in PLAINTEXT --
  -- deliberately NOT hashed, unlike sync_tokens/dashboard_sessions above.
  -- A hash destroys any correlation between similar inputs (the avalanche
  -- effect), so a WRONG guess's hash can never be matched to the specific
  -- row it was aimed at -- the only options are "iterate every active code
  -- and penalize all of them" (the bug this replaced: one wrong guess
  -- against shop A degraded shop B's unrelated code too) or "don't
  -- attribute failures at all." Plaintext lets dashboard.js's
  -- recordFailedClaimAttempt() do a prefix lookup instead, correctly
  -- attributing a wrong guess to the ONE code it was actually aimed at (see
  -- that function). Acceptable given this table's narrow scope: read-only
  -- claim tickets, single-use, dead in 15 minutes, average pairing_codes
  -- row count in the single digits at any moment -- not a long-lived
  -- credential like the two token tables above.
  CREATE TABLE IF NOT EXISTS pairing_codes (
    code TEXT PRIMARY KEY,
    shop_id INTEGER NOT NULL REFERENCES shops(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    invalidated_at TEXT,
    used_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_pairing_codes_shop ON pairing_codes(shop_id);

  -- Opaque random session tokens (NOT JWTs -- see sync/dashboard design
  -- notes: a JWT can't be revoked before its own expiry without a separate
  -- blocklist, which just re-adds the complexity a plain DB-backed session
  -- avoids). Looked up and re-checked live on every /dashboard/* request.
  -- Revoke = set revoked_at; checked on every lookup, so a revoked
  -- session's very next request is rejected, not after a delay.
  -- session_id is a separate, non-secret random identifier (NOT derived
  -- from token_hash) used only for display/revoke purposes -- the Settings
  -- UI's session list and Revoke button reference sessions by this, never
  -- by any part of the actual bearer token or its hash.
  CREATE TABLE IF NOT EXISTS dashboard_sessions (
    token_hash TEXT PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    shop_id INTEGER NOT NULL REFERENCES shops(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_active_at TEXT NOT NULL,
    revoked_at TEXT,
    device_label TEXT,
    ip_address TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_shop ON dashboard_sessions(shop_id);
  CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_session_id ON dashboard_sessions(session_id);
`)

export function nowIso() {
  return new Date().toISOString()
}

// Basic disk-usage monitoring (finding #7) -- this file is not the system
// of record, but its loss still blanks every dashboard until a resync, so
// its size is worth surfacing even without a full alerting pipeline.
// Exposed via GET /health (see server.js) and the admin API.
export function getDbFileSizeBytes() {
  try {
    return fs.statSync(DB_PATH).size
  } catch (_) {
    return 0
  }
}

export function getMonitoringDbPath() {
  return DB_PATH
}

// 12 months, rolling -- the doc's default for outstanding decision #2.
// Older rows are dropped from the relay only; the shop's local SQLite
// database is completely unaffected either way (it stays the real,
// unbounded record). Bounds the actual growth concern (finding #6).
export const RETENTION_MS = 365 * 24 * 60 * 60 * 1000

export function pruneOldSnapshots(retentionMs = RETENTION_MS) {
  const cutoff = new Date(Date.now() - retentionMs).toISOString()
  const result = db.prepare('DELETE FROM snapshots WHERE updated_at < ?').run(cutoff)
  return result.changes
}
