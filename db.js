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
  -- Keyed by a hash of the license_key (each branch necessarily has its own
  -- separate license), NOT by machine_id. machine_id is stored for display
  -- only -- see the 2026-08 audit follow-up: keying by machine_id let two
  -- genuinely different branches silently merge into one shop record
  -- whenever their machine_id happened to collide (e.g. branch 2 set up by
  -- disk-cloning branch 1's PC image, which copies Windows' MachineGuid
  -- byte-for-byte). license_key_hash has no such collision path -- two
  -- branches always have two different licenses.
  CREATE TABLE IF NOT EXISTS shops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key_hash TEXT UNIQUE,
    machine_id TEXT NOT NULL,
    shop_name TEXT,
    tier TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_shops_machine_id ON shops(machine_id);

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

  -- AI-assisted resume generation (Premium feature, resume.js). One row
  -- per successful OpenAI call -- this table IS the durable per-shop daily
  -- quota (resume.js queries COUNT(*) WHERE shop_id = ? AND created_at >=
  -- <start of current UTC day>), deliberately not the in-memory
  -- rateLimiter.js used elsewhere in this relay, since a process restart
  -- must not silently reopen a shop's quota for a feature that costs real
  -- money per call. input_chars/output_chars are character counts only
  -- (not the actual resume text) -- usage/cost visibility without storing
  -- customer PII (names, contact info, work history) in this database.
  CREATE TABLE IF NOT EXISTS resume_generations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER NOT NULL REFERENCES shops(id),
    created_at TEXT NOT NULL,
    input_chars INTEGER,
    output_chars INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_resume_generations_shop_created ON resume_generations(shop_id, created_at);
`)

// ---------------------------------------------------------------------------
// Migration: shops keyed by license_key_hash, not machine_id.
//
// See the audit follow-up dated 2026-08-31 for the full incident writeup.
// A database created before this fix has `machine_id TEXT UNIQUE NOT NULL`
// and no `license_key_hash` column -- two genuinely different branches
// could silently merge into one shop record whenever their machine_id
// happened to collide (e.g. branch 2 set up by disk-cloning branch 1's PC
// image, which copies Windows' MachineGuid byte-for-byte). SQLite has no
// ALTER TABLE DROP CONSTRAINT, so removing that unique constraint needs a
// full table rebuild. Idempotent -- a no-op once shops.license_key_hash
// already exists (true immediately for a fresh install, since the
// CREATE TABLE IF NOT EXISTS above already has the new shape).
// ---------------------------------------------------------------------------
function migrateShopsTableToLicenseKeyHash() {
  const columns = db.prepare('PRAGMA table_info(shops)').all()
  if (columns.some((c) => c.name === 'license_key_hash')) return // already migrated

  console.log('[db] migrating shops table: unique key machine_id -> license_key_hash')

  // PRAGMA foreign_keys can't be toggled inside a transaction, so it's set
  // outside the transaction() call, not inside it. Every child table
  // (sync_tokens, pairing_codes, dashboard_sessions, snapshots) keeps
  // referencing shops(id) unchanged -- ids are preserved by the copy below,
  // so no child-table rows need touching.
  db.pragma('foreign_keys = OFF')
  const migrate = db.transaction(() => {
    db.exec(`
      CREATE TABLE shops_migrated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key_hash TEXT UNIQUE,
        machine_id TEXT NOT NULL,
        shop_name TEXT,
        tier TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT
      );
    `)
    // license_key_hash starts NULL for every pre-existing row -- the raw
    // license_key was never stored on this table, so it can't be backfilled
    // here. Each shop's own app fills it in automatically the next time it
    // calls /sync/register (see handleSyncRegister's fallback lookup in
    // sync.js), which happens on its next ordinary connectivity -- no
    // customer action required.
    db.exec(`
      INSERT INTO shops_migrated (id, machine_id, shop_name, tier, created_at, last_seen_at)
      SELECT id, machine_id, shop_name, tier, created_at, last_seen_at FROM shops;
    `)
    db.exec('DROP TABLE shops;')
    db.exec('ALTER TABLE shops_migrated RENAME TO shops;')
    db.exec('CREATE INDEX IF NOT EXISTS idx_shops_machine_id ON shops(machine_id);')
  })
  migrate()
  db.pragma('foreign_keys = ON')

  console.log('[db] shops table migration complete')
}

migrateShopsTableToLicenseKeyHash()

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
