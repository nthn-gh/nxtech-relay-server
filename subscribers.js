/**
 * NXTech POS Pro — Remote Access subscriber whitelist
 *
 * A tiny file-backed allow-list of host Machine IDs, with independent
 * per-feature entitlement (currently: remote_access, mobile_data). This is
 * the subscription kill-switch: a shop whose monthly fee lapses for a given
 * feature gets that feature's flag set to false (or the whole record
 * removed) here and can no longer open a relay connection that requires it.
 *
 * The relay itself stays stateless — this module only gates the upgrade. The
 * on-disk format is { "subscribers": [ ... ] }; each entry looks like:
 *   { machineId, label, features: { remote_access, mobile_data }, notes, addedAt }
 *
 * Everything here is intentionally synchronous and crash-proof: the relay
 * must never fall over because the whitelist file is missing or malformed.
 */

import fs from 'fs'
import path from 'path'

const subscribersFile = path.join(process.cwd(), 'subscribers.json')

// Canonical feature list. Adding a third feature later means adding one
// entry here — migrateEntry() backfills it as `false` on every existing
// record automatically, no separate migration pass needed.
export const KNOWN_FEATURES = ['remote_access', 'mobile_data']

function normalizeFeatures(features) {
  const result = {}
  for (const feature of KNOWN_FEATURES) {
    result[feature] = !!(features && features[feature] === true)
  }
  return result
}

// Converts one entry to the current { features: {...} } shape, whatever its
// starting shape was. Returns { entry, changed } — changed is true if the
// returned entry differs from the input (old `active` shape, or a new-shape
// entry missing a feature key added since it was last written).
function migrateEntry(entry) {
  if (entry && entry.features && typeof entry.features === 'object' && !Array.isArray(entry.features)) {
    let changed = false
    const features = {}
    for (const feature of KNOWN_FEATURES) {
      if (typeof entry.features[feature] === 'boolean') {
        features[feature] = entry.features[feature]
      } else {
        features[feature] = false
        changed = true
      }
    }
    return { entry: changed ? { ...entry, features } : entry, changed }
  }

  // Old shape: { active: bool, ... } (or no active/features at all). Preserve
  // the existing Remote Access status exactly; mobile_data defaults to false
  // for everyone — no one is grandfathered into a feature they never paid for.
  const { active, ...rest } = entry || {}
  return {
    entry: {
      ...rest,
      features: {
        remote_access: active === true,
        mobile_data: false
      }
    },
    changed: true
  }
}

// One-time shape migration over the whole list. Returns { list, changed }.
function migrateShape(list) {
  let changed = false
  const migrated = list.map((raw) => {
    const { entry, changed: entryChanged } = migrateEntry(raw)
    if (entryChanged) changed = true
    return entry
  })
  return { list: migrated, changed }
}

// Reads subscribers.json and returns the entry array. Tolerates a missing or
// malformed file (and both the wrapped `{ subscribers: [...] }` and bare-array
// shapes) — never throws. Runs the shape migration on every read; if any
// entry needed migrating, persists the migrated shape back immediately, so
// this is a one-time upgrade on first read after deploy, not a per-read
// conversion — every subsequent read finds the file already in the new
// shape and migrateShape() is a no-op.
export function loadSubscribers() {
  try {
    const raw = fs.readFileSync(subscribersFile, 'utf8')
    const parsed = JSON.parse(raw)
    let list
    if (Array.isArray(parsed)) list = parsed
    else if (parsed && Array.isArray(parsed.subscribers)) list = parsed.subscribers
    else list = []

    const { list: migrated, changed } = migrateShape(list)
    if (changed) {
      saveSubscribers(migrated)
    }
    return migrated
  } catch (_) {
    return []
  }
}

// Writes the array back to subscribers.json, pretty-printed, synchronously.
// Always persists the documented { subscribers: [...] } wrapper shape.
//
// Crash-safe: writes to a temp file in the same directory, then
// fs.renameSync() over the real file. rename() is atomic on the same
// filesystem, so a crash mid-write leaves either the old complete file or
// the new complete file — never a truncated/corrupted one.
export function saveSubscribers(list) {
  const data = JSON.stringify({ subscribers: Array.isArray(list) ? list : [] }, null, 2)
  const tempPath = `${subscribersFile}.tmp`
  fs.writeFileSync(tempPath, data + '\n')
  fs.renameSync(tempPath, subscribersFile)
}

// True only when a matching entry exists AND has that specific feature
// entitled. Any other case (not found, feature not entitled, blank id,
// unknown feature name) is false — this is a fail-closed check.
export function isActive(machineId, feature) {
  if (!machineId) return false
  if (!KNOWN_FEATURES.includes(feature)) return false
  const entry = loadSubscribers().find((s) => s.machineId === machineId)
  return !!(entry && entry.features && entry.features[feature] === true)
}

// Upsert by machineId. New entries get an addedAt ISO timestamp; existing
// entries keep theirs. `features` is normalized to a full
// { remote_access, mobile_data } object — any omitted or non-boolean key
// defaults to false. Saves and returns the resulting entry.
export function addOrUpdate({ machineId, label, features, notes }) {
  const list = loadSubscribers()
  const existing = list.find((s) => s.machineId === machineId)
  const normalizedFeatures = normalizeFeatures(features)
  if (existing) {
    existing.label = label
    existing.features = normalizedFeatures
    existing.notes = notes
  } else {
    list.push({
      machineId,
      label,
      features: normalizedFeatures,
      notes,
      addedAt: new Date().toISOString(),
    })
  }
  saveSubscribers(list)
  return list.find((s) => s.machineId === machineId)
}

// Flip ONE feature flag for one entry, leaving every other feature untouched.
// Returns true if found and the feature name is valid, false otherwise
// (not found, or unknown feature — the caller is expected to validate the
// feature name itself and return a distinct 400 vs. 404 to its own caller).
export function setActive(machineId, feature, value) {
  if (!KNOWN_FEATURES.includes(feature)) return false
  const list = loadSubscribers()
  const entry = list.find((s) => s.machineId === machineId)
  if (!entry) return false
  entry.features = normalizeFeatures(entry.features)
  entry.features[feature] = value === true
  saveSubscribers(list)
  return true
}

// Remove an entry by machineId. Returns true if something was removed.
export function remove(machineId) {
  const list = loadSubscribers()
  const next = list.filter((s) => s.machineId !== machineId)
  if (next.length === list.length) return false
  saveSubscribers(next)
  return true
}

// Returns the full subscriber array.
export function listAll() {
  return loadSubscribers()
}
