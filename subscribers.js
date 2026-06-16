/**
 * NXTech POS Pro — Remote Access subscriber whitelist
 *
 * A tiny file-backed allow-list of host Machine IDs that are permitted to
 * open a relay connection. This is the subscription kill-switch: a shop whose
 * monthly fee lapses gets active=false (or removed) here and can no longer
 * pair as a host.
 *
 * The relay itself stays stateless — this module only gates the upgrade. The
 * on-disk format is { "subscribers": [ ... ] }; each entry looks like:
 *   { machineId, label, active, notes, addedAt }
 *
 * Everything here is intentionally synchronous and crash-proof: the relay must
 * never fall over because the whitelist file is missing or malformed.
 */

import fs from 'fs'
import path from 'path'

const subscribersFile = path.join(process.cwd(), 'subscribers.json')

// Reads subscribers.json and returns the entry array. Tolerates a missing or
// malformed file (and both the wrapped `{ subscribers: [...] }` and bare-array
// shapes) — never throws.
export function loadSubscribers() {
  try {
    const raw = fs.readFileSync(subscribersFile, 'utf8')
    const parsed = JSON.parse(raw)
    if (Array.isArray(parsed)) return parsed
    if (parsed && Array.isArray(parsed.subscribers)) return parsed.subscribers
    return []
  } catch (_) {
    return []
  }
}

// Writes the array back to subscribers.json, pretty-printed, synchronously.
// Always persists the documented { subscribers: [...] } wrapper shape.
export function saveSubscribers(list) {
  const data = JSON.stringify({ subscribers: Array.isArray(list) ? list : [] }, null, 2)
  fs.writeFileSync(subscribersFile, data + '\n')
}

// True only when a matching entry exists AND is active. Any other case
// (not found, inactive, blank id) is false.
export function isActive(machineId) {
  if (!machineId) return false
  const entry = loadSubscribers().find((s) => s.machineId === machineId)
  return !!(entry && entry.active === true)
}

// Upsert by machineId. New entries get an addedAt ISO timestamp; existing
// entries keep theirs. Saves and returns the resulting entry.
export function addOrUpdate({ machineId, label, active, notes }) {
  const list = loadSubscribers()
  const existing = list.find((s) => s.machineId === machineId)
  if (existing) {
    existing.label = label
    existing.active = active
    existing.notes = notes
  } else {
    list.push({
      machineId,
      label,
      active,
      notes,
      addedAt: new Date().toISOString(),
    })
  }
  saveSubscribers(list)
  return list.find((s) => s.machineId === machineId)
}

// Flip the active flag for one entry. Returns true if found, false otherwise.
export function setActive(machineId, active) {
  const list = loadSubscribers()
  const entry = list.find((s) => s.machineId === machineId)
  if (!entry) return false
  entry.active = active
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
