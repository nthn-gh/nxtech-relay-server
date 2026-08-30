/**
 * Tiny in-memory, fixed-window rate limiter — no new dependency, matching
 * this relay's existing "in-memory only, nothing persisted" posture.
 *
 * Fixed window (not sliding) deliberately: at this relay's actual scale
 * (~5 subscribers, tens of legitimate lookups/day total), the boundary
 * imprecision a fixed window allows (up to ~2x the limit across a window
 * edge, in the worst case) isn't worth the extra bookkeeping a sliding
 * window or token bucket would add — this exists to blunt casual phone
 * enumeration and fat-fingered retries, not to defend a high-value target.
 *
 * Keyed however the caller likes (this relay's own callers use `${ip}:${code}`
 * so one IP hammering one shop's code is limited independently of that same
 * IP trying a different shop's code, and independently of other IPs trying
 * the same shop's code).
 */

// key -> { count, windowStart }
const buckets = new Map()

/**
 * Returns true if the call is allowed (and counts it), false if the caller
 * has exceeded `limit` calls within the current `windowMs` window for `key`.
 */
export function checkAndConsume(key, { limit, windowMs }) {
  const now = Date.now()
  const entry = buckets.get(key)

  if (!entry || now - entry.windowStart >= windowMs) {
    buckets.set(key, { count: 1, windowStart: now })
    return true
  }

  if (entry.count >= limit) {
    return false
  }

  entry.count += 1
  return true
}

// Lazy sweep of expired buckets so this Map never grows unbounded across a
// long-running relay process — called opportunistically, not on a timer, to
// avoid one more interval to manage in a small process. maxWindowMs should
// be the largest windowMs any caller uses, so nothing gets swept early.
export function sweepExpired(maxWindowMs) {
  const now = Date.now()
  for (const [key, entry] of buckets) {
    if (now - entry.windowStart >= maxWindowMs) {
      buckets.delete(key)
    }
  }
}

// Test/introspection only.
export function _size() {
  return buckets.size
}

export function _clear() {
  buckets.clear()
}
