/**
 * NXTech POS Pro relay — NXV2 license signature verification.
 *
 * Ports the verification half of the app's own validateLicenseV2()
 * (src/main/services/license.service.js) -- same public key, same
 * Ed25519 verify call, same payload shape. Only the PUBLIC key lives
 * here; it can verify a signature but never produce one, so this file
 * gives an attacker nothing usable to forge a key with.
 *
 * Deliberately does NOT support the legacy v1 (symmetric HMAC) scheme.
 * Verifying a v1 key server-side would require putting the shared
 * LICENSE_SECRET on this relay -- a real security downgrade, since a
 * compromised relay could then forge licenses for anyone, not just read
 * them. Remote Monitoring registration requires an NXV2-prefixed key;
 * a shop still on a legacy key needs to re-activate with a v2 key first
 * (already the normal path for new activations since the v1/v2 bridge
 * landed -- see keygen-tool/README.md in the main app repo).
 *
 * machine_id trust note: the app's own getMachineId() reads the Windows
 * registry, which this relay (running on Linux) cannot do. So machine_id
 * here is CLIENT-ASSERTED (whatever /sync/register's request body claims)
 * but cryptographically BOUND to the license: the signed payload's own
 * `m` field must match the asserted machine_id, or verification fails.
 * A forged/mismatched machine_id still can't produce a valid signature
 * for it -- this doesn't weaken the guarantee, it just sources "which
 * machine is this" from the request instead of a local OS query, the same
 * way the shop's own machine already implicitly asserts it to itself.
 */
import { createPublicKey, verify as cryptoVerify } from 'crypto'

const LICENSE_V2_PREFIX = 'NXV2-'
const LICENSE_V2_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAnIcAQPcfoQLrAnM4YaFD8uLXCoHIg/6JBtOZ6I6/hpU=
-----END PUBLIC KEY-----`

function base64urlDecode(value) {
  const padded = String(value || '').replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(padded, 'base64')
}

function normalizeMachineId(machineId) {
  return String(machineId || '').trim().toUpperCase()
}

/**
 * Verifies an NXV2 license key against an asserted machine_id.
 *
 * Returns one of:
 *   { valid: true, tier, machineId, issueDate }
 *   { valid: false, reason: 'not_nxv2' | 'malformed' | 'bad_signature' | 'bad_version' | 'machine_mismatch' | 'error' }
 *
 * Never throws -- any malformed input (bad base64, truncated payload,
 * non-JSON payload) is caught and reported as a normal invalid result,
 * matching validateLicenseV2()'s own fail-closed posture.
 */
export function verifyNxv2License(licenseKey, assertedMachineId) {
  const cleanInput = String(licenseKey || '').trim()
  if (!cleanInput.toUpperCase().startsWith(LICENSE_V2_PREFIX)) {
    return { valid: false, reason: 'not_nxv2' }
  }

  try {
    const body = cleanInput.slice(LICENSE_V2_PREFIX.length)
    const dotIndex = body.indexOf('.')
    if (dotIndex === -1) return { valid: false, reason: 'malformed' }

    const payloadBytes = base64urlDecode(body.slice(0, dotIndex))
    const signature = base64urlDecode(body.slice(dotIndex + 1))

    const publicKey = createPublicKey(LICENSE_V2_PUBLIC_KEY_PEM)
    if (!cryptoVerify(null, payloadBytes, publicKey, signature)) {
      return { valid: false, reason: 'bad_signature' }
    }

    const payload = JSON.parse(payloadBytes.toString('utf8'))
    if (payload.v !== 2) return { valid: false, reason: 'bad_version' }

    if (normalizeMachineId(payload.m) !== normalizeMachineId(assertedMachineId)) {
      return { valid: false, reason: 'machine_mismatch' }
    }

    return {
      valid: true,
      tier: String(payload.t || '').trim().toLowerCase(),
      machineId: normalizeMachineId(payload.m),
      issueDate: payload.i || null
    }
  } catch (_) {
    return { valid: false, reason: 'error' }
  }
}
