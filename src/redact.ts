/**
 * Conservative, deep redaction of secret-bearing fields in Keycloak representations before they reach the
 * model. Keycloak keeps secrets in more places than the obvious `secret` property: `registrationAccessToken`,
 * the previous secret during rotation (`attributes["client.secret.rotated"]`), SAML signing/encryption private
 * keys (`attributes["saml.signing.private.key"]`), mapper/component configs (`clientSecret`, `bindCredential`),
 * user `credentials`, and so on. Matching is on key names, so it is a safety net and not a guarantee: a secret
 * stored under an innocuous key name is not detected (see SECURITY.md).
 *
 * Two tiers:
 *  - HARD keys (name ends in secret / password / credential(s) / private key / api key): the value is always
 *    replaced, whatever it holds or however deep it is.
 *  - SOFT keys (name merely contains secret / token / credential / password / key-ish words, such as
 *    `access.token.lifespan` or `client.secret.creation.time`): replaced unless the key ends in a plainly
 *    non-secret word (time, period, lifespan, timeout, expiration, alg, algorithm, type, method, enabled) or the
 *    value cannot hold a secret (boolean, number, null, empty, "true"/"false"). That keeps timestamps, lifespans,
 *    algorithms and feature flags readable while a token or key string under such a name is still hidden.
 * Independently of the key, a string containing a PEM private key block is replaced.
 */

export const REDACTED = "[REDACTED]";

const HARD_KEY =
  /(secret|passw(or)?d|private[\s._-]?key|api[\s._-]?key|credentials?|registration[\s._-]?access[\s._-]?token|secret[\s._-]?rotated)$/i;
const SOFT_KEY = /secret|token|credential|passw(or)?d|private[\s._-]?key|api[\s._-]?key|authorization|bearer|cookie/i;
/** Keys that match the patterns by wording only and hold plain configuration. */
const SAFE_KEYS = new Set(["passwordpolicy", "clientauthenticatortype"]);
/** Soft-key names ending in one of these hold configuration (a timestamp, a duration, an algorithm, a flag). */
const BENIGN_SUFFIX = /(time|period|lifespan|timeout|expiration|expiry|alg|algorithm|type|method|enabled)$/i;
const PEM_PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const MAX_DEPTH = 12;

/** True for values that cannot be a credential: booleans, numbers, null, empty, "true"/"false". */
function inert(v: unknown): boolean {
  if (v === null || v === undefined || typeof v === "boolean" || typeof v === "number") return true;
  if (typeof v !== "string") return false;
  const t = v.trim();
  return t === "" || /^(true|false|null)$/i.test(t);
}

function walk(value: unknown, softKey: boolean, depth: number): unknown {
  if (depth > MAX_DEPTH) return REDACTED; // too deep to inspect safely: drop rather than pass through
  if (typeof value === "string") {
    if (PEM_PRIVATE_KEY.test(value)) return REDACTED;
    return softKey && !inert(value) ? REDACTED : value;
  }
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => walk(v, softKey, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === undefined) continue;
    if (SAFE_KEYS.has(k.toLowerCase())) {
      out[k] = walk(v, false, depth + 1);
    } else if (HARD_KEY.test(k)) {
      out[k] = REDACTED;
    } else {
      out[k] = walk(v, softKey || (SOFT_KEY.test(k) && !BENIGN_SUFFIX.test(k)), depth + 1);
    }
  }
  return out;
}

/** Deep copy of `value` with secret-bearing fields replaced by "[REDACTED]". */
export function redactSecrets<T>(value: T): T {
  return walk(value, false, 0) as T;
}
