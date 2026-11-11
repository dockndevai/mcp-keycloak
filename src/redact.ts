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
 *
 * Word-aware additions (the key is split into words at separators and camelCase boundaries, so `recoveryCodes`,
 * `recovery.codes` and `recovery-authn-codes` are the same name, and `otpPolicyType` is not `otp`):
 *  - recovery / backup / scratch codes (`recovery.codes`, `recoveryCodes`, `backupCodes`, ...) are HARD when the key
 *    ends in them and SOFT when it merely contains them;
 *  - a key whose LAST word is `otp` / `totp` / `hotp` (or whose last two words are one of those plus value / code /
 *    seed / key, e.g. `totpValue`) is SOFT, so a TOTP credential blob is hidden while the user flag
 *    `totp: false` and settings like `otpPolicyType` stay readable;
 *  - `initialAccessToken` is HARD like `registrationAccessToken`.
 *
 * URL-valued fields are the exception to the SOFT rule. `authorizationUrl`, `tokenUrl`, `userInfoUrl`,
 * `token_endpoint`, `jwks_uri` ... contain "authorization"/"token" but hold a public endpoint. A SOFT string value is
 * kept readable when (and only when) the key's last word is url / uri / endpoint AND the value is an http(s)/ldap(s)
 * URL without userinfo (`user:pw@host`), without a secret-named query or fragment parameter (`client_secret=`,
 * `access_token=`, `code=`, `api_key=` ...) and without JWT- or PEM-shaped content. Anything else under such a key is
 * still replaced; and a URL that embeds a credential is replaced under ANY url/uri/endpoint-named key, soft or not
 * (`jwksUrl: "https://host/jwks?api_key=..."`). HARD keys are never exempt. A secret placed in the URL PATH (for example a webhook URL) is not
 * detected: that is the same documented limit as a secret under an innocuous key name.
 *
 * `redactErrorBody` applies the same idea to the free text of a Keycloak error response.
 */

export const REDACTED = "[REDACTED]";

const HARD_KEY =
  /(secret|passw(or)?d|private[\s._-]?key|api[\s._-]?key|credentials?|(registration|initial)[\s._-]?access[\s._-]?token|secret[\s._-]?rotated)$/i;
const SOFT_KEY = /secret|token|credential|passw(or)?d|private[\s._-]?key|api[\s._-]?key|authorization|bearer|cookie/i;
/** Keys that match the patterns by wording only and hold plain configuration. */
const SAFE_KEYS = new Set(["passwordpolicy", "clientauthenticatortype"]);
/** `webAuthnPolicy*` / `webAuthnPolicyPasswordless*` realm settings are WebAuthn configuration; "Passwordless" is not a password. */
const SAFE_PREFIX = /^webauthnpolicy/i;
/** Soft-key names ending in one of these hold configuration (a timestamp, a duration, an algorithm, a flag). */
const BENIGN_SUFFIX = /(time|period|lifespan|timeout|expiration|expiry|alg|algorithm|type|types|method|enabled|flow|mode)$/i;

/** `userInfoURL` -> ["user", "info", "url"]; `recovery-authn-codes` -> ["recovery", "authn", "codes"]. */
function words(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

const RECOVERY_WORD = new Set(["recovery", "backup", "scratch"]);
/** recovery / backup / scratch (authn) code(s): returns "end" if the key ends in it, "inside" if it only contains it. */
function recoveryCodes(w: string[]): "end" | "inside" | undefined {
  let found: "end" | "inside" | undefined;
  for (let i = 0; i < w.length; i++) {
    if (!RECOVERY_WORD.has(w[i]!)) continue;
    let j = i + 1;
    if (w[j] === "authn") j++;
    if (w[j] === "code" || w[j] === "codes") return j === w.length - 1 ? "end" : (found = "inside");
  }
  return found;
}

const OTP_WORD = new Set(["otp", "totp", "hotp"]);
const OTP_VALUE_WORD = new Set(["value", "code", "seed", "key"]);
/** `totp`, `otp`, `userTotp` (last word) or `totpValue`, `otpSeed` (otp word, then a value-ish word). */
function otpName(w: string[]): boolean {
  const last = w[w.length - 1] ?? "";
  return OTP_WORD.has(last) || (OTP_VALUE_WORD.has(last) && OTP_WORD.has(w[w.length - 2] ?? ""));
}
const URL_WORD = new Set(["url", "urls", "uri", "uris", "endpoint", "endpoints"]);

/** Query / fragment parameter names that carry a credential (or a one-time code), whatever their value. */
const SECRET_PARAM =
  /secret|passw|credential|token|api[_.-]?key|apikey|private|signature|assertion|bearer|session|jwt|otp|verifier|(^|[_.-])(key|sig|code|auth|pwd|pw|sas)$|[a-z]Key$/i;
const JWT_SHAPE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\./;

/**
 * "public": an absolute http(s)/ldap(s) URL that embeds no credential we can recognise (see the file header for the
 * limits). "credentialed": it embeds one (userinfo, a secret-named query/fragment parameter, an opaque fragment, JWT
 * or PEM content). "other": not a URL we understand.
 */
function classifyUrl(v: string): "public" | "credentialed" | "other" {
  const t = v.trim();
  if (PEM_PRIVATE_KEY.test(t) || JWT_SHAPE.test(t)) return "credentialed";
  if (t.length === 0 || t.length > 2048) return "other";
  let u: URL;
  try {
    u = new URL(t);
  } catch {
    return "other";
  }
  if (!["http:", "https:", "ldap:", "ldaps:"].includes(u.protocol)) return "other";
  if (u.username || u.password) return "credentialed";
  const params = [...u.searchParams.keys()];
  if (u.hash.length > 1) {
    // A fragment that is not key=value is opaque: treat the whole fragment as a possible token.
    if (!u.hash.includes("=")) return "credentialed";
    params.push(...new URLSearchParams(u.hash.slice(1)).keys());
  }
  return params.some((k) => SECRET_PARAM.test(k)) ? "credentialed" : "public";
}

const PEM_PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const MAX_DEPTH = 12;

/** True for values that cannot be a credential: booleans, numbers, null, empty, "true"/"false". */
function inert(v: unknown): boolean {
  if (v === null || v === undefined || typeof v === "boolean" || typeof v === "number") return true;
  if (typeof v !== "string") return false;
  const t = v.trim();
  return t === "" || /^(true|false|null)$/i.test(t);
}

function walk(value: unknown, softKey: boolean, urlKey: boolean, depth: number): unknown {
  if (depth > MAX_DEPTH) return REDACTED; // too deep to inspect safely: drop rather than pass through
  if (typeof value === "string") {
    if (PEM_PRIVATE_KEY.test(value)) return REDACTED;
    if (inert(value)) return value;
    if (urlKey) {
      // A URL-named field: readable when it is a clean URL, hidden when it embeds a credential (even under a key
      // that is not otherwise secret-looking, such as `jwksUrl`); a non-URL value follows the key's own rule.
      const kind = classifyUrl(value);
      if (kind === "credentialed") return REDACTED;
      if (kind === "public") return value;
    }
    return softKey ? REDACTED : value;
  }
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => walk(v, softKey, urlKey, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === undefined) continue;
    const w = words(k);
    const codes = recoveryCodes(w);
    const urlName = URL_WORD.has(w[w.length - 1] ?? "");
    if (SAFE_KEYS.has(k.toLowerCase()) || SAFE_PREFIX.test(k)) {
      out[k] = walk(v, false, false, depth + 1);
    } else if (HARD_KEY.test(k) || codes === "end") {
      out[k] = REDACTED;
    } else {
      const soft =
        (SOFT_KEY.test(k) && !BENIGN_SUFFIX.test(k)) ||
        (codes === "inside" && !BENIGN_SUFFIX.test(k)) ||
        otpName(w);
      out[k] = walk(v, softKey || soft, urlName, depth + 1);
    }
  }
  return out;
}

/** Deep copy of `value` with secret-bearing fields replaced by "[REDACTED]". */
export function redactSecrets<T>(value: T): T {
  return walk(value, false, false, 0) as T;
}

/** Largest slice of a Keycloak error body that is passed on to the model. */
export const MAX_ERROR_BODY = 800;

const TEXT_RULES: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, REDACTED],
  // JWT-shaped strings (access / refresh / id / action tokens).
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, REDACTED],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, `Bearer ${REDACTED}`],
  // key=value / key: value / "key":"value" where the key names a secret (form bodies, query strings, plain text).
  [
    /((?:secret|passw(?:or)?d|token|credential|api[\s._-]?key|private[\s._-]?key|authorization)[\w.-]*["']?\s*[=:]\s*["']?)(?:\[REDACTED\]|[^\s"'&,;}\]]+)/gi,
    `$1${REDACTED}`,
  ],
];

function scrubText(s: string): string {
  return TEXT_RULES.reduce((acc, [re, to]) => acc.replace(re, to), s);
}

/**
 * A Keycloak error response body made safe to show the model: a JSON body goes through `redactSecrets`
 * (key-based), every body then has PEM private keys, JWT-shaped strings, `Bearer` tokens and `secret=…` /
 * `password: …` style pairs replaced, and only after that is it cut to `max` characters, so a secret that
 * straddles the cut cannot survive as a partial value. Name- and shape-based, like `redactSecrets`.
 */
export function redactErrorBody(body: string, max = MAX_ERROR_BODY): string {
  let text = body;
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed !== null && typeof parsed === "object") text = JSON.stringify(redactSecrets(parsed));
  } catch {
    // not JSON: handled as text below
  }
  const safe = scrubText(text);
  return safe.length > max ? `${safe.slice(0, max)}…` : safe;
}
