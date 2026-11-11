# Security

`mcp-keycloak` exposes Keycloak administration to an AI agent. Treat it like any
other privileged automation and grant it the least access it needs.

## Principles

- **Start read-only.** Leave `KEYCLOAK_MODE=read-only` until you specifically
  need the agent to make changes. Tools above the current mode are never
  registered, so a read-only server cannot mutate anything even if asked.
- **Scope the credentials, not just the flags.** The flags are defence in depth;
  the primary control is the Keycloak service-account role mapping. Give the
  client only the `realm-management` roles it actually needs.
- **Protect sensitive realms.** `master` is protected by default. Add any other
  realm you never want mutated to `KEYCLOAK_PROTECTED_REALMS`.
- **Gate deletion explicitly.** `delete_*` tools require both `admin` mode and
  `KEYCLOAK_ALLOW_DELETE=true`.
- **Require a human for destructive ops.** Set `KEYCLOAK_REQUIRE_HUMAN_APPROVAL=true` so `delete_user`,
  `reset_password` and `logout_user` are refused when the client cannot show an approval prompt.
  Each approval is bound to the exact tool and arguments (fingerprint; secrets such as the new password
  are redacted from the prompt and the fingerprint) and to the target user's version (a hash of the user
  representation without volatile fields such as `notBefore`, and without secret-looking fields; Keycloak
  has no ETag); if the user changed while the human was deciding, the action is refused. Approval
  receipts are written to the audit log (`"audit":"approval"`, with `approvedBy` = `human` or `flag-only`).
- **Prefer an allowlist.** Set `KEYCLOAK_REALM_ALLOWLIST` so the agent can only
  touch the realms you intend.
- **Keep the audit log on.** `KEYCLOAK_AUDIT_LOG=true` (default) writes a JSON
  line per guarded operation to stderr.

## Handling of secrets

- Credentials are read from environment variables and never logged.
- `reset_password` never echoes the password back in its result.
- `list_clients`, `get_user`, `list_users`, `get_realm`, `list_realm_roles` and `list_groups` redact secret-bearing
  fields before they reach the model, deeply and by key name (`src/redact.ts`; user, role, group and realm
  `attributes` are free-form and can hold secrets, a user's `credentials` is dropped, and `get_realm` hides
  `smtpServer.password`, `codeSecret`, identity-provider and LDAP secrets itself instead of relying on Keycloak's
  `**********` masking):
  `secret`, `registrationAccessToken`, the previous secret kept during rotation
  (`attributes["client.secret.rotated"]`), SAML signing/encryption private keys, anything whose name ends in
  secret / password / credential(s) / private key / API key (including inside protocol-mapper configs and
  authorization settings), other token/secret/credential-named fields whose value is not a flag, number or
  empty, and any string containing a PEM private key block. Replaced values read `[REDACTED]`; timestamps,
  lifespans, algorithms and booleans (for example `client.secret.creation.time`, `access.token.lifespan`,
  `clientAuthenticatorType`) are kept. Key names are matched word by word (`recoveryCodes`, `recovery.codes` and
  `recovery-authn-codes` are the same name): recovery / backup / scratch codes, `initialAccessToken`, and OTP / TOTP
  credential blobs (a key ending in `otp` / `totp`, such as `totp: {...}` or `otpSecret`) are hidden, while the user
  flag `totp: false` and realm OTP settings such as `otpPolicyType` stay readable.
  **Endpoint URLs stay readable.** A field whose name ends in url / uri / endpoint (`authorizationUrl`, `tokenUrl`,
  `userInfoUrl`, `token_endpoint`, `jwks_uri`, ...) is shown when its value is an http(s) or ldap(s) URL with no
  userinfo (`user:pw@host`), no secret-named query or fragment parameter (`client_secret`, `access_token`, `code`,
  `api_key`, ...) and no JWT- or PEM-shaped content; otherwise it is hidden, and that also applies to such a field
  whose name is not otherwise secret-looking (`jwksUrl`). `secret`, `password` and `credential` fields are always
  hidden whatever they hold. The redaction is name-based and is a safety net, not a guarantee: a secret stored in a
  field with an innocuous name (for example `notes`, or an attribute called `emergency.access`) is not detected, and
  neither is a secret embedded in a URL path (such as a webhook URL). Ordinary attributes (phone, department,
  locale, ...) and realm configuration such as `passwordPolicy`, authentication flow aliases and WebAuthn policy
  settings stay readable. `count_users` and `list_realms` return no free-form fields. Error bodies use a separate,
  stricter text pass (below) and may hide URLs that the tools above would show.
- **Error responses.** When Keycloak answers with an error, the response body shown to the model is passed through
  the same redaction (JSON bodies by key; any body for PEM private keys, JWT-shaped strings, `Bearer` tokens and
  `secret=` / `password:` style pairs) and only then cut to 800 characters, so a secret cannot survive as a partial
  value at the cut.
- **TLS verification.** `KEYCLOAK_TLS_REJECT_UNAUTHORIZED=false` disables certificate verification for requests
  to Keycloak only (a dedicated connection pool for this client), with a warning on stderr. It no longer
  changes the process-wide `NODE_TLS_REJECT_UNAUTHORIZED`, so other outbound connections (for example to the
  laya-guard daemon) keep verifying certificates. Leave it on (the default) for anything but a throwaway lab.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a
public issue.
