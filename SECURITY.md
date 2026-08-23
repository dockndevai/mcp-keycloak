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
- **Prefer an allowlist.** Set `KEYCLOAK_REALM_ALLOWLIST` so the agent can only
  touch the realms you intend.
- **Keep the audit log on.** `KEYCLOAK_AUDIT_LOG=true` (default) writes a JSON
  line per guarded operation to stderr.

## Handling of secrets

- Credentials are read from environment variables and never logged.
- `reset_password` never echoes the password back in its result.
- `list_clients` strips client secrets from responses defensively.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a
public issue.
