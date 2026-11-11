# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-11

### Security
- **Approval prompts are fully reviewable.** Arguments are shown in full up to 16 000 characters (previously cut at 1500, so a padded prefix could hide the tail of a long statement); a longer action is refused instead of approved blind. Secret redaction in prompts matches whole words (`bypass`/`tokenizer` are no longer shown as `[redacted]`).
- laya-guard now receives the secret-redacted arguments (`canonicalArgs`) instead of `JSON.stringify(args)`, so credentials in tool arguments no longer reach the guard prompt, the guard daemon, or its log.
- **Approval no longer fails open on timeout.** The human-approval prompt used the MCP SDK's default
  60 s request timeout, and a timeout fell through to "approved" (the `KEYCLOAK_ALLOW_DELETE` gate had
  already passed). A prompt nobody answered therefore auto-approved a destructive operation. A timeout is
  now a refusal, and the wait defaults to 5 minutes.
- **`list_clients` redacts secrets deeply.** It only removed the top-level `secret` key, although the docs said
  secrets are stripped defensively. `registrationAccessToken`, the rotated secret
  (`attributes["client.secret.rotated"]`), SAML private keys, secret-shaped attributes and mapper/authorization
  config values, and PEM private key blocks reached the model. They are now replaced with `[REDACTED]` by a
  conservative key-name matcher (`src/redact.ts`); timestamps, lifespans, algorithms, booleans and
  `clientAuthenticatorType` are kept. Name-based: a secret under an innocuous key name is not detected.
- **`KEYCLOAK_TLS_REJECT_UNAUTHORIZED=false` is scoped to Keycloak.** It set `NODE_TLS_REJECT_UNAUTHORIZED=0`,
  which turned certificate verification off for every outbound TLS connection in the process (including the
  laya-guard daemon call). It now uses a dedicated undici `Agent` with `rejectUnauthorized:false` for the
  Keycloak client's own requests; the warning is unchanged. Adds `undici` (^7) as a runtime dependency.

### Added
- **Approvals are bound to the exact action.** The prompt shows the tool, the full (secret-redacted)
  arguments and a fingerprint; every approval and refusal is written to the audit log as
  `"audit":"approval"` with the fingerprint, resource version and `approvedBy` (`human` / `flag-only`).
- **Approvals are bound to the target's version.** `delete_user`, `reset_password` and `logout_user`
  read a version token for the user before the prompt and again after the human answers, and refuse if it
  changed. Keycloak has no ETag, so the token is a hash of the user representation without volatile fields
  (`notBefore`, `access`, `totp`, …) and without secret-looking fields.
- `KEYCLOAK_REQUIRE_HUMAN_APPROVAL=true` — refuse destructive ops when the client cannot elicit.

Tracking issue: https://github.com/dockndevai/mcp-core/issues/1

## [0.3.5] - 2026-11-09

### Changed
- Routine weekly dependency maintenance: `npm audit --audit-level=high` reported 0 high/critical advisories. Took the safe in-range minor bump for `vitest` (5.0.5 → 5.1.0, dev-only); no direct dependency crossed a major version boundary. `npm audit` reports 0 vulnerabilities. No behavior change.

## [0.3.4] - 2026-11-02

### Changed
- Routine weekly dependency maintenance: `npm audit --audit-level=high` reported 0 advisories (no high/critical findings). Took the safe in-range patch bump for `@types/node` (26.6.5 → 26.6.6); no direct dependency crossed a major version boundary. `npm audit` reports 0 vulnerabilities after the bump.

## [0.3.3] - 2026-10-26

### Changed
- Dependency/security maintenance: `npm audit fix` cleared 2 advisories (1 high: `body-parser` DoS via trailing bytes after a compressed body — GHSA-27r3-jxmh-p828; 1 moderate: `fast-uri` scheme/host confusion — GHSA-w74x-v6f9-j3xg, GHSA-xhq7-xmqj-769h, GHSA-wjr9-j795-jxcr, GHSA-333x-w4r6-6crp). Bumped `@modelcontextprotocol/sdk` 1.32.1 → 1.32.2 (in-range patch). `npm audit` reports 0 vulnerabilities. No behavior change.

## [0.3.2] - 2026-10-19

### Changed
- Routine dependency maintenance: `npm audit --audit-level=high` reported 0 advisories; in-range patch bumps for `vitest` (5.0.3 → 5.0.5) and `zod` (4.6.6 → 4.6.7). `npm audit` reports 0 vulnerabilities. No behavior change.

## [0.3.1] - 2026-10-12

### Security
- Bump `@modelcontextprotocol/sdk` to 1.32.1, fixing a high-severity advisory (OAuth client could send credentials to an authorization server chosen by the MCP server) and a critical transitive `proxy-addr` IP-spoofing advisory. `npm audit` now reports 0 vulnerabilities.

### Changed
- Routine in-range dependency refresh: `@types/node`, `tsx`, `vitest`, `zod`.

## [0.3.0] - 2026-09-29

### Added
- **Optional AI risk guard (laya-guard).** Mutating tools can consult a local [laya-guard](https://github.com/dockndevai/laya-guard) daemon that classifies each operation allow / confirm / block before it runs. Runs after the deterministic policy gates and can only *tighten*, never grant; fails closed. Off by default (`KEYCLOAK_GUARD_MODE=monitor|enforce`).

## [0.2.2] - 2026-09-12

### Changed
- Bring dependencies and CI to current majors: `zod` ^4, TypeScript ^7, `@types/node` ^26, `tsx` ^4.23, and GitHub Actions (checkout v7, setup-node v7, action-gh-release v3, gitleaks v3, codeql-action v4). Clears the open Dependabot updates; `npm audit` reports 0 vulnerabilities.

## [0.2.1] - 2026-09-10

### Added
- Extend interactive confirmation (MCP elicitation) to `logout_user` (forces re-authentication).

## [0.2.0] - 2026-09-10

### Added
- **Human-in-the-loop confirmation for destructive actions**, via MCP [elicitation](https://modelcontextprotocol.io/specification/draft/client/elicitation). When the connected client supports elicitation, `delete_user` and `reset_password` now pause and ask the **human** to approve the exact action before it runs — a model can echo a confirmation string, but it cannot approve a prompt shown to the user. Clients that don't advertise elicitation fall back to the existing `*_ALLOW_*` flag gate, so enabling this is never *more* permissive than before.

## [0.1.3] - 2026-09-09

### Changed
- Require **Node 22** (previously Node 20); the updated dependency tree needs Node ≥ 22.19. CI and release workflows, the Dockerfile base image, and `engines` were updated.
- Bump the test runner `vitest` to ^5.0.0.

### Security
- Refresh the dependency tree to clear the moderate `hono` and `qs` advisories (transitive via the MCP SDK's HTTP transport, unused by this stdio server) and the `vitest` advisory; `npm audit` now reports **0 vulnerabilities**.

## [0.1.2] - 2026-08-30

### Changed
- Bump `@modelcontextprotocol/sdk` to ^1.30.0 to clear known dependency advisories flagged by supply-chain scanners.

## [0.1.1] - 2026-08-28

### Added
- MCP **tool annotations** on every tool (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`), derived from each tool's access
  capability. Hosts can now reason about a tool's safety from structured
  metadata instead of parsing the description — read tools are advertised as
  read-only and non-destructive, admin/destructive tools as mutating.
- A test that keeps the annotations consistent with each tool's capability.

## [0.1.0]

### Added
- Initial release.
