# mcp-keycloak

[![CI](https://github.com/dockndevai/mcp-keycloak/actions/workflows/ci.yml/badge.svg)](https://github.com/dockndevai/mcp-keycloak/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A [Model Context Protocol](https://modelcontextprotocol.io) server for **Keycloak**. It lets an MCP-capable client (Claude Desktop, Claude Code, etc.) inspect and manage Keycloak realms, users, clients, roles, and groups — with security controlled entirely by flags.

The design goal is **safe by default**: it starts read-only, scopes to an allowlist of realms, protects sensitive realms from mutation, and gates destructive operations behind an explicit opt-in.

## Features

- **Multi-realm** — every tool takes a `realm` argument; scope it with an allowlist.
- **Access modes** — `read-only` → `read-write` → `admin`, layered so a mode never exposes tools above its level.
- **Security flags** — realm allowlist, protected realms, delete gating, dry-run, and JSON audit logging (see below).
- **Two auth strategies** — confidential-client service account (recommended) or admin username/password.
- **Zero heavy dependencies** — a thin fetch-based Admin REST client, plus the MCP SDK and zod.

## Security model

| Concern | Flag | Default | Effect |
| --- | --- | --- | --- |
| What can the server do at all? | `KEYCLOAK_MODE` | `read-only` | `read-only` exposes only read tools; `read-write` adds mutations; `admin` adds destructive tools. Tools above the mode are **never registered**. |
| Which realms are in scope? | `KEYCLOAK_REALM_ALLOWLIST` | *(all)* | Comma-separated. When set, any operation on a realm outside the list is refused. |
| Which realms are read-only forever? | `KEYCLOAK_PROTECTED_REALMS` | `master` | Protected realms can be read but never mutated or deleted, regardless of mode. |
| Can it delete? | `KEYCLOAK_ALLOW_DELETE` | `false` | `delete_*` tools require this **and** admin mode. |
| Preview without touching Keycloak | `KEYCLOAK_DRY_RUN` | `false` | Write/admin tools validate + log intent, then return without calling Keycloak. |
| Audit trail | `KEYCLOAK_AUDIT_LOG` | `true` | Emits a JSON line to stderr per guarded operation (`ALLOW` / `DENY` / `DRY_RUN`). |

These layers are independent — for example `admin` mode with `KEYCLOAK_ALLOW_DELETE=false` can create and update users but cannot delete them.

## Tools

**Read** (`read-only`+): `list_realms`, `get_realm`, `list_users`, `get_user`, `count_users`, `list_clients`, `list_realm_roles`, `list_groups`

**Write** (`read-write`+): `create_user`, `update_user`, `reset_password`, `logout_user`

**Admin** (`admin`): `delete_user`

## Install

```bash
npm install
npm run build
```

## Configure

Copy `.env.example` and fill it in, or set the variables directly in your MCP client config. A confidential client with the `realm-management` roles you need is the recommended credential.

## Run with Claude Desktop / Claude Code

Add to your MCP client configuration (`claude_desktop_config.json` or via `claude mcp add`):

```json
{
  "mcpServers": {
    "keycloak": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-keycloak/dist/index.js"],
      "env": {
        "KEYCLOAK_URL": "https://keycloak.example.com",
        "KEYCLOAK_CLIENT_ID": "admin-cli",
        "KEYCLOAK_CLIENT_SECRET": "your-secret",
        "KEYCLOAK_MODE": "read-only",
        "KEYCLOAK_REALM_ALLOWLIST": "app,customers"
      }
    }
  }
}
```

Bump `KEYCLOAK_MODE` to `read-write` (and, for deletes, `admin` + `KEYCLOAK_ALLOW_DELETE=true`) only when you intend to let the model make changes.

## Develop

```bash
npm run dev        # watch mode
npm test           # unit tests for the security policy
npm run typecheck
```

## License

MIT
