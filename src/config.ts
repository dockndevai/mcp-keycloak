/**
 * Configuration is read entirely from environment variables so the server can
 * be dropped into any MCP client config without code changes.
 */
import type { AccessMode, SecurityConfig } from "./security.js";

export interface KeycloakConnection {
  /** Base URL of the Keycloak server, e.g. https://kc.example.com */
  baseUrl: string;
  /** Realm used to authenticate the admin credentials (usually "master"). */
  authRealm: string;
  /** Authentication strategy. */
  auth:
    | { kind: "password"; clientId: string; username: string; password: string }
    | { kind: "client_credentials"; clientId: string; clientSecret: string };
  /** Reject self-signed / invalid TLS certs unless explicitly disabled. */
  tlsRejectUnauthorized: boolean;
}

export interface AppConfig {
  connection: KeycloakConnection;
  security: SecurityConfig;
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function list(name: string): string[] {
  const v = process.env[name];
  if (!v) return [];
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return v;
}

function parseMode(): AccessMode {
  const raw = (process.env.KEYCLOAK_MODE ?? "read-only").toLowerCase();
  if (raw === "read-only" || raw === "read-write" || raw === "admin") return raw;
  throw new Error(
    `Invalid KEYCLOAK_MODE '${raw}'. Expected one of: read-only, read-write, admin.`,
  );
}

export function loadConfig(): AppConfig {
  // Fall back to placeholders so the server can start and advertise its tools
  // (introspection) even without config; auth failures surface on first request.
  const baseUrl = (process.env.KEYCLOAK_URL ?? "http://localhost:8080").replace(/\/+$/, "");
  if (!process.env.KEYCLOAK_URL) {
    process.stderr.write("[keycloak-mcp] WARNING: KEYCLOAK_URL not set; using http://localhost:8080.\n");
  }
  const authRealm = process.env.KEYCLOAK_AUTH_REALM ?? "master";

  const clientId = process.env.KEYCLOAK_CLIENT_ID ?? "admin-cli";
  const clientSecret = process.env.KEYCLOAK_CLIENT_SECRET;
  const username = process.env.KEYCLOAK_USERNAME;
  const password = process.env.KEYCLOAK_PASSWORD;

  let auth: KeycloakConnection["auth"];
  if (clientSecret) {
    auth = { kind: "client_credentials", clientId, clientSecret };
  } else if (username && password) {
    auth = { kind: "password", clientId, username, password };
  } else {
    process.stderr.write(
      "[keycloak-mcp] WARNING: no credentials set (KEYCLOAK_CLIENT_SECRET or KEYCLOAK_USERNAME/PASSWORD); tool calls will fail until provided.\n",
    );
    auth = { kind: "client_credentials", clientId, clientSecret: "" };
  }

  return {
    connection: {
      baseUrl,
      authRealm,
      auth,
      tlsRejectUnauthorized: bool("KEYCLOAK_TLS_REJECT_UNAUTHORIZED", true),
    },
    security: {
      mode: parseMode(),
      realmAllowlist: list("KEYCLOAK_REALM_ALLOWLIST"),
      protectedRealms: list("KEYCLOAK_PROTECTED_REALMS").length
        ? list("KEYCLOAK_PROTECTED_REALMS")
        : ["master"],
      allowDelete: bool("KEYCLOAK_ALLOW_DELETE", false),
      dryRun: bool("KEYCLOAK_DRY_RUN", false),
      auditLog: bool("KEYCLOAK_AUDIT_LOG", true),
    },
  };
}
