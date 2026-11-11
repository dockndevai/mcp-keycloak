/**
 * Minimal Keycloak Admin REST client built on the global fetch API.
 *
 * We deliberately avoid a heavy SDK: the Admin REST surface we need is small,
 * and a thin wrapper keeps the dependency footprint (and audit surface) tiny.
 * Access tokens are cached and refreshed automatically before expiry.
 */
import { createHash } from "node:crypto";
import type { KeycloakConnection } from "../config.js";

interface TokenState {
  accessToken: string;
  expiresAt: number; // epoch ms
}

export interface UserRepresentation {
  id?: string;
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
  emailVerified?: boolean;
  attributes?: Record<string, string[]>;
  [k: string]: unknown;
}

/**
 * Fields of a user representation that change without the user itself changing (or that are
 * derived/per-request), so they must not feed the version token. `notBefore` moves on session
 * revocation; `access` / `disableableCredentialTypes` / `totp` are computed by the server.
 */
const VOLATILE_USER_FIELDS = new Set(["notBefore", "access", "disableableCredentialTypes", "totp", "credentials"]);

/** Keys that look like secrets are dropped entirely: a secret must never be hashed or displayed. */
const SECRET_KEY = /pass(word|wd)?|secret|token|api[-_]?key|credential|authorization|private[-_]?key|bearer|cookie/i;

/** Deterministic copy of `value` with sorted keys and secret-looking keys removed. */
function stripForHash(value: unknown, depth = 0): unknown {
  if (value === null || typeof value !== "object") return value;
  if (depth >= 8) return "[depth-limit]";
  if (Array.isArray(value)) return value.map((v) => stripForHash(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    if (SECRET_KEY.test(k)) continue;
    const v = (value as Record<string, unknown>)[k];
    if (v !== undefined) out[k] = stripForHash(v, depth + 1);
  }
  return out;
}

export class KeycloakError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: string,
  ) {
    super(message);
    this.name = "KeycloakError";
  }
}

export class KeycloakClient {
  private token?: TokenState;

  constructor(private readonly conn: KeycloakConnection) {
    if (!conn.tlsRejectUnauthorized) {
      // Node's fetch has no per-request TLS toggle; this is the documented
      // escape hatch. It is intentionally opt-in and loudly warned about.
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
      process.stderr.write(
        "[keycloak-mcp] WARNING: TLS certificate verification is DISABLED.\n",
      );
    }
  }

  private async authenticate(): Promise<TokenState> {
    const url = `${this.conn.baseUrl}/realms/${this.conn.authRealm}/protocol/openid-connect/token`;
    const form = new URLSearchParams();
    const { auth } = this.conn;
    if (auth.kind === "client_credentials") {
      form.set("grant_type", "client_credentials");
      form.set("client_id", auth.clientId);
      form.set("client_secret", auth.clientSecret);
    } else {
      form.set("grant_type", "password");
      form.set("client_id", auth.clientId);
      form.set("username", auth.username);
      form.set("password", auth.password);
    }

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new KeycloakError(
        `Authentication to Keycloak failed (${res.status}). Check credentials and KEYCLOAK_AUTH_REALM.`,
        res.status,
        body,
      );
    }
    const data = (await res.json()) as { access_token: string; expires_in: number };
    return {
      accessToken: data.access_token,
      // Refresh 15s before actual expiry to avoid edge-of-window failures.
      expiresAt: Date.now() + (data.expires_in - 15) * 1000,
    };
  }

  private async getToken(): Promise<string> {
    if (this.token && this.token.expiresAt > Date.now()) {
      return this.token.accessToken;
    }
    this.token = await this.authenticate();
    return this.token.accessToken;
  }

  /** Low-level request against the Admin REST API (paths are relative to /admin). */
  async request<T = unknown>(
    method: string,
    path: string,
    options: { query?: Record<string, string | number | boolean | undefined>; body?: unknown } = {},
  ): Promise<{ status: number; data: T; location?: string }> {
    const token = await this.getToken();
    const url = new URL(`${this.conn.baseUrl}/admin${path}`);
    for (const [k, v] of Object.entries(options.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }

    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new KeycloakError(
        `Keycloak API ${method} ${path} failed with ${res.status}.`,
        res.status,
        body,
      );
    }

    const location = res.headers.get("location") ?? undefined;
    const text = await res.text();
    const data = text ? (JSON.parse(text) as T) : (undefined as T);
    return { status: res.status, data, location };
  }

  // --- Convenience helpers used by the tools ---------------------------------

  listRealms() {
    return this.request<Array<{ realm: string; enabled: boolean; id: string }>>("GET", "/realms");
  }

  getRealm(realm: string) {
    return this.request<Record<string, unknown>>("GET", `/realms/${encodeURIComponent(realm)}`);
  }

  listUsers(realm: string, query: Record<string, string | number | undefined>) {
    return this.request<UserRepresentation[]>(
      "GET",
      `/realms/${encodeURIComponent(realm)}/users`,
      { query },
    );
  }

  getUser(realm: string, id: string) {
    return this.request<UserRepresentation>(
      "GET",
      `/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(id)}`,
    );
  }

  /**
   * Version token for a user, pinned across an approval prompt. Keycloak exposes no ETag, so this
   * is a hash of the user representation minus volatile (`notBefore`, `access`, `totp`, …) and
   * secret-looking fields: id, username, email, names, enabled/emailVerified, createdTimestamp,
   * attributes, required actions, federation link. Returns undefined if the user does not exist;
   * any other failure throws. Limits: credentials and role/group membership are not covered, and a
   * user recreated with an identical id and identical fields would not be distinguishable.
   */
  async userVersion(realm: string, id: string): Promise<string | undefined> {
    let user: UserRepresentation | undefined;
    try {
      user = (await this.getUser(realm, id)).data;
    } catch (err) {
      if (err instanceof KeycloakError && err.status === 404) return undefined;
      throw err;
    }
    if (!user) return undefined;
    const stable: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(user)) {
      if (!VOLATILE_USER_FIELDS.has(k)) stable[k] = v;
    }
    return createHash("sha256").update(JSON.stringify(stripForHash(stable))).digest("hex").slice(0, 12);
  }

  countUsers(realm: string, query: Record<string, string | undefined>) {
    return this.request<number>("GET", `/realms/${encodeURIComponent(realm)}/users/count`, {
      query,
    });
  }

  listClients(realm: string, query: Record<string, string | number | undefined>) {
    return this.request<Array<Record<string, unknown>>>(
      "GET",
      `/realms/${encodeURIComponent(realm)}/clients`,
      { query },
    );
  }

  listRealmRoles(realm: string) {
    return this.request<Array<Record<string, unknown>>>(
      "GET",
      `/realms/${encodeURIComponent(realm)}/roles`,
    );
  }

  listGroups(realm: string, query: Record<string, string | number | undefined>) {
    return this.request<Array<Record<string, unknown>>>(
      "GET",
      `/realms/${encodeURIComponent(realm)}/groups`,
      { query },
    );
  }

  createUser(realm: string, user: UserRepresentation) {
    return this.request<void>("POST", `/realms/${encodeURIComponent(realm)}/users`, { body: user });
  }

  updateUser(realm: string, id: string, patch: UserRepresentation) {
    return this.request<void>(
      "PUT",
      `/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(id)}`,
      { body: patch },
    );
  }

  resetPassword(realm: string, id: string, value: string, temporary: boolean) {
    return this.request<void>(
      "PUT",
      `/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(id)}/reset-password`,
      { body: { type: "password", value, temporary } },
    );
  }

  deleteUser(realm: string, id: string) {
    return this.request<void>(
      "DELETE",
      `/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(id)}`,
    );
  }

  logoutUser(realm: string, id: string) {
    return this.request<void>(
      "POST",
      `/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(id)}/logout`,
    );
  }

  getUserSessions(realm: string, id: string) {
    return this.request<Array<Record<string, unknown>>>(
      "GET",
      `/realms/${encodeURIComponent(realm)}/users/${encodeURIComponent(id)}/sessions`,
    );
  }

  listEvents(
    realm: string,
    query: {
      type?: string[];
      client?: string;
      user?: string;
      dateFrom?: string;
      dateTo?: string;
      first?: number;
      max?: number;
    },
  ) {
    const url = new URL(`${this.conn.baseUrl}/admin/realms/${encodeURIComponent(realm)}/events`);
    for (const t of query.type ?? []) url.searchParams.append("type", t);
    if (query.client) url.searchParams.set("client", query.client);
    if (query.user) url.searchParams.set("user", query.user);
    if (query.dateFrom) url.searchParams.set("dateFrom", query.dateFrom);
    if (query.dateTo) url.searchParams.set("dateTo", query.dateTo);
    if (query.first !== undefined) url.searchParams.set("first", String(query.first));
    if (query.max !== undefined) url.searchParams.set("max", String(query.max));
    return this.requestUrl<Array<Record<string, unknown>>>("GET", url);
  }

  /** Like {@link request}, but for endpoints (e.g. multi-value query params) that need a pre-built URL. */
  private async requestUrl<T = unknown>(
    method: string,
    url: URL,
  ): Promise<{ status: number; data: T }> {
    const token = await this.getToken();
    const res = await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new KeycloakError(
        `Keycloak API ${method} ${url.pathname} failed with ${res.status}.`,
        res.status,
        body,
      );
    }
    const text = await res.text();
    const data = text ? (JSON.parse(text) as T) : (undefined as T);
    return { status: res.status, data };
  }
}
