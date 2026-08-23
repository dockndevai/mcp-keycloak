/**
 * Minimal Keycloak Admin REST client built on the global fetch API.
 *
 * We deliberately avoid a heavy SDK: the Admin REST surface we need is small,
 * and a thin wrapper keeps the dependency footprint (and audit surface) tiny.
 * Access tokens are cached and refreshed automatically before expiry.
 */
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
}
