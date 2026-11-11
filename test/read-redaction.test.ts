import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { KeycloakClient, KeycloakError } from "../src/keycloak/client.js";
import { MAX_ERROR_BODY, REDACTED, redactErrorBody } from "../src/redact.js";
import { buildServer } from "../src/server.js";

/**
 * The read tools other than list_clients used to hand Keycloak's JSON to the model untouched. Free-form user, role,
 * group and realm `attributes` can hold secrets, and Keycloak's own masking only covers the fields it knows about.
 * Shapes below follow the Admin REST API representations; every secret is a recognisable "LEAK-" string.
 */
const config = (): AppConfig => ({
  connection: {
    baseUrl: "http://localhost:8080",
    authRealm: "master",
    auth: { kind: "client_credentials", clientId: "t", clientSecret: "s" },
    tlsRejectUnauthorized: true,
  },
  security: {
    mode: "read-only",
    realmAllowlist: [],
    protectedRealms: [],
    allowDelete: false,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
  },
});

async function call(name: string, args: Record<string, unknown>) {
  const { server } = buildServer(config());
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  const res = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
  const raw = res.content[0]?.text ?? "";
  return { raw, isError: res.isError === true, json: () => JSON.parse(raw) as any };
}

afterEach(() => vi.restoreAllMocks());

const user = {
  id: "5b0a8f1e-0000-4000-8000-000000000001",
  username: "alice",
  firstName: "Alice",
  lastName: "Anders",
  email: "alice@example.com",
  emailVerified: true,
  enabled: true,
  totp: false,
  createdTimestamp: 1730000000000,
  notBefore: 0,
  disableableCredentialTypes: ["password"],
  requiredActions: ["UPDATE_PASSWORD"],
  attributes: {
    phone: ["+1 555 0100"],
    department: ["Engineering"],
    locale: ["en"],
    "employee.id": ["E-1042"],
    api_key: ["LEAK-user-api-key"],
    "legacy.password": ["LEAK-legacy-password"],
    "totp.secret": ["LEAK-totp-secret"],
    "ci.access.token": ["LEAK-ci-token"],
  },
  credentials: [{ type: "password", userLabel: "My password", secretData: '{"value":"LEAK-hash","salt":"LEAK-salt"}', credentialData: '{"hashIterations":27500}' }],
  access: { manageGroupMembership: true, view: true, mapRoles: true },
};

const role = {
  id: "role-1",
  name: "billing-admin",
  description: "Billing administrators",
  composite: false,
  clientRole: false,
  containerId: "demo",
  attributes: { owner: ["finance"], "webhook.secret": ["LEAK-role-webhook-secret"], "ticket.queue": ["billing"] },
};

const group = {
  id: "group-1",
  name: "platform",
  path: "/platform",
  attributes: { cost_center: ["CC-77"], slackToken: ["LEAK-group-slack-token"] },
  subGroups: [{ id: "group-2", name: "sre", path: "/platform/sre", attributes: { password: ["LEAK-subgroup-password"], oncall: ["true"] }, subGroups: [] }],
};

const realm = {
  id: "demo",
  realm: "demo",
  displayName: "Demo",
  enabled: true,
  sslRequired: "external",
  accessTokenLifespan: 300,
  ssoSessionIdleTimeout: 1800,
  passwordPolicy: "length(8) and digits(1)",
  codeSecret: "LEAK-realm-codeSecret",
  otpPolicyType: "totp",
  otpPolicyDigits: 6,
  webAuthnPolicyRpEntityName: "keycloak",
  webAuthnPolicyPasswordlessRpEntityName: "keycloak",
  webAuthnPolicyPasswordlessSignatureAlgorithms: ["ES256"],
  webAuthnPolicyPasswordlessUserVerificationRequirement: "not specified",
  browserFlow: "browser",
  resetCredentialsFlow: "reset credentials",
  smtpServer: { host: "smtp.example.com", port: "587", from: "no-reply@example.com", auth: "true", user: "mailer", password: "LEAK-smtp-password", starttls: "true" },
  browserSecurityHeaders: { xFrameOptions: "SAMEORIGIN", contentSecurityPolicy: "frame-src 'self'" },
  attributes: { frontendUrl: "https://sso.example.com", cibaBackchannelTokenDeliveryMode: "poll", "custom.api.key": "LEAK-realm-attribute-key" },
  identityProviders: [{ alias: "corp-oidc", providerId: "oidc", enabled: true, config: { clientId: "kc", clientSecret: "LEAK-idp-client-secret", syncMode: "IMPORT" } }],
  components: {
    "org.keycloak.storage.UserStorageProvider": [{ id: "ldap-1", name: "corp-ldap", providerId: "ldap", config: { connectionUrl: ["ldaps://ldap.example.com"], bindDn: ["cn=svc,dc=example,dc=com"], bindCredential: ["LEAK-ldap-bind-credential"] } }],
  },
};

describe("get_user / list_users", () => {
  it("get_user hides secret-bearing attributes and credentials, keeps ordinary attributes", async () => {
    vi.spyOn(KeycloakClient.prototype, "getUser").mockResolvedValue({ status: 200, data: user } as never);
    const { raw, json } = await call("get_user", { realm: "demo", userId: user.id });
    expect(raw).not.toContain("LEAK-");
    const u = json();
    expect(u.attributes.phone).toEqual(["+1 555 0100"]);
    expect(u.attributes.department).toEqual(["Engineering"]);
    expect(u.attributes["employee.id"]).toEqual(["E-1042"]);
    expect(u.attributes.api_key).toBe(REDACTED);
    expect(u.credentials).toBe(REDACTED);
    expect(u.username).toBe("alice");
    expect(u.email).toBe("alice@example.com");
    expect(u.emailVerified).toBe(true);
    expect(u.requiredActions).toEqual(["UPDATE_PASSWORD"]);
    expect(u.disableableCredentialTypes).toEqual(["password"]);
    expect(u.access.view).toBe(true);
  });

  it("list_users applies the same redaction to every user", async () => {
    vi.spyOn(KeycloakClient.prototype, "listUsers").mockResolvedValue({ status: 200, data: [user, { ...user, id: "u2", username: "bob" }] } as never);
    const { raw, json } = await call("list_users", { realm: "demo" });
    expect(raw).not.toContain("LEAK-");
    expect(json()).toHaveLength(2);
    expect(json()[1].username).toBe("bob");
    expect(json()[1].attributes.locale).toEqual(["en"]);
  });
});

describe("list_realm_roles / list_groups", () => {
  it("list_realm_roles hides secret-shaped role attributes only", async () => {
    vi.spyOn(KeycloakClient.prototype, "listRealmRoles").mockResolvedValue({ status: 200, data: [role] } as never);
    const { raw, json } = await call("list_realm_roles", { realm: "demo" });
    expect(raw).not.toContain("LEAK-");
    expect(json()[0].name).toBe("billing-admin");
    expect(json()[0].attributes.owner).toEqual(["finance"]);
    expect(json()[0].attributes["ticket.queue"]).toEqual(["billing"]);
  });

  it("list_groups redacts attributes at every sub-group depth", async () => {
    vi.spyOn(KeycloakClient.prototype, "listGroups").mockResolvedValue({ status: 200, data: [group] } as never);
    const { raw, json } = await call("list_groups", { realm: "demo" });
    expect(raw).not.toContain("LEAK-");
    expect(json()[0].path).toBe("/platform");
    expect(json()[0].attributes.cost_center).toEqual(["CC-77"]);
    expect(json()[0].subGroups[0].path).toBe("/platform/sre");
    expect(json()[0].subGroups[0].attributes.oncall).toEqual(["true"]);
  });
});

describe("get_realm", () => {
  it("redacts smtp password, codeSecret, identity-provider and LDAP secrets and secret-shaped attributes", async () => {
    vi.spyOn(KeycloakClient.prototype, "getRealm").mockResolvedValue({ status: 200, data: realm } as never);
    const { raw, json } = await call("get_realm", { realm: "demo" });
    expect(raw).not.toContain("LEAK-");
    const r = json();
    expect(r.smtpServer.password).toBe(REDACTED);
    expect(r.codeSecret).toBe(REDACTED);
    expect(r.attributes["custom.api.key"]).toBe(REDACTED);
    expect(r.identityProviders[0].config.clientSecret).toBe(REDACTED);
  });

  it("keeps the configuration an operator reads the realm for", async () => {
    vi.spyOn(KeycloakClient.prototype, "getRealm").mockResolvedValue({ status: 200, data: realm } as never);
    const r = (await call("get_realm", { realm: "demo" })).json();
    expect(r.realm).toBe("demo");
    expect(r.sslRequired).toBe("external");
    expect(r.accessTokenLifespan).toBe(300);
    expect(r.passwordPolicy).toBe("length(8) and digits(1)");
    expect(r.otpPolicyType).toBe("totp");
    expect(r.browserFlow).toBe("browser");
    expect(r.resetCredentialsFlow).toBe("reset credentials");
    expect(r.webAuthnPolicyPasswordlessRpEntityName).toBe("keycloak");
    expect(r.webAuthnPolicyPasswordlessSignatureAlgorithms).toEqual(["ES256"]);
    expect(r.smtpServer).toMatchObject({ host: "smtp.example.com", port: "587", from: "no-reply@example.com", user: "mailer", starttls: "true" });
    expect(r.browserSecurityHeaders.xFrameOptions).toBe("SAMEORIGIN");
    expect(r.attributes.frontendUrl).toBe("https://sso.example.com");
    expect(r.attributes.cibaBackchannelTokenDeliveryMode).toBe("poll");
    expect(r.identityProviders[0].config).toMatchObject({ clientId: "kc", syncMode: "IMPORT" });
    expect(r.components["org.keycloak.storage.UserStorageProvider"][0].config.connectionUrl).toEqual(["ldaps://ldap.example.com"]);
  });

  it("also hides a realm secret that Keycloak itself already masks as **********", async () => {
    vi.spyOn(KeycloakClient.prototype, "getRealm").mockResolvedValue({ status: 200, data: { realm: "demo", smtpServer: { password: "**********" } } } as never);
    expect((await call("get_realm", { realm: "demo" })).json().smtpServer.password).toBe(REDACTED);
  });
});

describe("Keycloak error bodies", () => {
  // Built at runtime: a JWT literal in source trips the repo's secret scanner.
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const JWT = [b64({ alg: "RS256", typ: "JWT" }), b64({ sub: "LEAK-jwt-payload" }), "LEAK-signature-part"].join(".");

  const failWith = async (body: string, status = 400) => {
    vi.spyOn(KeycloakClient.prototype, "getUser").mockRejectedValue(new KeycloakError(`Keycloak API GET /users/x failed with ${status}.`, status, body));
    return call("get_user", { realm: "demo", userId: "x" });
  };

  it("keeps the useful part of a JSON error and hides secrets in it", async () => {
    const res = await failWith(
      JSON.stringify({ error: "invalid_request", error_description: `Bad token ${JWT}`, client_secret: "LEAK-echoed-client-secret", errorMessage: "Invalid user credentials" }),
    );
    expect(res.isError).toBe(true);
    expect(res.raw).toContain("failed with 400");
    expect(res.raw).toContain("invalid_request");
    expect(res.raw).toContain("Invalid user credentials");
    expect(res.raw).not.toContain("LEAK");
    expect(res.raw).not.toContain("eyJhbGci");
  });

  it("hides secrets in a plain-text / form-style body", async () => {
    const res = await failWith("Unexpected: client_id=kc&client_secret=LEAK-form-secret&password=LEAK-form-pw Authorization: Bearer LEAK-bearer-token-value");
    expect(res.raw).not.toContain("LEAK");
    expect(res.raw).toContain("client_id=kc");
  });

  it("hides a PEM private key", async () => {
    const res = await failWith("bad key\n-----BEGIN PRIVATE KEY-----\nLEAK-pem-body\n-----END PRIVATE KEY-----\nend");
    expect(res.raw).not.toContain("LEAK");
    expect(res.raw).not.toContain("BEGIN PRIVATE KEY");
  });

  it("truncates an oversized body", async () => {
    const res = await failWith("A".repeat(50_000));
    expect(res.raw.length).toBeLessThan(MAX_ERROR_BODY + 200);
  });

  it("redacts before truncating, so a secret straddling the cut leaves no fragment", async () => {
    // The cut at 800 characters falls inside the token: cutting first would leave its header and part of its payload.
    const res = await failWith(`${"y".repeat(745)} ${JWT}`);
    expect(res.raw).not.toContain("eyJ");
    const res2 = await failWith(`${"x ".repeat(380)}secret=LEAK-straddling-secret-value more`);
    expect(res2.raw).not.toContain("LEAK");
  });
});

describe("redactErrorBody", () => {
  it("is idempotent on already-redacted JSON (no doubled markers)", () => {
    const once = redactErrorBody(JSON.stringify({ password: "p", error: "x" }));
    expect(once).toBe(`{"password":"${REDACTED}","error":"x"}`);
    expect(redactErrorBody(once)).toBe(once);
  });

  it("leaves a harmless message alone", () => {
    expect(redactErrorBody('{"errorMessage":"User exists with same username"}')).toBe('{"errorMessage":"User exists with same username"}');
    expect(redactErrorBody("Not Found")).toBe("Not Found");
  });
});
