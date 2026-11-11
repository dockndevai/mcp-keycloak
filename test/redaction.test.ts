import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { KeycloakClient } from "../src/keycloak/client.js";
import { REDACTED, redactSecrets } from "../src/redact.js";
import { buildServer } from "../src/server.js";

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

async function connect() {
  const { server } = buildServer(config());
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

// Fake values, deliberately recognisable so a leak is obvious in a failing assertion.
const LEAK = {
  secret: "LEAK-client-secret-value",
  rotated: "LEAK-rotated-old-secret",
  reg: "LEAK-registration-access-token",
  samlKey: "LEAK-saml-private-key-body",
  pem: "-----BEGIN PRIVATE KEY-----\nLEAK-pem-body\n-----END PRIVATE KEY-----",
  mapperSecret: "LEAK-mapper-config-secret",
  nested: "LEAK-nested-secret",
  jwt: "LEAK-jwt-credential-blob",
  bind: "LEAK-bind-credential",
};

/** Realistic ClientRepresentation shapes as returned by GET /admin/realms/{realm}/clients. */
const oidcConfidential = {
  id: "11111111-aaaa-bbbb-cccc-000000000001",
  clientId: "billing-service",
  name: "Billing",
  enabled: true,
  protocol: "openid-connect",
  publicClient: false,
  bearerOnly: false,
  standardFlowEnabled: true,
  serviceAccountsEnabled: true,
  clientAuthenticatorType: "client-secret",
  secret: LEAK.secret,
  registrationAccessToken: LEAK.reg,
  redirectUris: ["https://billing.example.com/*"],
  webOrigins: ["+"],
  attributes: {
    "client.secret.creation.time": "1730000000",
    "client.secret.rotated": LEAK.rotated,
    "client.secret.rotated.creation.time": "1720000000",
    "client.secret.rotated.expiration.time": "1731000000",
    "client.secret.rotation.period": "86400",
    "access.token.lifespan": "300",
    "access.token.signed.response.alg": "RS256",
    "use.refresh.tokens": "true",
    client_credentials_use_refresh_token: "false",
    "post.logout.redirect.uris": "https://billing.example.com/bye",
    "tls.client.certificate.bound.access.tokens": "false",
    "jwt.credential.certificate": LEAK.jwt,
    "backchannel.logout.url": "https://billing.example.com/logout",
  },
  protocolMappers: [
    { name: "aud", protocol: "openid-connect", protocolMapper: "oidc-audience-mapper", config: { "included.client.audience": "billing", "id.token.claim": "true", clientSecret: LEAK.mapperSecret } },
  ],
  authenticationFlowBindingOverrides: {},
  defaultClientScopes: ["web-origins", "profile", "roles"],
};

const samlClient = {
  id: "11111111-aaaa-bbbb-cccc-000000000002",
  clientId: "https://sp.example.com/saml",
  protocol: "saml",
  enabled: true,
  clientAuthenticatorType: "client-secret",
  attributes: {
    "saml.signing.private.key": LEAK.samlKey,
    "saml.encryption.private.key": LEAK.samlKey,
    "saml.signing.certificate": "MIIC-public-cert",
    "saml.server.signature": "true",
    "saml.assertion.signature": "false",
    "saml_name_id_format": "username",
  },
};

const jwtClient = {
  id: "11111111-aaaa-bbbb-cccc-000000000003",
  clientId: "jwt-client",
  protocol: "openid-connect",
  clientAuthenticatorType: "client-jwt",
  attributes: {
    "token.endpoint.auth.signing.alg": "RS256",
    "jwks.url": "https://jwt-client.example.com/jwks",
    "use.jwks.url": "true",
    notes: `see ${LEAK.pem}`,
  },
  authorizationSettings: { resources: [{ name: "r", attributes: { apiKey: LEAK.nested, ldap: [{ bindCredential: LEAK.bind }] } }] },
};

afterEach(() => vi.restoreAllMocks());

async function listClients(data: unknown[]) {
  vi.spyOn(KeycloakClient.prototype, "listClients").mockResolvedValue({ status: 200, data: data as Array<Record<string, unknown>> });
  const client = await connect();
  const res = await client.callTool({ name: "list_clients", arguments: { realm: "demo" } });
  return { raw: text(res), parsed: JSON.parse(text(res)) as Array<Record<string, any>> };
}

describe("list_clients redaction", () => {
  it("never returns any secret-bearing value from realistic client representations", async () => {
    const { raw } = await listClients([oidcConfidential, samlClient, jwtClient]);
    expect(raw).not.toContain("LEAK-");
    expect(raw).not.toContain("BEGIN PRIVATE KEY");
  });

  it("keeps the non-secret configuration an operator needs", async () => {
    const { parsed } = await listClients([oidcConfidential, samlClient, jwtClient]);
    const c = parsed[0]!;
    expect(c.clientId).toBe("billing-service");
    expect(c.clientAuthenticatorType).toBe("client-secret");
    expect(c.redirectUris).toEqual(["https://billing.example.com/*"]);
    expect(c.attributes["client.secret.creation.time"]).toBe("1730000000");
    expect(c.attributes["client.secret.rotated.creation.time"]).toBe("1720000000");
    expect(c.attributes["client.secret.rotation.period"]).toBe("86400");
    expect(c.attributes["access.token.lifespan"]).toBe("300");
    expect(c.attributes["access.token.signed.response.alg"]).toBe("RS256");
    expect(c.attributes["use.refresh.tokens"]).toBe("true");
    expect(c.attributes["backchannel.logout.url"]).toBe("https://billing.example.com/logout");
    expect(c.protocolMappers[0].config["included.client.audience"]).toBe("billing");
    expect(parsed[1]!.attributes["saml.signing.certificate"]).toBe("MIIC-public-cert");
    expect(parsed[1]!.attributes["saml.server.signature"]).toBe("true");
    expect(parsed[2]!.clientAuthenticatorType).toBe("client-jwt");
    expect(parsed[2]!.attributes["jwks.url"]).toBe("https://jwt-client.example.com/jwks");
  });

  it("marks what it removed so the model can tell a secret exists", async () => {
    const { parsed } = await listClients([oidcConfidential]);
    expect(parsed[0]!.secret).toBe("[REDACTED]");
    expect(parsed[0]!.registrationAccessToken).toBe("[REDACTED]");
    expect(parsed[0]!.attributes["client.secret.rotated"]).toBe("[REDACTED]");
  });
});

describe("redactSecrets", () => {
  it("replaces hard-key values whatever they hold, including objects and arrays, at any depth", () => {
    const out = redactSecrets({
      a: { clientSecret: "x", b: [{ bindCredential: "y", ok: "keep" }] },
      credentials: [{ type: "password", secretData: "{...}", value: "z" }],
      "client.secret.rotated": "123456",
      smtpServer: { host: "smtp.example.com", password: "p" },
      "saml.signing.private.key": "k",
    });
    expect(out).toEqual({
      a: { clientSecret: REDACTED, b: [{ bindCredential: REDACTED, ok: "keep" }] },
      credentials: REDACTED,
      "client.secret.rotated": REDACTED,
      smtpServer: { host: "smtp.example.com", password: REDACTED },
      "saml.signing.private.key": REDACTED,
    });
  });

  it("hides non-inert values under soft keys but keeps flags, timestamps, durations and algorithms", () => {
    const out = redactSecrets({
      "my.custom.token": "123456",
      refreshToken: "abc",
      "use.refresh.tokens": "true",
      "client.secret.creation.time": "1730000000",
      "access.token.lifespan": "300",
      accessTokenSignedResponseAlg: "RS256",
      tokenType: "Bearer",
      expiresInSeconds: 3600,
      someToken: null,
    });
    expect(out).toEqual({
      "my.custom.token": REDACTED,
      refreshToken: REDACTED,
      "use.refresh.tokens": "true",
      "client.secret.creation.time": "1730000000",
      "access.token.lifespan": "300",
      accessTokenSignedResponseAlg: "RS256",
      tokenType: "Bearer",
      expiresInSeconds: 3600,
      someToken: null,
    });
  });

  it("applies a soft key to everything beneath it", () => {
    expect(redactSecrets({ tokenSettings: { opaque: "v", flag: false, list: ["a", "b"] } })).toEqual({
      tokenSettings: { opaque: REDACTED, flag: false, list: [REDACTED, REDACTED] },
    });
  });

  it("replaces a PEM private key found under an innocuous key", () => {
    const out = redactSecrets({ notes: "x -----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----", pub: "-----BEGIN CERTIFICATE-----\nAAA" });
    expect(out.notes).toBe(REDACTED);
    expect(out.pub).toContain("BEGIN CERTIFICATE");
  });

  it("keeps passwordPolicy (configuration, not a password) and does not mutate its input", () => {
    const input = { passwordPolicy: "length(8) and digits(1)", nested: { secret: "s" } };
    const out = redactSecrets(input);
    expect(out.passwordPolicy).toBe("length(8) and digits(1)");
    expect(out.nested.secret).toBe(REDACTED);
    expect(input.nested.secret).toBe("s");
  });

  it("does not pass through structures nested beyond the depth limit", () => {
    let deep: Record<string, unknown> = { leaf: "LEAK-deep" };
    for (let i = 0; i < 30; i++) deep = { n: deep };
    expect(JSON.stringify(redactSecrets(deep))).not.toContain("LEAK-deep");
  });
});
