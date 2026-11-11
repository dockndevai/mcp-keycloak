import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { KeycloakClient } from "../src/keycloak/client.js";
import { REDACTED, redactErrorBody, redactSecrets } from "../src/redact.js";
import { buildServer } from "../src/server.js";

/**
 * Tuning of the deep redactor: secret-bearing names it used to miss (recovery codes, OTP blobs, dotted keys), and
 * public endpoint URLs it used to hide because the key name contains "authorization" / "token". Shapes follow the
 * Admin REST API representations (identity providers, LDAP components, realm, user, client); every secret is a
 * recognisable "LEAK-" string so a leak is obvious in a failing assertion.
 */
const config = (): AppConfig => ({
  connection: {
    baseUrl: "http://localhost:8080",
    authRealm: "master",
    auth: { kind: "client_credentials", clientId: "t", clientSecret: "s" },
    tlsRejectUnauthorized: true,
  },
  security: { mode: "read-only", realmAllowlist: [], protectedRealms: [], allowDelete: false, dryRun: false, auditLog: false, requireHumanApproval: false },
});

async function call(name: string, args: Record<string, unknown>) {
  const { server } = buildServer(config());
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  const res = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }> };
  const raw = res.content[0]?.text ?? "";
  return { raw, json: () => JSON.parse(raw) as any };
}

afterEach(() => vi.restoreAllMocks());

const oidcIdp = {
  alias: "corp-oidc",
  displayName: "Corporate SSO",
  providerId: "oidc",
  enabled: true,
  trustEmail: false,
  storeToken: false,
  addReadTokenRoleOnCreate: false,
  config: {
    authorizationUrl: "https://login.example-idp.com/oauth2/v2.0/authorize",
    tokenUrl: "https://login.example-idp.com/oauth2/v2.0/token",
    userInfoUrl: "https://graph.example-idp.com/oidc/userinfo",
    logoutUrl: "https://login.example-idp.com/oauth2/v2.0/logout",
    jwksUrl: "https://login.example-idp.com/discovery/v2.0/keys",
    issuer: "https://login.example-idp.com/tenant-id/v2.0",
    clientId: "keycloak-broker",
    clientSecret: "LEAK-idp-client-secret",
    clientAuthMethod: "client_secret_post",
    defaultScope: "openid profile email",
    validateSignature: "true",
    useJwksUrl: "true",
    pkceEnabled: "true",
    pkceMethod: "S256",
    syncMode: "IMPORT",
  },
};

const samlIdp = {
  alias: "partner-saml",
  providerId: "saml",
  enabled: true,
  config: {
    singleSignOnServiceUrl: "https://sso.partner.example/saml2/sso",
    singleLogoutServiceUrl: "https://sso.partner.example/saml2/slo",
    entityId: "https://sso.partner.example/metadata",
    signingCertificate: "MIIC-public-signing-cert",
    postBindingAuthnRequest: "true",
    wantAssertionsSigned: "true",
    nameIDPolicyFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:persistent",
  },
};

const ldapComponent = {
  id: "c1",
  name: "corp-ldap",
  providerId: "ldap",
  providerType: "org.keycloak.storage.UserStorageProvider",
  config: {
    connectionUrl: ["ldaps://ldap.example.com:636"],
    bindDn: ["cn=svc-keycloak,ou=services,dc=example,dc=com"],
    bindCredential: ["LEAK-ldap-bind-credential"],
    authType: ["simple"],
    usersDn: ["ou=people,dc=example,dc=com"],
    startTls: ["false"],
    useTruststoreSpi: ["ldapsOnly"],
    editMode: ["READ_ONLY"],
  },
};

const realm = {
  realm: "demo",
  enabled: true,
  smtpServer: { host: "smtp.example.com", port: "587", from: "no-reply@example.com", auth: "true", user: "mailer", password: "LEAK-smtp-password" },
  otpPolicyType: "totp",
  otpPolicyAlgorithm: "HmacSHA1",
  otpPolicyDigits: 6,
  otpPolicyPeriod: 30,
  passwordPolicy: "length(12)",
  codeSecret: "LEAK-code-secret",
  attributes: { "recovery.codes.enabled": "true", frontendUrl: "https://sso.example.com" },
  identityProviders: [oidcIdp, samlIdp],
  components: { "org.keycloak.storage.UserStorageProvider": [ldapComponent] },
};

describe("secret-bearing names that used to be missed", () => {
  it("hides recovery / backup codes however the key is spelled, even when the value is a number or a list", () => {
    const out = redactSecrets({
      "recovery.codes": ["LEAK-1", "LEAK-2"],
      recoveryCodes: "LEAK-3",
      "recovery-authn-codes": ["LEAK-4"],
      recovery_authn_codes: 12345678,
      backupCodes: ["LEAK-5"],
      attributes: { "backup.codes": "LEAK-6", scratchCodes: ["LEAK-7"] },
      recoveryCodesConfig: { codes: ["LEAK-8"], generated: true, count: 12 },
    });
    expect(JSON.stringify(out)).not.toContain("LEAK-");
    expect(out["recovery_authn_codes"]).toBe(REDACTED);
    // flags and counts next to them stay readable
    expect(out.recoveryCodesConfig).toEqual({ codes: [REDACTED], generated: true, count: 12 });
  });

  it("hides TOTP / OTP credential blobs but keeps the user's `totp` flag and the realm OTP policy", () => {
    const out = redactSecrets({
      totp: false,
      otpPolicyType: "totp",
      otpPolicyAlgorithm: "HmacSHA256",
      otpPolicyDigits: 6,
      otpPolicyPeriod: 30,
      otpSecret: "LEAK-otp-secret",
      totpValue: "LEAK-totp-value",
      userTotp: { secretData: "{\"value\":\"LEAK-secret-data\"}", credentialData: "{\"digits\":6}" },
      otp: "LEAK-123456",
      credentials: [{ type: "otp", secretData: "LEAK-x", credentialData: "LEAK-y" }],
    });
    expect(JSON.stringify(out)).not.toContain("LEAK-");
    expect(out.totp).toBe(false);
    expect(out.otpPolicyType).toBe("totp");
    expect(out.otpPolicyAlgorithm).toBe("HmacSHA256");
    expect(out.otpPolicyDigits).toBe(6);
    expect(out.otpPolicyPeriod).toBe(30);
  });

  it("hides dotted / nested password keys and the credential names Keycloak uses", () => {
    const out = redactSecrets({
      "smtp.password": "LEAK-a",
      "config.smtp.password": "LEAK-b",
      smtpServer: { password: "LEAK-c", host: "smtp.example.com" },
      bindCredential: ["LEAK-d"],
      clientSecret: "LEAK-e",
      registrationAccessToken: "LEAK-f",
      initialAccessToken: "LEAK-g",
      "initial.access.token": 1234567890,
      bindDn: ["cn=admin,dc=example,dc=com"],
    });
    expect(JSON.stringify(out)).not.toContain("LEAK-");
    expect(out["initial.access.token"]).toBe(REDACTED);
    expect(out.smtpServer.host).toBe("smtp.example.com");
    expect(out.bindDn).toEqual(["cn=admin,dc=example,dc=com"]);
  });

  it("does not mistake words that merely contain these names (word-aware)", () => {
    const out = redactSecrets({
      photo: "https://cdn.example.com/p.png", // 'otp' inside a word is not an OTP key
      hotpotato: "keep",
      recoveryEmail: "user@example.com",
      codesOfConduct: "https://example.com/conduct",
      backupLocation: "eu-west",
    });
    expect(out).toEqual({
      photo: "https://cdn.example.com/p.png",
      hotpotato: "keep",
      recoveryEmail: "user@example.com",
      codesOfConduct: "https://example.com/conduct",
      backupLocation: "eu-west",
    });
  });
});

describe("endpoint URLs stay readable (unless they embed a credential)", () => {
  it("keeps the public endpoints of an OIDC and a SAML identity provider while still hiding the client secret", () => {
    const out = redactSecrets({ idps: [oidcIdp, samlIdp] }) as { idps: Array<typeof oidcIdp> };
    const c = out.idps[0]!.config;
    expect(c.authorizationUrl).toBe(oidcIdp.config.authorizationUrl);
    expect(c.tokenUrl).toBe(oidcIdp.config.tokenUrl);
    expect(c.userInfoUrl).toBe(oidcIdp.config.userInfoUrl);
    expect(c.logoutUrl).toBe(oidcIdp.config.logoutUrl);
    expect(c.jwksUrl).toBe(oidcIdp.config.jwksUrl);
    expect(c.clientSecret).toBe(REDACTED);
    expect(JSON.stringify(out)).not.toContain("LEAK-");
    expect(out.idps[1]!.config).toEqual(samlIdp.config);
  });

  it("keeps endpoint-named fields in the other spellings Keycloak and OIDC discovery use", () => {
    const urls = {
      authorization_endpoint: "https://idp.example.com/auth?client_id=web&response_type=code&scope=openid&code_challenge_method=S256",
      token_endpoint: "https://idp.example.com/token",
      "token.url": "https://idp.example.com/token",
      tokenEndpointUrl: "ldap://ldap.example.com:389",
      authorizationServerUri: "https://idp.example.com",
      "access.token.endpoint": "https://idp.example.com/tokens",
      tokenUrls: ["https://a.example.com/token", "https://b.example.com/token"],
    };
    expect(redactSecrets(urls)).toEqual(urls);
  });

  it("still hides a URL that embeds a credential: userinfo, a secret-named query/fragment parameter, a JWT", () => {
    const bad = {
      tokenUrl: "https://svc:LEAK-pw@idp.example.com/token",
      authorizationUrl: "https://idp.example.com/auth?client_secret=LEAK-1",
      userInfoUrl: "https://idp.example.com/userinfo?access_token=LEAK-2",
      logoutUrl: "https://idp.example.com/logout?id_token_hint=LEAK-3",
      jwksUrl: "https://idp.example.com/jwks?api_key=LEAK-4",
      tokenEndpoint: "https://idp.example.com/cb#access_token=LEAK-5&state=x",
      authorizationEndpoint: "https://idp.example.com/auth?code=LEAK-6",
      "token.url": "https://idp.example.com/t?sig=LEAK-7",
      tokenUri: "https://idp.example.com/t?Password=LEAK-8",
      authorizationServerUrl: "https://idp.example.com/cb#LEAK-opaque-fragment",
      anotherTokenUrl: "https://idp.example.com/x/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJMRUFLIn0.sigsig",
      tokenUrlWithKey: "https://idp.example.com/t?x-api-key=LEAK-9",
    };
    expect(JSON.stringify(redactSecrets(bad))).not.toContain("LEAK-");
    expect(JSON.stringify(redactSecrets(bad))).not.toContain("eyJ");
  });

  it("only exempts URL-shaped values under URL-named keys: a non-URL or a non-URL key stays hidden", () => {
    const out = redactSecrets({
      tokenUrl: "LEAK-not-a-url",
      authorizationUrl: "javascript:alert('LEAK-js')",
      tokenEndpoint: "file:///etc/LEAK-passwd",
      refreshToken: "https://idp.example.com/looks-like-a-url-but-is-a-token",
      "my.custom.token": "https://idp.example.com/x",
    });
    expect(JSON.stringify(out)).not.toContain("LEAK-");
    expect(out.refreshToken).toBe(REDACTED);
    expect(out["my.custom.token"]).toBe(REDACTED);
  });

  it("a HARD key is never exempt, even with a URL-looking value", () => {
    expect(redactSecrets({ clientSecret: "https://idp.example.com/x", "api.key": "https://x.example.com" })).toEqual({
      clientSecret: REDACTED,
      "api.key": REDACTED,
    });
  });

  it("a PEM private key under a URL-named key is still hidden", () => {
    const out = redactSecrets({ tokenUrl: "https://x.example.com -----BEGIN PRIVATE KEY-----\nLEAK\n-----END PRIVATE KEY-----" });
    expect(out.tokenUrl).toBe(REDACTED);
  });
});

describe("through the tools", () => {
  it("get_realm: identity-provider endpoints and LDAP connection settings are readable; every secret is hidden", async () => {
    vi.spyOn(KeycloakClient.prototype, "getRealm").mockResolvedValue({ status: 200, data: realm } as never);
    const { raw, json } = await call("get_realm", { realm: "demo" });
    expect(raw).not.toContain("LEAK-");
    const r = json();
    expect(r.identityProviders[0].config.authorizationUrl).toBe(oidcIdp.config.authorizationUrl);
    expect(r.identityProviders[0].config.tokenUrl).toBe(oidcIdp.config.tokenUrl);
    expect(r.identityProviders[0].config.userInfoUrl).toBe(oidcIdp.config.userInfoUrl);
    expect(r.identityProviders[0].config.clientId).toBe("keycloak-broker");
    expect(r.identityProviders[0].config.clientSecret).toBe(REDACTED);
    expect(r.identityProviders[1].config).toEqual(samlIdp.config);
    const ldap = r.components["org.keycloak.storage.UserStorageProvider"][0].config;
    expect(ldap.connectionUrl).toEqual(["ldaps://ldap.example.com:636"]);
    expect(ldap.bindDn).toEqual(["cn=svc-keycloak,ou=services,dc=example,dc=com"]);
    expect(ldap.bindCredential).toEqual(REDACTED);
    expect(r.smtpServer).toMatchObject({ host: "smtp.example.com", user: "mailer", password: REDACTED });
    expect(r.otpPolicyType).toBe("totp");
    expect(r.attributes["recovery.codes.enabled"]).toBe("true");
    expect(r.attributes.frontendUrl).toBe("https://sso.example.com");
  });

  it("get_user: recovery codes and OTP blobs under free-form attributes and credentials are hidden", async () => {
    vi.spyOn(KeycloakClient.prototype, "getUser").mockResolvedValue({
      status: 200,
      data: {
        id: "u1",
        username: "alice",
        totp: true,
        attributes: { "recovery.codes": ["LEAK-r1", "LEAK-r2"], department: ["Engineering"], otpSecret: ["LEAK-o"] },
        credentials: [{ type: "otp", secretData: "LEAK-s" }],
      },
    } as never);
    const { raw, json } = await call("get_user", { realm: "demo", userId: "u1" });
    expect(raw).not.toContain("LEAK-");
    expect(json().totp).toBe(true);
    expect(json().attributes.department).toEqual(["Engineering"]);
  });
});

describe("documented limit: a secret under an innocuous key is NOT caught", () => {
  it("passes a secret stored under a plain key name through unchanged (name-based redaction is a safety net, not a guarantee)", () => {
    const out = redactSecrets({
      notes: "the vault pin is 4821-LEAK",
      attributes: { "emergency.access": "LEAK-emergency-phrase", webhook: "https://hooks.example.com/services/T000/B000/LEAK-path-secret" },
      tokenUrl: "https://hooks.example.com/services/T000/B000/LEAK-path-secret",
    });
    // These are NOT redacted and this test exists so nobody documents otherwise: see SECURITY.md.
    expect(out.notes).toContain("LEAK");
    expect(out.attributes["emergency.access"]).toBe("LEAK-emergency-phrase");
    expect(out.attributes.webhook).toContain("LEAK-path-secret");
    // A secret carried in a URL PATH under a URL-named key is not detected either.
    expect(out.tokenUrl).toContain("LEAK-path-secret");
  });
});

describe("error bodies stay conservative", () => {
  it("still hides secrets in a JSON error body (URL fields there are also hidden by the text pass)", () => {
    const body = JSON.stringify({ error: "invalid", recoveryCodes: ["LEAK-1"], clientSecret: "LEAK-2", tokenUrl: "https://idp.example.com/token?client_secret=LEAK-3" });
    expect(redactErrorBody(body)).not.toContain("LEAK-");
  });
});
