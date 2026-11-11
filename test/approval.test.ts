import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { AppConfig } from "../src/config.js";
import { KeycloakClient, KeycloakError } from "../src/keycloak/client.js";
import { buildServer } from "../src/server.js";

const config = (requireHumanApproval = false): AppConfig => ({
  connection: {
    baseUrl: "http://localhost:8080",
    authRealm: "master",
    auth: { kind: "client_credentials", clientId: "t", clientSecret: "s" },
    tlsRejectUnauthorized: true,
  },
  security: {
    mode: "admin",
    realmAllowlist: [],
    protectedRealms: ["master"],
    allowDelete: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval,
  },
});

type Answer = { action: "accept" | "decline"; content?: Record<string, unknown> };

/** Connect an in-memory MCP client (optionally able to answer elicitation) to a freshly built server. */
async function connect(opts: { requireHuman?: boolean; answer?: (message: string) => Answer | Promise<Answer>; elicits?: boolean }) {
  const { server } = buildServer(config(opts.requireHuman));
  const prompts: string[] = [];
  const client = new Client({ name: "t", version: "0" }, { capabilities: opts.elicits === false ? {} : { elicitation: {} } });
  if (opts.elicits !== false) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      prompts.push(req.params.message);
      return (await opts.answer?.(req.params.message)) ?? { action: "accept", content: { confirm: true } };
    });
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, prompts };
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

/** Fake value for the new credential; only used to prove it never reaches the prompt or the result. */
const NEW_VALUE = ["fake", "value", "for", "test"].join("-");

afterEach(() => vi.restoreAllMocks());

describe("delete_user approval (end to end)", () => {
  const args = { realm: "acme", userId: "u-1" };

  it("shows the tool, full arguments, version and fingerprint, then deletes", async () => {
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockResolvedValue("v1");
    const del = vi.spyOn(KeycloakClient.prototype, "deleteUser").mockResolvedValue({ status: 204, data: undefined });
    const { client, prompts } = await connect({});
    const res = await client.callTool({ name: "delete_user", arguments: args });
    expect(text(res)).toContain('"deleted": true');
    expect(del).toHaveBeenCalledWith("acme", "u-1");
    expect(prompts[0]).toContain("tool: delete_user");
    expect(prompts[0]).toContain('{"realm":"acme","userId":"u-1"}');
    expect(prompts[0]).toContain("resource version: v1");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });

  it("does NOT delete when the user changed while the human was deciding", async () => {
    const versions = ["v1", "v2"];
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(KeycloakClient.prototype, "deleteUser").mockResolvedValue({ status: 204, data: undefined });
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_user", arguments: args });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the human declines", async () => {
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockResolvedValue("v1");
    const del = vi.spyOn(KeycloakClient.prototype, "deleteUser").mockResolvedValue({ status: 204, data: undefined });
    const { client } = await connect({ answer: () => ({ action: "decline" }) });
    await client.callTool({ name: "delete_user", arguments: args });
    expect(del).not.toHaveBeenCalled();
  });

  it("protected realms are still refused before any prompt", async () => {
    const probe = vi.spyOn(KeycloakClient.prototype, "userVersion").mockResolvedValue("v1");
    const del = vi.spyOn(KeycloakClient.prototype, "deleteUser").mockResolvedValue({ status: 204, data: undefined });
    const { client, prompts } = await connect({});
    const res = await client.callTool({ name: "delete_user", arguments: { realm: "master", userId: "u-1" } });
    expect(text(res)).toContain("protected");
    expect(prompts).toHaveLength(0);
    expect(probe).not.toHaveBeenCalled();
    expect(del).not.toHaveBeenCalled();
  });
});

describe("KEYCLOAK_REQUIRE_HUMAN_APPROVAL", () => {
  const args = { realm: "acme", userId: "u-1" };

  it("falls back to the flags when the client cannot elicit (default)", async () => {
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockResolvedValue("v1");
    const del = vi.spyOn(KeycloakClient.prototype, "deleteUser").mockResolvedValue({ status: 204, data: undefined });
    const { client } = await connect({ elicits: false });
    await client.callTool({ name: "delete_user", arguments: args });
    expect(del).toHaveBeenCalledWith("acme", "u-1");
  });

  it("refuses to delete when the client cannot elicit and human approval is required", async () => {
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockResolvedValue("v1");
    const del = vi.spyOn(KeycloakClient.prototype, "deleteUser").mockResolvedValue({ status: 204, data: undefined });
    const { client } = await connect({ elicits: false, requireHuman: true });
    const res = await client.callTool({ name: "delete_user", arguments: args });
    expect(text(res)).toContain("no human approval channel");
    expect(del).not.toHaveBeenCalled();
  });
});

describe("reset_password and logout_user bind their version too", () => {
  it("reset_password never shows or echoes the password, and refuses when the user changed", async () => {
    const versions = ["v1", "v2"];
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockImplementation(async () => versions.shift());
    const reset = vi.spyOn(KeycloakClient.prototype, "resetPassword").mockResolvedValue({ status: 204, data: undefined });
    const { client, prompts } = await connect({});
    const res = await client.callTool({
      name: "reset_password",
      arguments: { realm: "acme", userId: "u-1", password: NEW_VALUE },
    });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(reset).not.toHaveBeenCalled();
    expect(prompts[0]).not.toContain(NEW_VALUE);
    expect(prompts[0]).toContain("[redacted]");
  });

  it("reset_password proceeds on a stable version and does not echo the password", async () => {
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockResolvedValue("v1");
    const reset = vi.spyOn(KeycloakClient.prototype, "resetPassword").mockResolvedValue({ status: 204, data: undefined });
    const { client } = await connect({});
    const res = await client.callTool({
      name: "reset_password",
      arguments: { realm: "acme", userId: "u-1", password: NEW_VALUE },
    });
    expect(reset).toHaveBeenCalledWith("acme", "u-1", NEW_VALUE, true);
    expect(text(res)).toContain('"passwordReset": true');
    expect(text(res)).not.toContain(NEW_VALUE);
  });

  it("logout_user refuses when the user changed", async () => {
    const versions = ["v1", "v2"];
    vi.spyOn(KeycloakClient.prototype, "userVersion").mockImplementation(async () => versions.shift());
    const logout = vi.spyOn(KeycloakClient.prototype, "logoutUser").mockResolvedValue({ status: 204, data: undefined });
    const { client } = await connect({});
    const res = await client.callTool({ name: "logout_user", arguments: { realm: "acme", userId: "u-1" } });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(logout).not.toHaveBeenCalled();
  });
});

describe("KeycloakClient.userVersion", () => {
  const client = new KeycloakClient(config().connection);
  const base = { id: "u-1", username: "ann", email: "a@x.io", enabled: true, createdTimestamp: 1, attributes: { team: ["a"] } };
  const stub = (user: Record<string, unknown>) =>
    vi.spyOn(KeycloakClient.prototype, "getUser").mockResolvedValue({ status: 200, data: user });

  it("is stable across volatile fields, key order and secret-looking fields", async () => {
    stub(base);
    const v = await client.userVersion("acme", "u-1");
    expect(v).toMatch(/^[0-9a-f]{12}$/);
    vi.restoreAllMocks();
    stub({
      attributes: { team: ["a"], apiToken: ["rotating"] },
      notBefore: 99,
      access: { manage: true },
      totp: true,
      disableableCredentialTypes: ["password"],
      createdTimestamp: 1,
      enabled: true,
      email: "a@x.io",
      username: "ann",
      id: "u-1",
    });
    expect(await client.userVersion("acme", "u-1")).toBe(v);
  });

  it("changes when the user's content changes", async () => {
    stub(base);
    const v = await client.userVersion("acme", "u-1");
    vi.restoreAllMocks();
    stub({ ...base, enabled: false });
    expect(await client.userVersion("acme", "u-1")).not.toBe(v);
  });

  it("returns undefined for a missing user and throws on other errors", async () => {
    vi.spyOn(KeycloakClient.prototype, "getUser").mockRejectedValue(new KeycloakError("nf", 404));
    expect(await client.userVersion("acme", "gone")).toBeUndefined();
    vi.restoreAllMocks();
    vi.spyOn(KeycloakClient.prototype, "getUser").mockRejectedValue(new KeycloakError("boom", 500));
    await expect(client.userVersion("acme", "u-1")).rejects.toThrow();
  });
});
