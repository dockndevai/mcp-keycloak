import { describe, expect, it } from "vitest";
import { PolicyError, SecurityPolicy, type SecurityConfig } from "../src/security.js";

function makePolicy(overrides: Partial<SecurityConfig> = {}): SecurityPolicy {
  return new SecurityPolicy({
    mode: "read-only",
    realmAllowlist: [],
    protectedRealms: ["master"],
    allowDelete: false,
    dryRun: false,
    auditLog: false,
    ...overrides,
  });
}

describe("capability gating by mode", () => {
  it("read-only enables only read tools", () => {
    const p = makePolicy({ mode: "read-only" });
    expect(p.isCapabilityEnabled("read")).toBe(true);
    expect(p.isCapabilityEnabled("write")).toBe(false);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });

  it("read-write enables read and write but not admin", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(p.isCapabilityEnabled("read")).toBe(true);
    expect(p.isCapabilityEnabled("write")).toBe(true);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });

  it("admin enables everything", () => {
    const p = makePolicy({ mode: "admin" });
    expect(p.isCapabilityEnabled("admin")).toBe(true);
  });
});

describe("guard: capability vs mode", () => {
  it("rejects a write in read-only mode", () => {
    const p = makePolicy({ mode: "read-only" });
    expect(() => p.guard({ tool: "create_user", capability: "write", realm: "app" })).toThrow(
      PolicyError,
    );
  });

  it("allows a read in read-only mode", () => {
    const p = makePolicy({ mode: "read-only" });
    expect(() => p.guard({ tool: "list_users", capability: "read", realm: "app" })).not.toThrow();
  });
});

describe("realm allowlist", () => {
  it("empty allowlist permits any realm", () => {
    const p = makePolicy({ realmAllowlist: [] });
    expect(p.isRealmAllowed("anything")).toBe(true);
  });

  it("non-empty allowlist blocks realms outside it", () => {
    const p = makePolicy({ mode: "read-write", realmAllowlist: ["app", "customers"] });
    expect(() => p.guard({ tool: "get_realm", capability: "read", realm: "secret" })).toThrow(
      /allowlist/,
    );
    expect(() => p.guard({ tool: "get_realm", capability: "read", realm: "app" })).not.toThrow();
  });
});

describe("protected realms", () => {
  it("allows reading a protected realm", () => {
    const p = makePolicy({ mode: "admin" });
    expect(() => p.guard({ tool: "get_realm", capability: "read", realm: "master" })).not.toThrow();
  });

  it("blocks mutating a protected realm even in admin mode", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true });
    expect(() =>
      p.guard({ tool: "create_user", capability: "write", realm: "master" }),
    ).toThrow(/protected/);
  });
});

describe("destructive gating", () => {
  it("blocks delete when allowDelete is false", () => {
    const p = makePolicy({ mode: "admin", allowDelete: false });
    expect(() =>
      p.guard({ tool: "delete_user", capability: "admin", realm: "app", destructive: true }),
    ).toThrow(/ALLOW_DELETE/);
  });

  it("permits delete when allowDelete is true", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true });
    expect(() =>
      p.guard({ tool: "delete_user", capability: "admin", realm: "app", destructive: true }),
    ).not.toThrow();
  });
});

describe("dry run", () => {
  it("marks write operations as dry-run but not reads", () => {
    const p = makePolicy({ mode: "read-write", dryRun: true });
    expect(p.guard({ tool: "list_users", capability: "read", realm: "app" }).dryRun).toBe(false);
    expect(p.guard({ tool: "create_user", capability: "write", realm: "app" }).dryRun).toBe(true);
  });
});
