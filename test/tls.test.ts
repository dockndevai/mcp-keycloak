import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { KeycloakConnection } from "../src/config.js";
import { KeycloakClient } from "../src/keycloak/client.js";

/**
 * KEYCLOAK_TLS_REJECT_UNAUTHORIZED=false must relax certificate checks for requests to Keycloak ONLY.
 * Previously the client set NODE_TLS_REJECT_UNAUTHORIZED=0, which switches verification off for every
 * outbound TLS connection in the process (the laya-guard daemon call, anything else using fetch/https).
 *
 * The server below presents a self-signed certificate, so "does a connection to it succeed?" is a direct
 * probe of whether verification is on for that caller.
 */

let dir: string;
let server: Server;
let base: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "kc-tls-"));
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
    { stdio: "ignore" },
  );
  server = createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) }, (req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url?.includes("/protocol/openid-connect/token")) res.end(JSON.stringify({ access_token: "tok", expires_in: 300 }));
    else if (req.url === "/admin/realms") res.end(JSON.stringify([{ realm: "demo", enabled: true, id: "1" }]));
    else res.end("{}");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

const envBefore = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
afterEach(() => {
  // Never let a failing assertion (or the old behaviour) leak process-wide TLS state into other tests.
  if (envBefore === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = envBefore;
  vi.restoreAllMocks();
});

const conn = (tlsRejectUnauthorized: boolean): KeycloakConnection => ({
  baseUrl: base,
  authRealm: "master",
  auth: { kind: "client_credentials", clientId: "c", clientSecret: "s" },
  tlsRejectUnauthorized,
});

describe("KEYCLOAK_TLS_REJECT_UNAUTHORIZED=false is scoped to the Keycloak client", () => {
  it("the verifying client rejects the self-signed server (baseline)", async () => {
    await expect(new KeycloakClient(conn(true)).listRealms()).rejects.toThrow();
  });

  it("the non-verifying client reaches it (token + admin request)", async () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const { data } = await new KeycloakClient(conn(false)).listRealms();
    expect(data).toEqual([{ realm: "demo", enabled: true, id: "1" }]);
  });

  it("keeps the loud warning", () => {
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    new KeycloakClient(conn(false));
    expect(write.mock.calls.map((c) => String(c[0])).join("")).toContain("TLS certificate verification is DISABLED");
  });

  it("does not switch verification off process-wide: NODE_TLS_REJECT_UNAUTHORIZED is untouched", () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    new KeycloakClient(conn(false));
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBeUndefined();
  });

  it("other callers in the process still verify certificates after a non-verifying client exists", async () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const kc = new KeycloakClient(conn(false));
    await kc.listRealms(); // the client works against the self-signed server...
    await expect(fetch(`${base}/anything`)).rejects.toThrow(); // ...but a plain fetch to it is still refused
  });

  it("does not replace the global fetch", () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const f = globalThis.fetch;
    new KeycloakClient(conn(false));
    expect(globalThis.fetch).toBe(f);
  });
});
