import type { ZodRawShape } from "zod";
import type { KeycloakClient } from "../keycloak/client.js";
import type { Capability, SecurityPolicy } from "../security.js";

export interface ToolContext {
  client: KeycloakClient;
  policy: SecurityPolicy;
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  // The MCP SDK's CallToolResult carries an open index signature; mirror it so
  // our handlers are assignable to registerTool without casts.
  [key: string]: unknown;
}

/** A tool definition tagged with the capability it requires. */
export interface ToolDef<Shape extends ZodRawShape = ZodRawShape> {
  name: string;
  capability: Capability;
  /** Marks a mutating tool as destructive (data loss possible). Defaults to `capability === "admin"`. */
  destructive?: boolean;
  /** Overrides the idempotency hint. Defaults to `true` for read tools, `false` otherwise. */
  idempotent?: boolean;
  config: {
    title: string;
    description: string;
    inputSchema: Shape;
  };
  handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<ToolResult>;
}

/** Render any JSON-serialisable value as a text tool result. */
export function jsonResult(value: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

export function textResult(text: string): ToolResult {
  return { content: [{ type: "text", text }] };
}
