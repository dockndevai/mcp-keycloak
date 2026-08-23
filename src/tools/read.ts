import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult } from "./types.js";

export const readTools: ToolDef[] = [
  {
    name: "list_realms",
    capability: "read",
    config: {
      title: "List realms",
      description:
        "List all realms visible to the configured credentials. Realms outside the allowlist are filtered out.",
      inputSchema: {},
    },
    handler: async (_args, { client, policy }) => {
      policy.guard({ tool: "list_realms", capability: "read" });
      const { data } = await client.listRealms();
      const filtered = (data ?? [])
        .filter((r) => policy.isRealmAllowed(r.realm))
        .map((r) => ({
          realm: r.realm,
          enabled: r.enabled,
          protected: policy.isRealmProtected(r.realm),
        }));
      return jsonResult(filtered);
    },
  },
  {
    name: "get_realm",
    capability: "read",
    config: {
      title: "Get realm settings",
      description: "Fetch the configuration of a single realm.",
      inputSchema: { realm: z.string().describe("Realm name") },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "get_realm", capability: "read", realm });
      const { data } = await client.getRealm(realm);
      return jsonResult(data);
    },
  },
  {
    name: "list_users",
    capability: "read",
    config: {
      title: "List / search users",
      description:
        "List users in a realm. Supports free-text search and pagination. Passwords and secrets are never returned by Keycloak.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        search: z
          .string()
          .optional()
          .describe("Free-text search across username, email, first and last name"),
        first: z.number().int().min(0).optional().describe("Pagination offset"),
        max: z.number().int().min(1).max(500).optional().describe("Max results (default 50)"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "list_users", capability: "read", realm });
      const { data } = await client.listUsers(realm, {
        search: args.search as string | undefined,
        first: args.first as number | undefined,
        max: (args.max as number | undefined) ?? 50,
      });
      return jsonResult(data);
    },
  },
  {
    name: "get_user",
    capability: "read",
    config: {
      title: "Get user by id",
      description: "Fetch a single user representation by their Keycloak id.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        userId: z.string().describe("Keycloak user id (UUID)"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "get_user", capability: "read", realm });
      const { data } = await client.getUser(realm, args.userId as string);
      return jsonResult(data);
    },
  },
  {
    name: "count_users",
    capability: "read",
    config: {
      title: "Count users",
      description: "Return the number of users in a realm, optionally matching a search term.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        search: z.string().optional().describe("Optional search term"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "count_users", capability: "read", realm });
      const { data } = await client.countUsers(realm, { search: args.search as string | undefined });
      return jsonResult({ realm, count: data });
    },
  },
  {
    name: "list_clients",
    capability: "read",
    config: {
      title: "List clients",
      description: "List OAuth/OIDC clients configured in a realm. Client secrets are not included.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        clientId: z.string().optional().describe("Filter by clientId"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "list_clients", capability: "read", realm });
      const { data } = await client.listClients(realm, {
        clientId: args.clientId as string | undefined,
      });
      // Strip anything secret-shaped defensively.
      const safe = (data ?? []).map((c) => {
        const { secret, ...rest } = c as Record<string, unknown>;
        return rest;
      });
      return jsonResult(safe);
    },
  },
  {
    name: "list_realm_roles",
    capability: "read",
    config: {
      title: "List realm roles",
      description: "List the realm-level roles defined in a realm.",
      inputSchema: { realm: z.string().describe("Realm name") },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "list_realm_roles", capability: "read", realm });
      const { data } = await client.listRealmRoles(realm);
      return jsonResult(data);
    },
  },
  {
    name: "list_groups",
    capability: "read",
    config: {
      title: "List groups",
      description: "List groups in a realm.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        search: z.string().optional().describe("Optional search term"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      policy.guard({ tool: "list_groups", capability: "read", realm });
      const { data } = await client.listGroups(realm, {
        search: args.search as string | undefined,
      });
      return jsonResult(data);
    },
  },
];
