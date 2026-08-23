import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

/**
 * Admin tools are the most privileged. They are only registered when
 * KEYCLOAK_MODE=admin, and the destructive ones additionally require
 * KEYCLOAK_ALLOW_DELETE=true.
 */
export const adminTools: ToolDef[] = [
  {
    name: "delete_user",
    capability: "admin",
    config: {
      title: "Delete user",
      description:
        "Permanently delete a user from a realm. Requires admin mode AND KEYCLOAK_ALLOW_DELETE=true. Irreversible.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        userId: z.string().describe("Keycloak user id (UUID)"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      const userId = args.userId as string;
      const { dryRun } = policy.guard({
        tool: "delete_user",
        capability: "admin",
        realm,
        destructive: true,
      });
      if (dryRun) return textResult(`[dry-run] Would delete user ${userId} in '${realm}'.`);
      await client.deleteUser(realm, userId);
      return jsonResult({ deleted: true, realm, userId });
    },
  },
];
