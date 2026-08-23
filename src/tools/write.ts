import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

export const writeTools: ToolDef[] = [
  {
    name: "create_user",
    capability: "write",
    config: {
      title: "Create user",
      description:
        "Create a new user in a realm. The user is created enabled unless specified otherwise. " +
        "Set a password separately with reset_password.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        username: z.string().describe("Username (must be unique in the realm)"),
        email: z.string().email().optional().describe("Email address"),
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        enabled: z.boolean().optional().describe("Whether the account is enabled (default true)"),
        emailVerified: z.boolean().optional(),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      const { dryRun } = policy.guard({ tool: "create_user", capability: "write", realm });
      const user = {
        username: args.username as string,
        email: args.email as string | undefined,
        firstName: args.firstName as string | undefined,
        lastName: args.lastName as string | undefined,
        enabled: (args.enabled as boolean | undefined) ?? true,
        emailVerified: args.emailVerified as boolean | undefined,
      };
      if (dryRun) return textResult(`[dry-run] Would create user in '${realm}': ${JSON.stringify(user)}`);
      const { location } = await client.createUser(realm, user);
      const id = location?.split("/").pop();
      return jsonResult({ created: true, realm, userId: id ?? null, username: user.username });
    },
  },
  {
    name: "update_user",
    capability: "write",
    config: {
      title: "Update user",
      description:
        "Patch an existing user. Only provided fields are changed. Use enabled=false to disable an account.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        userId: z.string().describe("Keycloak user id (UUID)"),
        email: z.string().email().optional(),
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        enabled: z.boolean().optional().describe("Enable or disable the account"),
        emailVerified: z.boolean().optional(),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      const userId = args.userId as string;
      const { dryRun } = policy.guard({ tool: "update_user", capability: "write", realm });
      const patch: Record<string, unknown> = {};
      for (const k of ["email", "firstName", "lastName", "enabled", "emailVerified"]) {
        if (args[k] !== undefined) patch[k] = args[k];
      }
      if (dryRun)
        return textResult(`[dry-run] Would update user ${userId} in '${realm}': ${JSON.stringify(patch)}`);
      await client.updateUser(realm, userId, patch);
      return jsonResult({ updated: true, realm, userId, fields: Object.keys(patch) });
    },
  },
  {
    name: "reset_password",
    capability: "write",
    config: {
      title: "Reset user password",
      description:
        "Set a user's password. By default the password is temporary and must be changed at next login.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        userId: z.string().describe("Keycloak user id (UUID)"),
        password: z.string().min(1).describe("The new password value"),
        temporary: z
          .boolean()
          .optional()
          .describe("If true (default), user must change it at next login"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      const userId = args.userId as string;
      const temporary = (args.temporary as boolean | undefined) ?? true;
      const { dryRun } = policy.guard({ tool: "reset_password", capability: "write", realm });
      if (dryRun)
        return textResult(
          `[dry-run] Would set a ${temporary ? "temporary" : "permanent"} password for user ${userId} in '${realm}'.`,
        );
      await client.resetPassword(realm, userId, args.password as string, temporary);
      // Never echo the password back.
      return jsonResult({ passwordReset: true, realm, userId, temporary });
    },
  },
  {
    name: "logout_user",
    capability: "write",
    config: {
      title: "Log user out of all sessions",
      description: "Revoke all active sessions for a user, forcing re-authentication.",
      inputSchema: {
        realm: z.string().describe("Realm name"),
        userId: z.string().describe("Keycloak user id (UUID)"),
      },
    },
    handler: async (args, { client, policy }) => {
      const realm = args.realm as string;
      const userId = args.userId as string;
      const { dryRun } = policy.guard({ tool: "logout_user", capability: "write", realm });
      if (dryRun) return textResult(`[dry-run] Would revoke all sessions for user ${userId} in '${realm}'.`);
      await client.logoutUser(realm, userId);
      return jsonResult({ loggedOut: true, realm, userId });
    },
  },
];
