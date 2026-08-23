/**
 * Security policy engine.
 *
 * Behaviour is controlled entirely by flags (see config.ts). The engine decides:
 *   1. Which tools are even registered on the server (capability vs. access mode).
 *   2. Whether an individual call is permitted at runtime (realm scoping,
 *      protected-realm rules, destructive-op gating, dry-run).
 *
 * Keeping this logic pure (no I/O) makes it fully unit-testable.
 */

/** Capability a tool requires, ordered from least to most privileged. */
export type Capability = "read" | "write" | "admin";

/** Access mode the operator grants the server, ordered least to most privileged. */
export type AccessMode = "read-only" | "read-write" | "admin";

const MODE_RANK: Record<AccessMode, number> = {
  "read-only": 0,
  "read-write": 1,
  admin: 2,
};

const CAPABILITY_RANK: Record<Capability, number> = {
  read: 0,
  write: 1,
  admin: 2,
};

export interface SecurityConfig {
  /** Highest capability level the server is allowed to expose. */
  mode: AccessMode;
  /**
   * If set, only these realms may be touched (allowlist). Empty/undefined means
   * every realm the credentials can reach is permitted.
   */
  realmAllowlist: string[];
  /** Realms that can never be mutated or deleted, regardless of mode. */
  protectedRealms: string[];
  /** Destructive operations (delete_*) require this to be explicitly true. */
  allowDelete: boolean;
  /**
   * When true, write/admin operations are validated and logged but never sent
   * to Keycloak. Handy for previewing what an agent would do.
   */
  dryRun: boolean;
  /** Emit a structured audit line to stderr for every guarded operation. */
  auditLog: boolean;
}

/** Thrown when the policy rejects an operation. Surfaced to the model as an error. */
export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export interface GuardContext {
  /** Tool name, for audit lines and error messages. */
  tool: string;
  /** Capability the tool requires. */
  capability: Capability;
  /** Realm the operation targets, if any. */
  realm?: string;
  /** True for destructive delete operations, which need `allowDelete`. */
  destructive?: boolean;
}

export class SecurityPolicy {
  constructor(private readonly config: SecurityConfig) {}

  get mode(): AccessMode {
    return this.config.mode;
  }

  get dryRun(): boolean {
    return this.config.dryRun;
  }

  /**
   * Whether a tool of the given capability should be registered at all under
   * the current access mode. Read-only servers never even advertise write tools.
   */
  isCapabilityEnabled(capability: Capability): boolean {
    return CAPABILITY_RANK[capability] <= MODE_RANK[this.config.mode];
  }

  /** True if the named realm is in scope (allowlist check). */
  isRealmAllowed(realm: string): boolean {
    if (this.config.realmAllowlist.length === 0) return true;
    return this.config.realmAllowlist.includes(realm);
  }

  isRealmProtected(realm: string): boolean {
    return this.config.protectedRealms.includes(realm);
  }

  /**
   * Enforce policy for a single operation. Throws PolicyError on rejection.
   * Returns whether the caller should short-circuit as a dry run.
   */
  guard(ctx: GuardContext): { dryRun: boolean } {
    // 1. Capability must be permitted by the mode. This is a defence-in-depth
    //    check; disallowed tools are normally never registered.
    if (!this.isCapabilityEnabled(ctx.capability)) {
      this.audit(ctx, "DENY", `capability '${ctx.capability}' exceeds mode '${this.config.mode}'`);
      throw new PolicyError(
        `Operation '${ctx.tool}' requires '${ctx.capability}' access but the server runs in '${this.config.mode}' mode.`,
      );
    }

    // 2. Realm scoping.
    if (ctx.realm !== undefined) {
      if (!this.isRealmAllowed(ctx.realm)) {
        this.audit(ctx, "DENY", `realm '${ctx.realm}' not in allowlist`);
        throw new PolicyError(
          `Realm '${ctx.realm}' is not in the configured allowlist (KEYCLOAK_REALM_ALLOWLIST).`,
        );
      }
      // 3. Protected realms may be read but never mutated.
      if (ctx.capability !== "read" && this.isRealmProtected(ctx.realm)) {
        this.audit(ctx, "DENY", `realm '${ctx.realm}' is protected`);
        throw new PolicyError(
          `Realm '${ctx.realm}' is protected (KEYCLOAK_PROTECTED_REALMS); mutations are refused.`,
        );
      }
    }

    // 4. Destructive operations need an explicit opt-in beyond admin mode.
    if (ctx.destructive && !this.config.allowDelete) {
      this.audit(ctx, "DENY", "delete not enabled");
      throw new PolicyError(
        `Destructive operation '${ctx.tool}' is disabled. Set KEYCLOAK_ALLOW_DELETE=true to enable it.`,
      );
    }

    const dryRun = ctx.capability !== "read" && this.config.dryRun;
    this.audit(ctx, dryRun ? "DRY_RUN" : "ALLOW");
    return { dryRun };
  }

  private audit(ctx: GuardContext, decision: string, reason?: string): void {
    if (!this.config.auditLog) return;
    const line = {
      ts: new Date().toISOString(),
      audit: "keycloak-mcp",
      decision,
      tool: ctx.tool,
      capability: ctx.capability,
      realm: ctx.realm ?? null,
      destructive: ctx.destructive ?? false,
      ...(reason ? { reason } : {}),
    };
    // Audit goes to stderr so it never pollutes the stdio MCP channel.
    process.stderr.write(`${JSON.stringify(line)}\n`);
  }
}
