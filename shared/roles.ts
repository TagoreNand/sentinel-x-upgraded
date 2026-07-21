/**
 * Role-based access control primitives, shared by the Drizzle schema (which
 * defines the DB enum from ROLES) and the tRPC authorization middleware.
 *
 * The hierarchy is TOTALLY ORDERED — a higher tier is a strict superset of a
 * lower tier's permissions — so authorization is a single rank comparison,
 * not a permission matrix. This keeps "who can do what" auditable at a glance
 * and makes it impossible to accidentally grant a capability to `analyst`
 * without also granting it to `lead`/`admin`.
 *
 * Tiers:
 * - viewer:  read-only. Dashboards, lists, case overviews. No mutations.
 * - analyst: day-to-day SOC work — ingest events, open/triage incidents,
 *            record evidence & custody, curate IOCs, run vuln scans,
 *            analyze phishing.
 * - lead:    PRIVILEGED. Authors IDS detection rules (whose regex/logic the
 *            ingestion pipeline executes) and creates/executes SOAR
 *            playbooks (automated response). These are the capabilities that
 *            let a principal change what the platform DOES, not just what it
 *            records — so they sit above analyst.
 * - admin:   platform governance — user role management, audit log access,
 *            demo/destructive operations.
 *
 * This module has NO runtime dependencies so it is importable from the
 * Drizzle schema (via a relative path, to stay clear of build-time path-alias
 * resolution in drizzle-kit) and from server middleware alike.
 */

export const ROLES = ["viewer", "analyst", "lead", "admin"] as const;

export type Role = (typeof ROLES)[number];

/** Ascending privilege. Comparisons use this, never string equality on a tier. */
export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  analyst: 1,
  lead: 2,
  admin: 3,
};

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** True when `actual` satisfies the `required` minimum tier (or exceeds it). */
export function roleAtLeast(actual: Role, required: Role): boolean {
  return ROLE_RANK[actual] >= ROLE_RANK[required];
}

export type RoleAssignmentDecision = { ok: true } | { ok: false; reason: string };

/**
 * Pure policy for admin-initiated role changes. Kept separate from the tRPC
 * layer so every guard is unit-testable without a request context, and so
 * the invariants are stated in one place:
 *
 * - Only an admin may assign roles (the calling procedure also enforces this;
 *   defense in depth, since a policy that trusts its caller is one refactor
 *   away from a privilege-escalation bug).
 * - The target role must be a real tier.
 * - An admin cannot change their OWN role — prevents accidental self-lockout
 *   (demoting away your last admin) and self-promotion loops.
 * - The configured owner is a permanent admin anchor and cannot be demoted;
 *   there must always be at least one route back to admin.
 */
export function assertRoleAssignable(params: {
  actorRole: Role;
  actorUserId: number;
  targetUserId: number;
  targetOpenId: string;
  ownerOpenId: string;
  newRole: string;
}): RoleAssignmentDecision {
  if (params.actorRole !== "admin") {
    return { ok: false, reason: "Only admins can change user roles" };
  }
  if (!isRole(params.newRole)) {
    return { ok: false, reason: `Unknown role: ${params.newRole}` };
  }
  if (params.actorUserId === params.targetUserId) {
    return { ok: false, reason: "Admins cannot change their own role" };
  }
  if (params.ownerOpenId && params.targetOpenId === params.ownerOpenId && params.newRole !== "admin") {
    return { ok: false, reason: "The platform owner must remain an admin" };
  }
  return { ok: true };
}
