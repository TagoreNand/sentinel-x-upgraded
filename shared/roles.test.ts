import { describe, expect, it } from "vitest";
import { ROLE_RANK, ROLES, assertRoleAssignable, isRole, roleAtLeast, type Role } from "./roles";

describe("role hierarchy", () => {
  it("is totally ordered viewer < analyst < lead < admin", () => {
    expect(ROLE_RANK.viewer).toBeLessThan(ROLE_RANK.analyst);
    expect(ROLE_RANK.analyst).toBeLessThan(ROLE_RANK.lead);
    expect(ROLE_RANK.lead).toBeLessThan(ROLE_RANK.admin);
  });

  it("roleAtLeast: a higher tier satisfies every lower requirement", () => {
    // admin satisfies everything
    for (const req of ROLES) expect(roleAtLeast("admin", req)).toBe(true);
    // viewer satisfies only viewer
    expect(roleAtLeast("viewer", "viewer")).toBe(true);
    expect(roleAtLeast("viewer", "analyst")).toBe(false);
    expect(roleAtLeast("viewer", "lead")).toBe(false);
    // analyst can do analyst work but not lead-gated actions
    expect(roleAtLeast("analyst", "analyst")).toBe(true);
    expect(roleAtLeast("analyst", "lead")).toBe(false);
    // lead clears analyst and lead but not admin
    expect(roleAtLeast("lead", "analyst")).toBe(true);
    expect(roleAtLeast("lead", "lead")).toBe(true);
    expect(roleAtLeast("lead", "admin")).toBe(false);
  });

  it("isRole rejects the retired 'user' value and non-roles", () => {
    expect(isRole("analyst")).toBe(true);
    expect(isRole("user")).toBe(false); // migrated away
    expect(isRole("superuser")).toBe(false);
    expect(isRole(3)).toBe(false);
    expect(isRole(undefined)).toBe(false);
  });
});

describe("assertRoleAssignable", () => {
  const base = {
    actorRole: "admin" as Role,
    actorUserId: 1,
    targetUserId: 2,
    targetOpenId: "open-target",
    ownerOpenId: "open-owner",
    newRole: "lead",
  };

  it("allows an admin to change another user's role to a valid tier", () => {
    expect(assertRoleAssignable(base)).toEqual({ ok: true });
    expect(assertRoleAssignable({ ...base, newRole: "viewer" })).toEqual({ ok: true });
  });

  it("rejects a non-admin actor (defense in depth)", () => {
    const decision = assertRoleAssignable({ ...base, actorRole: "lead" });
    expect(decision.ok).toBe(false);
  });

  it("rejects an unknown target role", () => {
    const decision = assertRoleAssignable({ ...base, newRole: "root" });
    expect(decision).toEqual({ ok: false, reason: "Unknown role: root" });
  });

  it("forbids changing your own role (no self-lockout or self-promotion)", () => {
    const decision = assertRoleAssignable({ ...base, targetUserId: base.actorUserId });
    expect(decision.ok).toBe(false);
  });

  it("keeps the owner a permanent admin anchor", () => {
    const demoteOwner = assertRoleAssignable({ ...base, targetOpenId: "open-owner", newRole: "viewer" });
    expect(demoteOwner.ok).toBe(false);
    // Re-affirming the owner as admin is allowed (no-op, but not forbidden).
    const keepOwnerAdmin = assertRoleAssignable({ ...base, targetOpenId: "open-owner", newRole: "admin" });
    expect(keepOwnerAdmin).toEqual({ ok: true });
  });
});
