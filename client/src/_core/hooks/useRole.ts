import { roleAtLeast, type Role } from "@shared/roles";
import { useAuth } from "./useAuth";

/**
 * Client-side role helper. This drives UX only — hiding an action a user
 * cannot perform is courtesy, not security. Every gated capability is
 * ALSO enforced server-side by the tiered tRPC procedures; the client can
 * never be the authorization boundary.
 */
export function useRole() {
  const { user } = useAuth();
  const role = (user?.role ?? "viewer") as Role;
  return {
    role,
    atLeast: (min: Role) => roleAtLeast(role, min),
    isAnalyst: roleAtLeast(role, "analyst"),
    isLead: roleAtLeast(role, "lead"),
    isAdmin: role === "admin",
  };
}
