import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { useRole } from "@/_core/hooks/useRole";
import { ROLES, type Role } from "@shared/roles";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";
import { ShieldAlert, Users } from "lucide-react";

const ROLE_STYLES: Record<Role, string> = {
  viewer: "bg-slate-500/20 text-slate-300 border-slate-500/30",
  analyst: "bg-cyan-500/20 text-cyan-300 border-cyan-500/30",
  lead: "bg-purple-500/20 text-purple-300 border-purple-500/30",
  admin: "bg-amber-500/20 text-amber-300 border-amber-500/30",
};

export function RoleBadge({ role }: { role: string }) {
  const cls = ROLE_STYLES[role as Role] ?? ROLE_STYLES.viewer;
  return <Badge className={cls}>{role}</Badge>;
}

export default function AdminUsersPage() {
  const { user } = useAuth();
  const { isAdmin } = useRole();
  const utils = trpc.useUtils();
  const [pendingId, setPendingId] = useState<number | null>(null);

  const usersQuery = trpc.admin.listUsers.useQuery({ limit: 200 }, { enabled: isAdmin });
  const setRoleMutation = trpc.admin.setUserRole.useMutation({
    onSuccess: (_data, variables) => {
      toast.success(`Role updated to ${variables.role}`);
      utils.admin.listUsers.invalidate();
    },
    onError: (error) => toast.error(error.message),
    onSettled: () => setPendingId(null),
  });

  // Client-side courtesy gate; the adminProcedure enforces this server-side.
  if (!isAdmin) {
    return (
      <div className="min-h-screen bg-background text-foreground p-6">
        <Card className="max-w-md mx-auto mt-20 border-destructive/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <ShieldAlert className="w-5 h-5" />
              Admin access required
            </CardTitle>
            <CardDescription>User management is restricted to administrators.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <div className="max-w-5xl mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Users className="w-10 h-10 text-accent neon-glow" />
            User Management
          </h1>
          <p className="text-muted-foreground">
            Assign roles across the hierarchy: <span className="text-slate-300">viewer</span> (read-only) →{" "}
            <span className="text-cyan-300">analyst</span> (investigate) → <span className="text-purple-300">lead</span>{" "}
            (detection rules &amp; SOAR) → <span className="text-amber-300">admin</span> (governance).
          </p>
        </div>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle>Users</CardTitle>
            <CardDescription>
              {usersQuery.isLoading ? "Loading…" : `${usersQuery.data?.length ?? 0} users`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Login</TableHead>
                    <TableHead>Current role</TableHead>
                    <TableHead>Change role</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {usersQuery.data?.map((u) => {
                    const isSelf = u.id === user?.id;
                    return (
                      <TableRow key={u.id}>
                        <TableCell>
                          <div className="font-medium">{u.name || "—"}</div>
                          <div className="text-xs text-muted-foreground truncate max-w-[240px]">{u.email || u.openId}</div>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{u.loginMethod || "—"}</TableCell>
                        <TableCell>
                          <RoleBadge role={u.role} />
                        </TableCell>
                        <TableCell>
                          <Select
                            value={u.role}
                            disabled={isSelf || (pendingId === u.id && setRoleMutation.isPending)}
                            onValueChange={(role) => {
                              if (role === u.role) return;
                              setPendingId(u.id);
                              setRoleMutation.mutate({ userId: u.id, role: role as Role });
                            }}
                          >
                            <SelectTrigger className="w-36">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ROLES.map((r) => (
                                <SelectItem key={r} value={r}>
                                  {r}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          {isSelf && <div className="text-[10px] text-muted-foreground mt-1">You cannot change your own role</div>}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
