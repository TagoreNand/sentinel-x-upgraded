import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useRole } from "@/_core/hooks/useRole";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";
import { Bell, ShieldAlert, Trash2, Send } from "lucide-react";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export default function AdminNotificationsPage() {
  const { isAdmin } = useRole();
  const utils = trpc.useUtils();
  const [form, setForm] = useState({ name: "", type: "slack" as "slack" | "webhook" | "email", target: "", minSeverity: "high" as (typeof SEVERITIES)[number] });

  const channelsQuery = trpc.notifications.listChannels.useQuery({ limit: 100 }, { enabled: isAdmin });
  const deliveriesQuery = trpc.notifications.listDeliveries.useQuery({ limit: 50 }, { enabled: isAdmin });

  const invalidate = () => {
    utils.notifications.listChannels.invalidate();
    utils.notifications.listDeliveries.invalidate();
  };

  const createMutation = trpc.notifications.createChannel.useMutation({
    onSuccess: () => { toast.success("Channel created"); setForm({ name: "", type: "slack", target: "", minSeverity: "high" }); invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const updateMutation = trpc.notifications.updateChannel.useMutation({ onSuccess: () => invalidate(), onError: (e) => toast.error(e.message) });
  const deleteMutation = trpc.notifications.deleteChannel.useMutation({ onSuccess: () => { toast.success("Channel deleted"); invalidate(); }, onError: (e) => toast.error(e.message) });
  const testMutation = trpc.notifications.testChannel.useMutation({
    onSuccess: () => { toast.success("Test dispatched — check deliveries"); setTimeout(() => utils.notifications.listDeliveries.invalidate(), 800); },
    onError: (e) => toast.error(e.message),
  });

  if (!isAdmin) {
    return (
      <div className="min-h-screen bg-background text-foreground p-6">
        <Card className="max-w-md mx-auto mt-20 border-destructive/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive"><ShieldAlert className="w-5 h-5" />Admin access required</CardTitle>
            <CardDescription>Notification settings are restricted to administrators.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const targetPlaceholder = form.type === "email" ? "soc-team@corp.example" : form.type === "slack" ? "https://hooks.slack.com/services/…" : "https://your-endpoint.example/webhook";

  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <div className="max-w-5xl mx-auto space-y-6">
        <div>
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3"><Bell className="w-10 h-10 text-accent neon-glow" />Notifications</h1>
          <p className="text-muted-foreground">Fan out new incidents to Slack, generic webhooks, and email. Each channel fires only for incidents at or above its severity floor.</p>
        </div>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader><CardTitle>Add channel</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-5 gap-3 items-end">
            <div className="md:col-span-1">
              <label className="text-xs text-muted-foreground mb-1 block">Name</label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="SOC on-call" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Type</label>
              <Select value={form.type} onValueChange={(v: "slack" | "webhook" | "email") => setForm({ ...form, type: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="slack">Slack</SelectItem>
                  <SelectItem value="webhook">Webhook</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-2">
              <label className="text-xs text-muted-foreground mb-1 block">Target</label>
              <Input value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} placeholder={targetPlaceholder} />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Min severity</label>
              <Select value={form.minSeverity} onValueChange={(v: (typeof SEVERITIES)[number]) => setForm({ ...form, minSeverity: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-5">
              <Button
                className="w-full md:w-auto"
                disabled={createMutation.isPending}
                onClick={() => {
                  if (!form.name || !form.target) { toast.error("Name and target are required"); return; }
                  createMutation.mutate(form);
                }}
              >
                Add channel
              </Button>
              {form.type === "email" && <p className="text-xs text-muted-foreground mt-2">Email delivery requires SMTP_HOST/EMAIL_FROM to be configured on the server.</p>}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader><CardTitle>Channels</CardTitle></CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Target</TableHead><TableHead>Min sev</TableHead><TableHead>Enabled</TableHead><TableHead className="text-right">Actions</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {channelsQuery.data?.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell className="font-medium">{c.name}</TableCell>
                      <TableCell><Badge variant="outline">{c.type}</Badge></TableCell>
                      <TableCell className="text-xs text-muted-foreground truncate max-w-[220px]">{c.target}</TableCell>
                      <TableCell><Badge variant="outline">{c.minSeverity}</Badge></TableCell>
                      <TableCell>
                        <Button size="sm" variant={c.enabled ? "default" : "outline"} onClick={() => updateMutation.mutate({ id: c.id, enabled: !c.enabled })}>
                          {c.enabled ? "on" : "off"}
                        </Button>
                      </TableCell>
                      <TableCell className="text-right space-x-1">
                        <Button size="sm" variant="outline" onClick={() => testMutation.mutate({ id: c.id })} title="Send test"><Send className="w-3 h-3" /></Button>
                        <Button size="sm" variant="outline" onClick={() => deleteMutation.mutate({ id: c.id })} title="Delete"><Trash2 className="w-3 h-3" /></Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {channelsQuery.data?.length === 0 && <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground text-sm">No channels configured</TableCell></TableRow>}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader><CardTitle>Recent deliveries</CardTitle><CardDescription>Every send attempt is recorded here.</CardDescription></CardHeader>
          <CardContent>
            <div className="space-y-1">
              {deliveriesQuery.data?.map((d) => (
                <div key={d.id} className="flex items-center gap-3 text-xs border border-border rounded p-2">
                  <Badge className={d.status === "sent" ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" : d.status === "failed" ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-yellow-500/20 text-yellow-300 border-yellow-500/30"}>{d.status}</Badge>
                  <span className="text-muted-foreground">channel #{d.channelId}</span>
                  {d.statusCode ? <span className="text-muted-foreground">HTTP {d.statusCode}</span> : null}
                  {d.error ? <span className="text-muted-foreground truncate">{d.error}</span> : null}
                </div>
              ))}
              {deliveriesQuery.data?.length === 0 && <p className="text-sm text-muted-foreground">No deliveries yet</p>}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
