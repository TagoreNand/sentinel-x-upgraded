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
import { Rss, ShieldAlert, Trash2, RefreshCw } from "lucide-react";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export default function AdminIntelFeedsPage() {
  const { isAdmin } = useRole();
  const utils = trpc.useUtils();
  const [form, setForm] = useState({ name: "", type: "taxii" as "taxii" | "stix" | "misp", url: "", authToken: "", defaultThreatLevel: "medium" as (typeof SEVERITIES)[number] });

  const feedsQuery = trpc.intel.listFeeds.useQuery({ limit: 100 }, { enabled: isAdmin });
  const invalidate = () => utils.intel.listFeeds.invalidate();

  const createMutation = trpc.intel.createFeed.useMutation({
    onSuccess: () => { toast.success("Feed created"); setForm({ name: "", type: "taxii", url: "", authToken: "", defaultThreatLevel: "medium" }); invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const updateMutation = trpc.intel.updateFeed.useMutation({ onSuccess: invalidate, onError: (e) => toast.error(e.message) });
  const deleteMutation = trpc.intel.deleteFeed.useMutation({ onSuccess: () => { toast.success("Feed deleted"); invalidate(); }, onError: (e) => toast.error(e.message) });
  const pollMutation = trpc.intel.pollFeed.useMutation({
    onSuccess: (r) => { toast[r.error ? "error" : "success"](r.error ? `Poll failed: ${r.error}` : `Imported ${r.created} IOC(s), skipped ${r.skipped}`); invalidate(); },
    onError: (e) => toast.error(e.message),
  });

  if (!isAdmin) {
    return (
      <div className="min-h-screen bg-background text-foreground p-6">
        <Card className="max-w-md mx-auto mt-20 border-destructive/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive"><ShieldAlert className="w-5 h-5" />Admin access required</CardTitle>
            <CardDescription>Threat-intel feed configuration is restricted to administrators.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const urlPlaceholder = form.type === "misp" ? "https://misp.example/attributes/restSearch" : form.type === "taxii" ? "https://taxii.example/collections/<id>/objects/" : "https://feed.example/bundle.json";

  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <div>
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3"><Rss className="w-10 h-10 text-accent neon-glow" />Threat-Intel Feeds</h1>
          <p className="text-muted-foreground">Pull indicators from TAXII 2.x collections, STIX bundles, and MISP into the IOC store. Indicators that can't be translated faithfully are skipped, never mistranslated.</p>
        </div>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader><CardTitle>Add feed</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-6 gap-3 items-end">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Name</label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="AlienVault OTX" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Type</label>
              <Select value={form.type} onValueChange={(v: "taxii" | "stix" | "misp") => setForm({ ...form, type: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="taxii">TAXII 2.x</SelectItem>
                  <SelectItem value="stix">STIX bundle</SelectItem>
                  <SelectItem value="misp">MISP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="md:col-span-2">
              <label className="text-xs text-muted-foreground mb-1 block">URL</label>
              <Input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder={urlPlaceholder} />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Auth token</label>
              <Input type="password" value={form.authToken} onChange={(e) => setForm({ ...form, authToken: e.target.value })} placeholder="optional" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Threat level</label>
              <Select value={form.defaultThreatLevel} onValueChange={(v: (typeof SEVERITIES)[number]) => setForm({ ...form, defaultThreatLevel: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{SEVERITIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="md:col-span-6">
              <Button
                disabled={createMutation.isPending}
                onClick={() => {
                  if (!form.name || !form.url) { toast.error("Name and URL are required"); return; }
                  createMutation.mutate({ ...form, authToken: form.authToken || undefined });
                }}
              >
                Add feed
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur">
          <CardHeader><CardTitle>Feeds</CardTitle></CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Last poll</TableHead><TableHead>Enabled</TableHead><TableHead className="text-right">Actions</TableHead></TableRow>
                </TableHeader>
                <TableBody>
                  {feedsQuery.data?.map((f) => (
                    <TableRow key={f.id}>
                      <TableCell>
                        <div className="font-medium">{f.name}</div>
                        <div className="text-xs text-muted-foreground truncate max-w-[280px]">{f.url}</div>
                      </TableCell>
                      <TableCell><Badge variant="outline">{f.type}</Badge></TableCell>
                      <TableCell className="text-xs">
                        {f.lastStatus
                          ? <Badge className={f.lastStatus === "success" ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" : "bg-red-500/20 text-red-300 border-red-500/30"}>{f.lastStatus} · {f.lastIocCount ?? 0} new</Badge>
                          : <span className="text-muted-foreground">never</span>}
                        {f.lastError ? <div className="text-muted-foreground truncate max-w-[220px] mt-1">{f.lastError}</div> : null}
                      </TableCell>
                      <TableCell>
                        <Button size="sm" variant={f.enabled ? "default" : "outline"} onClick={() => updateMutation.mutate({ id: f.id, enabled: !f.enabled })}>
                          {f.enabled ? "on" : "off"}
                        </Button>
                      </TableCell>
                      <TableCell className="text-right space-x-1">
                        <Button size="sm" variant="outline" disabled={pollMutation.isPending} onClick={() => pollMutation.mutate({ id: f.id })} title="Poll now"><RefreshCw className="w-3 h-3" /></Button>
                        <Button size="sm" variant="outline" onClick={() => deleteMutation.mutate({ id: f.id })} title="Delete"><Trash2 className="w-3 h-3" /></Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {feedsQuery.data?.length === 0 && <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground text-sm">No feeds configured</TableCell></TableRow>}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
