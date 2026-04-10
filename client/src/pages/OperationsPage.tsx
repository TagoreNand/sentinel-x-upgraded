import { useMemo, useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { ShieldCheck, Activity, Search, Bot, FolderSearch } from "lucide-react";

function SeverityBadge({ value }: { value: string }) {
  const cls = value === "critical"
    ? "bg-red-500/20 text-red-300 border-red-500/30"
    : value === "high"
      ? "bg-orange-500/20 text-orange-300 border-orange-500/30"
      : value === "medium"
        ? "bg-yellow-500/20 text-yellow-300 border-yellow-500/30"
        : "bg-blue-500/20 text-blue-300 border-blue-500/30";
  return <Badge className={cls}>{value}</Badge>;
}

export default function OperationsPage() {
  const [sourceType, setSourceType] = useState("syslog");
  const [rawPayload, setRawPayload] = useState("Apr 10 12:00:01 web-01 sshd[101]: Failed password for invalid user admin from 91.240.118.12 port 49222 ssh2");
  const [assetForm, setAssetForm] = useState({ hostname: "web-01.prod.internal", ipAddress: "10.10.1.25", criticality: "critical" });
  const [iamForm, setIamForm] = useState({ actor: "jdoe", action: "MFA challenge failed", sourceIp: "91.240.118.12", anomalyScore: 82 });
  const [endpointForm, setEndpointForm] = useState({ hostname: "ws-044", processName: "powershell.exe", commandLine: "powershell -enc aQBlAHgA", severity: "high" });
  const [cloudForm, setCloudForm] = useState({ resourceId: "arn:aws:s3:::finance-bucket", findingType: "Public S3 bucket", severity: "high" });
  const [phishingForm, setPhishingForm] = useState({ subject: "Urgent: verify your payroll account", sender: "security-alerts@company-support.xyz", recipient: "alex@corp.local", body: "Urgent action required. Verify your account at https://secure-update-login.example.xyz/payroll" });
  const [playbookJson, setPlaybookJson] = useState('[{"name":"Create ticket","action":"create-ticket"},{"name":"Contain host","action":"contain-host"}]');
  const [soarForm, setSoarForm] = useState({ name: "Contain suspicious endpoint", triggerType: "endpoint_alert" });
  const [caseIncidentId, setCaseIncidentId] = useState<number>(1);
  const [evidenceForm, setEvidenceForm] = useState({ filename: "memory_dump.zip", classification: "internal", sha256Hash: "demo-sha256", collectionMethod: "live response" });
  const [timelineForm, setTimelineForm] = useState({ eventDescription: "Analyst confirmed brute-force pattern", severity: "medium" });
  const [artifactForm, setArtifactForm] = useState({ artifactType: "alert", title: "Primary detection artifact", sourceTable: "alerts", sourceRecordId: "1" });
  const [custodyForm, setCustodyForm] = useState({ evidenceId: 1, action: "transferred", notes: "Transferred to lead analyst" });

  const incidentsQuery = trpc.incidents.list.useQuery({ limit: 20, offset: 0 });
  const eventsQuery = trpc.siem.getEvents.useQuery({ limit: 12, offset: 0 });
  const alertsQuery = trpc.siem.getAlerts.useQuery({ limit: 8, offset: 0 });
  const detectionsQuery = trpc.ids.getDetections.useQuery({ limit: 8 });
  const assetsQuery = trpc.assets.list.useQuery({ limit: 8 });
  const iamQuery = trpc.iam.list.useQuery({ limit: 8 });
  const endpointQuery = trpc.endpoint.list.useQuery({ limit: 8 });
  const cloudQuery = trpc.cloud.list.useQuery({ limit: 8 });
  const phishingQuery = trpc.phishing.list.useQuery({ limit: 8 });
  const playbooksQuery = trpc.soar.listPlaybooks.useQuery({ limit: 8 });
  const executionsQuery = trpc.soar.listExecutions.useQuery({ limit: 8 });
  const caseOverviewQuery = trpc.forensics.getCaseOverview.useQuery({ incidentId: caseIncidentId }, { enabled: !!caseIncidentId });
  const custodyQuery = trpc.forensics.getCustody.useQuery({ evidenceId: custodyForm.evidenceId }, { enabled: !!custodyForm.evidenceId });

  const firstIncidentId = useMemo(() => incidentsQuery.data?.[0]?.id, [incidentsQuery.data]);

  const refreshAll = () => {
    incidentsQuery.refetch();
    eventsQuery.refetch();
    alertsQuery.refetch();
    detectionsQuery.refetch();
    assetsQuery.refetch();
    iamQuery.refetch();
    endpointQuery.refetch();
    cloudQuery.refetch();
    phishingQuery.refetch();
    playbooksQuery.refetch();
    executionsQuery.refetch();
    caseOverviewQuery.refetch();
    custodyQuery.refetch();
  };

  const ingestMutation = trpc.siem.ingestRawEvent.useMutation({ onSuccess: (data) => { toast.success(`Ingested event with ${data.detections.length} detections and ${data.alerts.length} alerts`); refreshAll(); }, onError: (error) => toast.error(error.message) });
  const seedDemoMutation = trpc.siem.seedDemo.useMutation({ onSuccess: () => { toast.success("Demo data seeded"); refreshAll(); }, onError: (error) => toast.error(error.message) });
  const createAssetMutation = trpc.assets.create.useMutation({ onSuccess: () => { toast.success("Asset added"); assetsQuery.refetch(); }, onError: (error) => toast.error(error.message) });
  const iamMutation = trpc.iam.createEvent.useMutation({ onSuccess: () => { toast.success("IAM event recorded"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const endpointMutation = trpc.endpoint.createTelemetry.useMutation({ onSuccess: () => { toast.success("Endpoint telemetry recorded"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const cloudMutation = trpc.cloud.createFinding.useMutation({ onSuccess: () => { toast.success("Cloud finding recorded"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const phishingMutation = trpc.phishing.analyze.useMutation({ onSuccess: (data) => { toast.success(`Phishing verdict: ${data.verdict}`); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const createPlaybookMutation = trpc.soar.createPlaybook.useMutation({ onSuccess: () => { toast.success("SOAR playbook created"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const executePlaybookMutation = trpc.soar.execute.useMutation({ onSuccess: () => { toast.success("SOAR playbook executed"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const createEvidenceMutation = trpc.forensics.createEvidence.useMutation({ onSuccess: (data) => { toast.success(`Evidence created: ${data.evidenceId}`); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const addTimelineMutation = trpc.forensics.addTimelineEvent.useMutation({ onSuccess: () => { toast.success("Timeline event added"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const linkArtifactMutation = trpc.forensics.linkArtifact.useMutation({ onSuccess: () => { toast.success("Artifact linked"); refreshAll(); }, onError: (e) => toast.error(e.message) });
  const addCustodyMutation = trpc.forensics.addCustodyEvent.useMutation({ onSuccess: () => { toast.success("Custody event added"); refreshAll(); }, onError: (e) => toast.error(e.message) });

  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-4xl font-bold flex items-center gap-3">
              <ShieldCheck className="w-10 h-10 text-accent" />
              Advanced Security Operations
            </h1>
            <p className="text-muted-foreground mt-2">Ingestion pipeline, enrichment, detection engineering, investigation workflows, and SOAR orchestration.</p>
          </div>
          <Button onClick={() => seedDemoMutation.mutate()} disabled={seedDemoMutation.isPending}>
            {seedDemoMutation.isPending ? "Seeding..." : "Seed Demo Dataset"}
          </Button>
        </div>

        <Tabs defaultValue="pipeline" className="space-y-4">
          <TabsList>
            <TabsTrigger value="pipeline">Pipeline</TabsTrigger>
            <TabsTrigger value="domains">IAM / Endpoint / Cloud</TabsTrigger>
            <TabsTrigger value="forensics">Forensics</TabsTrigger>
            <TabsTrigger value="phishing">Phishing & SOAR</TabsTrigger>
          </TabsList>

          <TabsContent value="pipeline" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-card/60">
                <CardHeader>
                  <CardTitle>Ingest & Detect</CardTitle>
                  <CardDescription>Send raw syslog, JSON, or generic logs through normalization, enrichment, and Sigma-like rule matching.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Select value={sourceType} onValueChange={setSourceType}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="syslog">Syslog</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="raw">Raw text</SelectItem>
                    </SelectContent>
                  </Select>
                  <Textarea rows={8} value={rawPayload} onChange={(e) => setRawPayload(e.target.value)} />
                  <Button className="w-full" onClick={() => ingestMutation.mutate({ sourceType: sourceType as any, payload: rawPayload })} disabled={ingestMutation.isPending}>
                    {ingestMutation.isPending ? "Processing..." : "Run Pipeline"}
                  </Button>
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader>
                  <CardTitle>Asset Context</CardTitle>
                  <CardDescription>Register critical assets so detections can use business context and service fingerprints.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Hostname" value={assetForm.hostname} onChange={(e) => setAssetForm({ ...assetForm, hostname: e.target.value })} />
                  <Input placeholder="IP address" value={assetForm.ipAddress} onChange={(e) => setAssetForm({ ...assetForm, ipAddress: e.target.value })} />
                  <Select value={assetForm.criticality} onValueChange={(value) => setAssetForm({ ...assetForm, criticality: value })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button className="w-full" onClick={() => createAssetMutation.mutate({ hostname: assetForm.hostname, ipAddress: assetForm.ipAddress, criticality: assetForm.criticality as any, assetType: "server", environment: "production", services: [{ port: 22, service: "ssh", product: "openssh", version: "7.2" }], tags: ["internet-facing"] })}>Add Asset</Button>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="bg-card/60">
                <CardHeader><CardTitle>Recent Detections</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {detectionsQuery.data?.map((item: any) => (
                    <div key={item.id} className="border border-border rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between"><span className="text-sm font-medium">Rule #{item.ruleId}</span><Badge>{item.confidence}%</Badge></div>
                      <div className="text-xs text-muted-foreground">{item.mitreTechnique || "No ATT&CK tag"}</div>
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card className="bg-card/60">
                <CardHeader><CardTitle>Recent Alerts</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {alertsQuery.data?.map((item: any) => (
                    <div key={item.id} className="border border-border rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium">{item.title}</span><SeverityBadge value={item.severity} /></div>
                      <div className="text-xs text-muted-foreground">{item.ruleName || "manual"}</div>
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card className="bg-card/60">
                <CardHeader><CardTitle>Assets</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {assetsQuery.data?.map((item: any) => (
                    <div key={item.id} className="border border-border rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between gap-2"><span className="text-sm font-medium">{item.hostname}</span><SeverityBadge value={item.criticality} /></div>
                      <div className="text-xs text-muted-foreground">{item.ipAddress}</div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="domains" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="bg-card/60">
                <CardHeader><CardTitle className="flex items-center gap-2"><Activity className="w-4 h-4" />IAM</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Actor" value={iamForm.actor} onChange={(e) => setIamForm({ ...iamForm, actor: e.target.value })} />
                  <Input placeholder="Action" value={iamForm.action} onChange={(e) => setIamForm({ ...iamForm, action: e.target.value })} />
                  <Input placeholder="Source IP" value={iamForm.sourceIp} onChange={(e) => setIamForm({ ...iamForm, sourceIp: e.target.value })} />
                  <Input type="number" placeholder="Anomaly score" value={iamForm.anomalyScore} onChange={(e) => setIamForm({ ...iamForm, anomalyScore: Number(e.target.value) })} />
                  <Button className="w-full" onClick={() => iamMutation.mutate({ ...iamForm })}>Record IAM Event</Button>
                  {iamQuery.data?.map((item: any) => <div key={item.id} className="text-xs border rounded p-2">{item.actor} · {item.action}</div>)}
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader><CardTitle>Endpoint Telemetry</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Hostname" value={endpointForm.hostname} onChange={(e) => setEndpointForm({ ...endpointForm, hostname: e.target.value })} />
                  <Input placeholder="Process" value={endpointForm.processName} onChange={(e) => setEndpointForm({ ...endpointForm, processName: e.target.value })} />
                  <Textarea rows={3} placeholder="Command line" value={endpointForm.commandLine} onChange={(e) => setEndpointForm({ ...endpointForm, commandLine: e.target.value })} />
                  <Select value={endpointForm.severity} onValueChange={(value) => setEndpointForm({ ...endpointForm, severity: value })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button className="w-full" onClick={() => endpointMutation.mutate({ ...endpointForm, severity: endpointForm.severity as any })}>Record Telemetry</Button>
                  {endpointQuery.data?.map((item: any) => <div key={item.id} className="text-xs border rounded p-2">{item.hostname} · {item.processName}</div>)}
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader><CardTitle>Cloud Findings</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Resource ID" value={cloudForm.resourceId} onChange={(e) => setCloudForm({ ...cloudForm, resourceId: e.target.value })} />
                  <Input placeholder="Finding type" value={cloudForm.findingType} onChange={(e) => setCloudForm({ ...cloudForm, findingType: e.target.value })} />
                  <Select value={cloudForm.severity} onValueChange={(value) => setCloudForm({ ...cloudForm, severity: value })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button className="w-full" onClick={() => cloudMutation.mutate({ ...cloudForm, severity: cloudForm.severity as any })}>Record Cloud Finding</Button>
                  {cloudQuery.data?.map((item: any) => <div key={item.id} className="text-xs border rounded p-2">{item.resourceId} · {item.findingType}</div>)}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="forensics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-card/60">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2"><FolderSearch className="w-4 h-4" />Case Overview</CardTitle>
                  <CardDescription>Select an incident and manage its evidence, timeline, and artifacts.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <Select value={String(caseIncidentId)} onValueChange={(value) => setCaseIncidentId(Number(value))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {(incidentsQuery.data || []).map((incident: any) => (
                        <SelectItem key={incident.id} value={String(incident.id)}>{incident.title}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div className="border rounded-lg p-3">
                      <div className="text-muted-foreground text-xs">Evidence</div>
                      <div className="font-semibold">{caseOverviewQuery.data?.evidence?.length || 0}</div>
                    </div>
                    <div className="border rounded-lg p-3">
                      <div className="text-muted-foreground text-xs">Timeline</div>
                      <div className="font-semibold">{caseOverviewQuery.data?.timeline?.length || 0}</div>
                    </div>
                    <div className="border rounded-lg p-3">
                      <div className="text-muted-foreground text-xs">Artifacts</div>
                      <div className="font-semibold">{caseOverviewQuery.data?.artifacts?.length || 0}</div>
                    </div>
                    <div className="border rounded-lg p-3">
                      <div className="text-muted-foreground text-xs">Audit trail</div>
                      <div className="font-semibold">{caseOverviewQuery.data?.auditTrail?.length || 0}</div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    {(caseOverviewQuery.data?.timeline || []).map((item: any) => (
                      <div key={item.id} className="text-xs border rounded p-2">{item.eventDescription}</div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader><CardTitle>Create Evidence</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Filename" value={evidenceForm.filename} onChange={(e) => setEvidenceForm({ ...evidenceForm, filename: e.target.value })} />
                  <Input placeholder="Classification" value={evidenceForm.classification} onChange={(e) => setEvidenceForm({ ...evidenceForm, classification: e.target.value })} />
                  <Input placeholder="SHA-256" value={evidenceForm.sha256Hash} onChange={(e) => setEvidenceForm({ ...evidenceForm, sha256Hash: e.target.value })} />
                  <Input placeholder="Collection method" value={evidenceForm.collectionMethod} onChange={(e) => setEvidenceForm({ ...evidenceForm, collectionMethod: e.target.value })} />
                  <Button className="w-full" onClick={() => createEvidenceMutation.mutate({ incidentId: caseIncidentId || firstIncidentId, ...evidenceForm })}>Add Evidence</Button>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="bg-card/60">
                <CardHeader><CardTitle>Add Timeline Event</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Textarea rows={4} value={timelineForm.eventDescription} onChange={(e) => setTimelineForm({ ...timelineForm, eventDescription: e.target.value })} />
                  <Select value={timelineForm.severity} onValueChange={(value) => setTimelineForm({ ...timelineForm, severity: value })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button className="w-full" onClick={() => addTimelineMutation.mutate({ incidentId: caseIncidentId || firstIncidentId || 1, eventDescription: timelineForm.eventDescription, severity: timelineForm.severity as any })}>Add Timeline</Button>
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader><CardTitle>Link Artifact</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Artifact type" value={artifactForm.artifactType} onChange={(e) => setArtifactForm({ ...artifactForm, artifactType: e.target.value })} />
                  <Input placeholder="Title" value={artifactForm.title} onChange={(e) => setArtifactForm({ ...artifactForm, title: e.target.value })} />
                  <Input placeholder="Source table" value={artifactForm.sourceTable} onChange={(e) => setArtifactForm({ ...artifactForm, sourceTable: e.target.value })} />
                  <Input placeholder="Source record ID" value={artifactForm.sourceRecordId} onChange={(e) => setArtifactForm({ ...artifactForm, sourceRecordId: e.target.value })} />
                  <Button className="w-full" onClick={() => linkArtifactMutation.mutate({ incidentId: caseIncidentId || firstIncidentId || 1, ...artifactForm })}>Link Artifact</Button>
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader><CardTitle>Chain of Custody</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input type="number" placeholder="Evidence ID" value={custodyForm.evidenceId} onChange={(e) => setCustodyForm({ ...custodyForm, evidenceId: Number(e.target.value) })} />
                  <Input placeholder="Action" value={custodyForm.action} onChange={(e) => setCustodyForm({ ...custodyForm, action: e.target.value })} />
                  <Textarea rows={3} placeholder="Notes" value={custodyForm.notes} onChange={(e) => setCustodyForm({ ...custodyForm, notes: e.target.value })} />
                  <Button className="w-full" onClick={() => addCustodyMutation.mutate(custodyForm)}>Add Custody Event</Button>
                  <div className="space-y-2">
                    {(custodyQuery.data || []).map((item: any) => (
                      <div key={item.id} className="text-xs border rounded p-2">{item.action} · {new Date(item.timestamp).toLocaleString()}</div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="phishing" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-card/60">
                <CardHeader><CardTitle className="flex items-center gap-2"><Search className="w-4 h-4" />Phishing Analysis</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Subject" value={phishingForm.subject} onChange={(e) => setPhishingForm({ ...phishingForm, subject: e.target.value })} />
                  <Input placeholder="Sender" value={phishingForm.sender} onChange={(e) => setPhishingForm({ ...phishingForm, sender: e.target.value })} />
                  <Input placeholder="Recipient" value={phishingForm.recipient} onChange={(e) => setPhishingForm({ ...phishingForm, recipient: e.target.value })} />
                  <Textarea rows={6} placeholder="Body" value={phishingForm.body} onChange={(e) => setPhishingForm({ ...phishingForm, body: e.target.value })} />
                  <Button className="w-full" onClick={() => phishingMutation.mutate(phishingForm)}>Analyze Email</Button>
                  {phishingQuery.data?.map((item: any) => (
                    <div key={item.id} className="border border-border rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between"><span className="text-sm font-medium">{item.emailSubject}</span><Badge>{item.verdict}</Badge></div>
                      <div className="text-xs text-muted-foreground">{item.sender}</div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card className="bg-card/60">
                <CardHeader><CardTitle className="flex items-center gap-2"><Bot className="w-4 h-4" />SOAR Playbooks</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Playbook name" value={soarForm.name} onChange={(e) => setSoarForm({ ...soarForm, name: e.target.value })} />
                  <Input placeholder="Trigger type" value={soarForm.triggerType} onChange={(e) => setSoarForm({ ...soarForm, triggerType: e.target.value })} />
                  <Textarea rows={5} value={playbookJson} onChange={(e) => setPlaybookJson(e.target.value)} />
                  <Button className="w-full" onClick={() => {
                    try {
                      createPlaybookMutation.mutate({ name: soarForm.name, triggerType: soarForm.triggerType, steps: JSON.parse(playbookJson) });
                    } catch {
                      toast.error("Steps must be valid JSON");
                    }
                  }}>Create Playbook</Button>
                  <div className="space-y-2 pt-2">
                    {playbooksQuery.data?.map((item: any) => (
                      <div key={item.id} className="border border-border rounded-lg p-3 flex items-center justify-between gap-3">
                        <div>
                          <div className="text-sm font-medium">{item.name}</div>
                          <div className="text-xs text-muted-foreground">{item.triggerType}</div>
                        </div>
                        <Button size="sm" variant="outline" onClick={() => executePlaybookMutation.mutate({ playbookId: item.id, incidentId: caseIncidentId || firstIncidentId, triggerEntityType: "manual" })}>Run</Button>
                      </div>
                    ))}
                  </div>
                  <div className="space-y-2 pt-2">
                    {executionsQuery.data?.map((item: any) => <div key={item.id} className="text-xs border rounded p-2">Execution #{item.id} · {item.status}</div>)}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
