import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertTriangle, Shield, Eye, Zap, Lock, Database, Radar, Skull } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

// ============================================================================
// SIEM MODULE
// ============================================================================

export function SiemModule() {
  const [eventForm, setEventForm] = useState({
    eventType: "",
    severity: "low" as const,
    sourceIp: "",
    destinationIp: "",
    hostname: "",
  });

  const createEventMutation = trpc.siem.createEvent.useMutation({
    onSuccess: () => {
      toast.success("Security event created");
      setEventForm({ eventType: "", severity: "low", sourceIp: "", destinationIp: "", hostname: "" });
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleCreateEvent = () => {
    if (!eventForm.eventType) {
      toast.error("Event type is required");
      return;
    }
    createEventMutation.mutate(eventForm);
  };

  return (
    <div className="space-y-6">
      <Card className="neon-border bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Radar className="w-5 h-5 text-cyan-500" />
            SIEM Engine
          </CardTitle>
          <CardDescription>Security Information and Event Management</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Event Type</label>
              <Input
                placeholder="e.g., Failed Login, Port Scan"
                value={eventForm.eventType}
                onChange={(e) => setEventForm({ ...eventForm, eventType: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Severity</label>
              <Select value={eventForm.severity} onValueChange={(val: any) => setEventForm({ ...eventForm, severity: val })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Source IP</label>
              <Input
                placeholder="192.168.1.100"
                value={eventForm.sourceIp}
                onChange={(e) => setEventForm({ ...eventForm, sourceIp: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Destination IP</label>
              <Input
                placeholder="10.0.0.50"
                value={eventForm.destinationIp}
                onChange={(e) => setEventForm({ ...eventForm, destinationIp: e.target.value })}
              />
            </div>
          </div>
          <Button onClick={handleCreateEvent} className="w-full" disabled={createEventMutation.isPending}>
            {createEventMutation.isPending ? "Creating..." : "Create Security Event"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// THREAT INTELLIGENCE MODULE
// ============================================================================

export function ThreatIntelModule() {
  const [iocForm, setIocForm] = useState({
    iocType: "ip" as const,
    iocValue: "",
    threatLevel: "medium" as const,
  });

  const createIocMutation = trpc.threatIntel.createIOC.useMutation({
    onSuccess: () => {
      toast.success("IOC created successfully");
      setIocForm({ iocType: "ip", iocValue: "", threatLevel: "medium" });
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleCreateIOC = () => {
    if (!iocForm.iocValue) {
      toast.error("IOC value is required");
      return;
    }
    createIocMutation.mutate(iocForm);
  };

  return (
    <div className="space-y-6">
      <Card className="neon-border bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-purple-500" />
            Threat Intelligence
          </CardTitle>
          <CardDescription>Indicators of Compromise & Threat Actor Management</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">IOC Type</label>
              <Select value={iocForm.iocType} onValueChange={(val: any) => setIocForm({ ...iocForm, iocType: val })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP Address</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="hash">Hash</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">IOC Value</label>
              <Input
                placeholder="192.168.1.1"
                value={iocForm.iocValue}
                onChange={(e) => setIocForm({ ...iocForm, iocValue: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Threat Level</label>
              <Select value={iocForm.threatLevel} onValueChange={(val: any) => setIocForm({ ...iocForm, threatLevel: val })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <Button onClick={handleCreateIOC} className="w-full" disabled={createIocMutation.isPending}>
            {createIocMutation.isPending ? "Creating..." : "Add IOC"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// VULNERABILITY SCANNER MODULE
// ============================================================================

export function VulnerabilityScannerModule() {
  const [scanForm, setScanForm] = useState({
    targetHost: "",
    targetIp: "",
  });

  const createScanMutation = trpc.vulnerabilityScanning.createScan.useMutation({
    onSuccess: () => {
      toast.success("Vulnerability scan initiated");
      setScanForm({ targetHost: "", targetIp: "" });
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleCreateScan = () => {
    if (!scanForm.targetHost && !scanForm.targetIp) {
      toast.error("Target host or IP is required");
      return;
    }
    createScanMutation.mutate(scanForm);
  };

  return (
    <div className="space-y-6">
      <Card className="neon-border bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-yellow-500" />
            Vulnerability Scanner
          </CardTitle>
          <CardDescription>Port scanning, service fingerprinting, and CVE assessment</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Target Host</label>
              <Input
                placeholder="example.com"
                value={scanForm.targetHost}
                onChange={(e) => setScanForm({ ...scanForm, targetHost: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Target IP</label>
              <Input
                placeholder="192.168.1.1"
                value={scanForm.targetIp}
                onChange={(e) => setScanForm({ ...scanForm, targetIp: e.target.value })}
              />
            </div>
          </div>
          <Button onClick={handleCreateScan} className="w-full" disabled={createScanMutation.isPending}>
            {createScanMutation.isPending ? "Scanning..." : "Start Vulnerability Scan"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// IDS MODULE
// ============================================================================

export function IdsModule() {
  const [ruleForm, setRuleForm] = useState({
    ruleName: "",
    pattern: "",
    severity: "medium" as const,
  });

  const createRuleMutation = trpc.ids.createRule.useMutation({
    onSuccess: () => {
      toast.success("IDS rule created");
      setRuleForm({ ruleName: "", pattern: "", severity: "medium" });
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleCreateRule = () => {
    if (!ruleForm.ruleName || !ruleForm.pattern) {
      toast.error("Rule name and pattern are required");
      return;
    }
    createRuleMutation.mutate(ruleForm);
  };

  return (
    <div className="space-y-6">
      <Card className="neon-border bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Radar className="w-5 h-5 text-red-500" />
            Intrusion Detection System
          </CardTitle>
          <CardDescription>Rule-based anomaly detection and pattern matching</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium mb-2 block">Rule Name</label>
              <Input
                placeholder="e.g., Brute Force Attack Detection"
                value={ruleForm.ruleName}
                onChange={(e) => setRuleForm({ ...ruleForm, ruleName: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Detection Pattern</label>
              <Textarea
                placeholder="Define the pattern for detection..."
                value={ruleForm.pattern}
                onChange={(e) => setRuleForm({ ...ruleForm, pattern: e.target.value })}
                rows={4}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Severity</label>
              <Select value={ruleForm.severity} onValueChange={(val: any) => setRuleForm({ ...ruleForm, severity: val })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <Button onClick={handleCreateRule} className="w-full" disabled={createRuleMutation.isPending}>
            {createRuleMutation.isPending ? "Creating..." : "Create IDS Rule"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// CRYPTOGRAPHY TOOLKIT MODULE
// ============================================================================

export function CryptographyModule() {
  const [hashInput, setHashInput] = useState("");
  const [hashAlgorithm, setHashAlgorithm] = useState("sha256");
  const [hashOutput, setHashOutput] = useState("");

  const handleGenerateHash = async () => {
    if (!hashInput) {
      toast.error("Input is required");
      return;
    }

    try {
      let algorithm = "SHA-256";
      switch (hashAlgorithm) {
        case "md5":
          toast.info("MD5 not available. Using SHA-256 instead.");
          algorithm = "SHA-256";
          break;
        case "sha1":
          algorithm = "SHA-1";
          break;
        case "sha256":
          algorithm = "SHA-256";
          break;
        case "sha512":
          algorithm = "SHA-512";
          break;
      }

      const encoder = new TextEncoder();
      const data = encoder.encode(hashInput);
      const hashBuffer = await crypto.subtle.digest(algorithm, data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
      setHashOutput(hashHex);
      toast.success(`${algorithm} hash generated`);
    } catch (error) {
      toast.error("Error generating hash");
    }
  };

  return (
    <div className="space-y-6">
      <Card className="neon-border bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-green-500" />
            Cryptography Toolkit
          </CardTitle>
          <CardDescription>Hash generation, encryption/decryption, and password analysis</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium mb-2 block">Input Text</label>
              <Textarea
                placeholder="Enter text to hash..."
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                rows={3}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Hash Algorithm</label>
              <Select value={hashAlgorithm} onValueChange={setHashAlgorithm}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="md5">MD5</SelectItem>
                  <SelectItem value="sha1">SHA-1</SelectItem>
                  <SelectItem value="sha256">SHA-256</SelectItem>
                  <SelectItem value="sha512">SHA-512</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleGenerateHash} className="w-full">
              Generate Hash
            </Button>
            {hashOutput && (
              <div>
                <label className="text-sm font-medium mb-2 block">Hash Output</label>
                <div className="p-3 bg-background/50 border border-border rounded font-mono text-xs break-all text-accent">
                  {hashOutput}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// HONEYPOT MODULE
// ============================================================================

export function HoneypotModule() {
  const [honeypotForm, setHoneypotForm] = useState({
    name: "",
    serviceType: "ssh",
    bindPort: 2222,
  });

  const createHoneypotMutation = trpc.honeypot.create.useMutation({
    onSuccess: () => {
      toast.success("Honeypot created");
      setHoneypotForm({ name: "", serviceType: "ssh", bindPort: 2222 });
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleCreateHoneypot = () => {
    if (!honeypotForm.name) {
      toast.error("Honeypot name is required");
      return;
    }
    createHoneypotMutation.mutate(honeypotForm);
  };

  return (
    <div className="space-y-6">
      <Card className="neon-border bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Skull className="w-5 h-5 text-pink-500" />
            Honeypot Simulation
          </CardTitle>
          <CardDescription>Configurable fake services with attacker tracking</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Honeypot Name</label>
              <Input
                placeholder="e.g., Fake SSH Server"
                value={honeypotForm.name}
                onChange={(e) => setHoneypotForm({ ...honeypotForm, name: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Service Type</label>
              <Select value={honeypotForm.serviceType} onValueChange={(val) => setHoneypotForm({ ...honeypotForm, serviceType: val })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ssh">SSH</SelectItem>
                  <SelectItem value="http">HTTP</SelectItem>
                  <SelectItem value="ftp">FTP</SelectItem>
                  <SelectItem value="smtp">SMTP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Bind Port</label>
              <Input
                type="number"
                placeholder="2222"
                value={honeypotForm.bindPort}
                onChange={(e) => setHoneypotForm({ ...honeypotForm, bindPort: parseInt(e.target.value) })}
              />
            </div>
          </div>
          <Button onClick={handleCreateHoneypot} className="w-full" disabled={createHoneypotMutation.isPending}>
            {createHoneypotMutation.isPending ? "Creating..." : "Deploy Honeypot"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
