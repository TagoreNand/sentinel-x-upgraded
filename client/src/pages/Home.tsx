import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Radar, Eye, Zap, Lock, Database, Skull, AlertTriangle, Activity } from "lucide-react";
import { getLoginUrl } from "@/const";

export default function Home() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        {/* Hero Section */}
        <div className="relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-accent/10 via-transparent to-transparent" />
          <div className="relative max-w-6xl mx-auto px-4 py-20 sm:py-32">
            <div className="text-center">
              <div className="flex justify-center mb-6">
                <Shield className="w-16 h-16 text-accent neon-glow" />
              </div>
              <h1 className="text-5xl sm:text-6xl font-bold mb-6 text-balance">
                Sentinel-X
                <br />
                <span className="text-accent">Security Operations Center</span>
              </h1>
              <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto text-balance">
                Advanced cybersecurity platform with real-time threat monitoring, SIEM engine, threat intelligence, vulnerability scanning, and comprehensive incident response management.
              </p>
              <Button asChild size="lg" className="neon-glow">
                <a href={getLoginUrl()}>Get Started</a>
              </Button>
            </div>
          </div>
        </div>

        {/* Features Grid */}
        <div className="max-w-6xl mx-auto px-4 py-20">
          <h2 className="text-3xl font-bold mb-12 text-center">Core Capabilities</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* SIEM */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Radar className="w-5 h-5 text-cyan-500" />
                  SIEM Engine
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Security event ingestion, correlation rules, log aggregation, and alert generation with four severity levels.
                </p>
              </CardContent>
            </Card>

            {/* Threat Intelligence */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="w-5 h-5 text-purple-500" />
                  Threat Intelligence
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  IOC management, threat actor profiles, CVE lookup, and MITRE ATT&CK framework mapping.
                </p>
              </CardContent>
            </Card>

            {/* Vulnerability Scanner */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  Vulnerability Scanner
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Port scanning, service fingerprinting, and CVE-based risk scoring for target hosts.
                </p>
              </CardContent>
            </Card>

            {/* IDS */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                  Intrusion Detection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Rule-based anomaly detection, pattern matching, and automated incident creation.
                </p>
              </CardContent>
            </Card>

            {/* Cryptography */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="w-5 h-5 text-green-500" />
                  Cryptography Toolkit
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  AES/RSA encryption, hash generation (MD5, SHA-1, SHA-256, SHA-512), and password analysis.
                </p>
              </CardContent>
            </Card>

            {/* Honeypot */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Skull className="w-5 h-5 text-pink-500" />
                  Honeypot Simulation
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Configurable fake services, attacker interaction logging, and geolocation-based origin mapping.
                </p>
              </CardContent>
            </Card>

            {/* Forensics */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="w-5 h-5 text-blue-500" />
                  Digital Forensics
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  File metadata extraction, hash verification, timeline analysis, and chain-of-custody logging.
                </p>
              </CardContent>
            </Card>

            {/* Incidents */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="w-5 h-5 text-orange-500" />
                  Incident Response
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Full lifecycle management with statuses, playbook steps, and complete audit trails.
                </p>
              </CardContent>
            </Card>

            {/* Dashboard */}
            <Card className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-accent" />
                  SOC Dashboard
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Real-time metrics, threat heatmaps, alert distribution charts, and live event feeds.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* CTA Section */}
        <div className="max-w-4xl mx-auto px-4 py-20 text-center">
          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader>
              <CardTitle className="text-2xl">Ready to Secure Your Infrastructure?</CardTitle>
              <CardDescription>
                Deploy Sentinel-X and gain comprehensive visibility into your security posture
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button asChild size="lg" className="neon-glow">
                <a href={getLoginUrl()}>Launch SOC Platform</a>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  // Authenticated users are redirected to dashboard by App.tsx
  return null;
}
