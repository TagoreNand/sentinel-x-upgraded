import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import IncidentsPage from "./pages/IncidentsPage";
import { SiemModule, ThreatIntelModule, VulnerabilityScannerModule, IdsModule, CryptographyModule, HoneypotModule } from "./pages/Modules";
import OperationsPage from "./pages/OperationsPage";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Radar, Eye, Zap, Lock, Skull, AlertTriangle, Settings, ShieldCheck } from "lucide-react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";

function SocLayout({ children }: { children: React.ReactNode }) {
  const { user, logout, isAuthenticated } = useAuth();

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Sidebar */}
      <div className="w-64 bg-card/80 backdrop-blur border-r border-border flex flex-col">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-8 h-8 text-accent neon-glow" />
            <h1 className="text-xl font-bold">Sentinel-X</h1>
          </div>
          <p className="text-xs text-muted-foreground">SOC Platform</p>
        </div>

        <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
          <a href="/dashboard" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm font-medium">
            <Radar className="w-4 h-4" />
            Dashboard
          </a>
          <a href="/incidents" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm font-medium">
            <AlertTriangle className="w-4 h-4" />
            Incidents
          </a>

          <div className="pt-4 border-t border-border">
            <p className="px-4 py-2 text-xs font-semibold text-muted-foreground uppercase">Modules</p>
            <a href="/siem" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <Radar className="w-4 h-4 text-cyan-500" />
              SIEM
            </a>
            <a href="/threat-intel" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <Eye className="w-4 h-4 text-purple-500" />
              Threat Intel
            </a>
            <a href="/vuln-scanner" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <Zap className="w-4 h-4 text-yellow-500" />
              Vulnerabilities
            </a>
            <a href="/ids" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <Radar className="w-4 h-4 text-red-500" />
              IDS
            </a>
            <a href="/crypto" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <Lock className="w-4 h-4 text-green-500" />
              Crypto
            </a>
            <a href="/honeypot" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <Skull className="w-4 h-4 text-pink-500" />
              Honeypot
            </a>
            <a href="/operations" className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-accent/10 transition-colors text-sm">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              Operations
            </a>
          </div>
        </nav>

        {/* User Info */}
        <div className="p-4 border-t border-border space-y-3">
          {isAuthenticated && user ? (
            <>
              <div className="text-sm">
                <p className="text-xs text-muted-foreground">Logged in as</p>
                <p className="font-medium truncate">{user.name || user.email}</p>
              </div>
              <Button onClick={logout} variant="outline" className="w-full text-xs" size="sm">
                Logout
              </Button>
            </>
          ) : (
            <Button asChild className="w-full text-xs" size="sm">
              <a href={getLoginUrl()}>Login</a>
            </Button>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        {children}
      </div>
    </div>
  );
}

function ModuleWrapper({ title, icon: Icon, description, children }: any) {
  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Icon className="w-10 h-10 text-accent neon-glow" />
            {title}
          </h1>
          <p className="text-muted-foreground">{description}</p>
        </div>
        {children}
      </div>
    </div>
  );
}

function Router() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <Card className="neon-border bg-card/50 backdrop-blur max-w-md w-full mx-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-accent" />
              Sentinel-X SOC
            </CardTitle>
            <CardDescription>Security Operations Center Platform</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-foreground/80">
              Welcome to Sentinel-X, an advanced cybersecurity platform featuring real-time threat monitoring, SIEM engine, threat intelligence, vulnerability scanning, IDS, cryptography toolkit, digital forensics, honeypot simulation, and comprehensive incident response management.
            </p>
            <Button asChild className="w-full">
              <a href={getLoginUrl()}>Sign In to Continue</a>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <SocLayout>
      <Switch>
        <Route path="/dashboard" component={Dashboard} />
        <Route path="/incidents" component={IncidentsPage} />
        <Route path="/operations" component={OperationsPage} />
        <Route
          path="/siem"
          component={() => (
            <ModuleWrapper
              title="SIEM Engine"
              icon={Radar}
              description="Security Information and Event Management"
            >
              <SiemModule />
            </ModuleWrapper>
          )}
        />
        <Route
          path="/threat-intel"
          component={() => (
            <ModuleWrapper
              title="Threat Intelligence"
              icon={Eye}
              description="IOC Management & Threat Actor Tracking"
            >
              <ThreatIntelModule />
            </ModuleWrapper>
          )}
        />
        <Route
          path="/vuln-scanner"
          component={() => (
            <ModuleWrapper
              title="Vulnerability Scanner"
              icon={Zap}
              description="Port Scanning & CVE Assessment"
            >
              <VulnerabilityScannerModule />
            </ModuleWrapper>
          )}
        />
        <Route
          path="/ids"
          component={() => (
            <ModuleWrapper
              title="Intrusion Detection System"
              icon={Radar}
              description="Rule-based Anomaly Detection"
            >
              <IdsModule />
            </ModuleWrapper>
          )}
        />
        <Route
          path="/crypto"
          component={() => (
            <ModuleWrapper
              title="Cryptography Toolkit"
              icon={Lock}
              description="Hash Generation & Encryption Tools"
            >
              <CryptographyModule />
            </ModuleWrapper>
          )}
        />
        <Route
          path="/honeypot"
          component={() => (
            <ModuleWrapper
              title="Honeypot Simulation"
              icon={Skull}
              description="Attacker Tracking & Geolocation"
            >
              <HoneypotModule />
            </ModuleWrapper>
          )}
        />
        <Route path="/" component={Dashboard} />
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </SocLayout>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
