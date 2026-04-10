import { useEffect, useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BarChart, Bar, PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { AlertTriangle, Shield, Activity, Zap } from "lucide-react";

export default function Dashboard() {
  const metricsQuery = trpc.dashboard.getMetrics.useQuery();
  const eventFeedQuery = trpc.dashboard.getEventFeed.useQuery({ limit: 10 });
  const [alertData, setAlertData] = useState<any[]>([]);
  const [incidentData, setIncidentData] = useState<any[]>([]);

  useEffect(() => {
    if (metricsQuery.data?.alertStats) {
      const stats = metricsQuery.data.alertStats.map((stat: any) => ({
        name: stat.severity,
        value: stat.count,
      }));
      setAlertData(stats);
    }
  }, [metricsQuery.data?.alertStats]);

  useEffect(() => {
    if (metricsQuery.data?.incidentStats) {
      const stats = metricsQuery.data.incidentStats.map((stat: any) => ({
        name: stat.status,
        value: stat.count,
      }));
      setIncidentData(stats);
    }
  }, [metricsQuery.data?.incidentStats]);

  const severityColors: Record<string, string> = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#3b82f6",
  };

  const statusColors: Record<string, string> = {
    open: "#ef4444",
    investigating: "#eab308",
    contained: "#3b82f6",
    resolved: "#22c55e",
  };

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case "critical":
        return "severity-critical";
      case "high":
        return "severity-high";
      case "medium":
        return "severity-medium";
      case "low":
        return "severity-low";
      default:
        return "severity-low";
    }
  };

  const getStatusClass = (status: string) => {
    switch (status) {
      case "open":
        return "status-open";
      case "investigating":
        return "status-investigating";
      case "contained":
        return "status-contained";
      case "resolved":
        return "status-resolved";
      default:
        return "status-open";
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Shield className="w-10 h-10 text-accent neon-glow" />
            Security Operations Center
          </h1>
          <p className="text-muted-foreground">Real-time threat monitoring and incident management</p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-500" />
                Critical Alerts
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-red-500">
                {alertData.find(d => d.name === "critical")?.value || 0}
              </div>
              <p className="text-xs text-muted-foreground mt-1">Requires immediate attention</p>
            </CardContent>
          </Card>

          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Activity className="w-4 h-4 text-orange-500" />
                High Priority
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-orange-500">
                {alertData.find(d => d.name === "high")?.value || 0}
              </div>
              <p className="text-xs text-muted-foreground mt-1">Active investigations</p>
            </CardContent>
          </Card>

          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Zap className="w-4 h-4 text-yellow-500" />
                Open Incidents
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-yellow-500">
                {incidentData.find(d => d.name === "open")?.value || 0}
              </div>
              <p className="text-xs text-muted-foreground mt-1">Unresolved cases</p>
            </CardContent>
          </Card>

          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Shield className="w-4 h-4 text-green-500" />
                Resolved
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-green-500">
                {incidentData.find(d => d.name === "resolved")?.value || 0}
              </div>
              <p className="text-xs text-muted-foreground mt-1">Closed incidents</p>
            </CardContent>
          </Card>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Alert Severity Distribution */}
          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader>
              <CardTitle>Alert Severity Distribution</CardTitle>
              <CardDescription>Distribution of alerts by severity level</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={alertData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {alertData.map((entry: any) => (
                      <Cell key={`cell-${entry.name}`} fill={severityColors[entry.name] || "#888"} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Incident Status Distribution */}
          <Card className="neon-border bg-card/50 backdrop-blur">
            <CardHeader>
              <CardTitle>Incident Status Overview</CardTitle>
              <CardDescription>Current state of all incidents</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={incidentData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="name" stroke="#888" />
                  <YAxis stroke="#888" />
                  <Tooltip contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #444" }} />
                  <Bar dataKey="value" fill="#a855f7" radius={[8, 8, 0, 0]}>
                    {incidentData.map((entry: any) => (
                      <Cell key={`cell-${entry.name}`} fill={statusColors[entry.name] || "#888"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Event Feed */}
        <Card className="neon-border bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle>Live Event Feed</CardTitle>
            <CardDescription>Real-time security events</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {eventFeedQuery.data && eventFeedQuery.data.length > 0 ? (
                eventFeedQuery.data.map((event: any) => (
                  <div key={event.id} className="p-3 bg-background/50 border border-border rounded-lg hover:border-accent/50 transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-sm text-accent">{event.eventType}</span>
                          <Badge className={getSeverityClass(event.severity)}>
                            {event.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-foreground/80">{event.hostname || event.sourceIp}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {event.eventCategory && `Category: ${event.eventCategory}`}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">
                          {new Date(event.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No events recorded yet
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
