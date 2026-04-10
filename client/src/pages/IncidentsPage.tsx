import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertTriangle, FileText, Clock } from "lucide-react";
import { toast } from "sonner";

export default function IncidentsPage() {
  const [incidentForm, setIncidentForm] = useState({
    title: "",
    description: "",
    severity: "high" as const,
    classification: "",
  });

  const [selectedIncident, setSelectedIncident] = useState<any>(null);
  const [playbookStep, setPlaybookStep] = useState({
    stepNumber: 1,
    title: "",
    description: "",
  });

  const incidentsQuery = trpc.incidents.list.useQuery({ limit: 50 });
  const createIncidentMutation = trpc.incidents.create.useMutation({
    onSuccess: () => {
      toast.success("Incident created");
      setIncidentForm({ title: "", description: "", severity: "high", classification: "" });
      incidentsQuery.refetch();
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const updateStatusMutation = trpc.incidents.updateStatus.useMutation({
    onSuccess: () => {
      toast.success("Incident status updated");
      incidentsQuery.refetch();
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const addPlaybookStepMutation = trpc.incidents.addPlaybookStep.useMutation({
    onSuccess: () => {
      toast.success("Playbook step added");
      setPlaybookStep({ stepNumber: 1, title: "", description: "" });
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`);
    },
  });

  const handleCreateIncident = () => {
    if (!incidentForm.title) {
      toast.error("Title is required");
      return;
    }
    createIncidentMutation.mutate(incidentForm);
  };

  const handleAddPlaybookStep = () => {
    if (!selectedIncident || !playbookStep.title) {
      toast.error("Incident and step title are required");
      return;
    }
    addPlaybookStepMutation.mutate({
      incidentId: selectedIncident.id,
      ...playbookStep,
    });
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
      <div className="max-w-6xl mx-auto">
        <h1 className="text-4xl font-bold mb-8 flex items-center gap-3">
          <AlertTriangle className="w-10 h-10 text-red-500 neon-glow" />
          Incident Response Center
        </h1>

        {/* Create Incident */}
        <Card className="neon-border bg-card/50 backdrop-blur mb-8">
          <CardHeader>
            <CardTitle>Create New Incident</CardTitle>
            <CardDescription>Register and track security incidents</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium mb-2 block">Title</label>
                <Input
                  placeholder="e.g., Suspected Data Breach"
                  value={incidentForm.title}
                  onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })}
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-2 block">Severity</label>
                <Select value={incidentForm.severity} onValueChange={(val: any) => setIncidentForm({ ...incidentForm, severity: val })}>
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
            <div>
              <label className="text-sm font-medium mb-2 block">Description</label>
              <Textarea
                placeholder="Detailed incident description..."
                value={incidentForm.description}
                onChange={(e) => setIncidentForm({ ...incidentForm, description: e.target.value })}
                rows={3}
              />
            </div>
            <Button onClick={handleCreateIncident} className="w-full" disabled={createIncidentMutation.isPending}>
              {createIncidentMutation.isPending ? "Creating..." : "Create Incident"}
            </Button>
          </CardContent>
        </Card>

        {/* Incidents List */}
        <div className="space-y-4">
          <h2 className="text-2xl font-bold">Active Incidents</h2>
          {incidentsQuery.data && incidentsQuery.data.length > 0 ? (
            incidentsQuery.data.map((incident: any) => (
              <Card key={incident.id} className="neon-border bg-card/50 backdrop-blur hover:border-accent/50 transition-colors">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-lg flex items-center gap-2">
                        {incident.title}
                        <Badge className={getSeverityClass(incident.severity)}>
                          {incident.severity}
                        </Badge>
                        <Badge className={getStatusClass(incident.status)}>
                          {incident.status}
                        </Badge>
                      </CardTitle>
                      <CardDescription className="mt-2">{incident.description}</CardDescription>
                    </div>
                    <Dialog>
                      <DialogTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setSelectedIncident(incident)}
                        >
                          Manage
                        </Button>
                      </DialogTrigger>
                      <DialogContent className="max-w-2xl bg-card border-border">
                        <DialogHeader>
                          <DialogTitle>{incident.title}</DialogTitle>
                          <DialogDescription>
                            Incident ID: {incident.incidentId}
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div>
                            <label className="text-sm font-medium mb-2 block">Update Status</label>
                            <Select
                              defaultValue={incident.status}
                              onValueChange={(status) => {
                                updateStatusMutation.mutate({
                                  id: incident.id,
                                  status: status as any,
                                });
                              }}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="open">Open</SelectItem>
                                <SelectItem value="investigating">Investigating</SelectItem>
                                <SelectItem value="contained">Contained</SelectItem>
                                <SelectItem value="resolved">Resolved</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>

                          <div className="border-t border-border pt-4">
                            <h3 className="font-semibold mb-3">Response Playbook</h3>
                            <div className="space-y-3">
                              <div>
                                <label className="text-sm font-medium mb-2 block">Step Title</label>
                                <Input
                                  placeholder="e.g., Isolate affected systems"
                                  value={playbookStep.title}
                                  onChange={(e) => setPlaybookStep({ ...playbookStep, title: e.target.value })}
                                />
                              </div>
                              <div>
                                <label className="text-sm font-medium mb-2 block">Description</label>
                                <Textarea
                                  placeholder="Step details..."
                                  value={playbookStep.description}
                                  onChange={(e) => setPlaybookStep({ ...playbookStep, description: e.target.value })}
                                  rows={2}
                                />
                              </div>
                              <Button
                                onClick={handleAddPlaybookStep}
                                className="w-full"
                                disabled={addPlaybookStepMutation.isPending}
                              >
                                {addPlaybookStepMutation.isPending ? "Adding..." : "Add Playbook Step"}
                              </Button>
                            </div>
                          </div>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </div>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  <div className="flex items-center gap-4">
                    <span className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      {new Date(incident.createdAt).toLocaleString()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))
          ) : (
            <Card className="neon-border bg-card/50 backdrop-blur">
              <CardContent className="text-center py-8 text-muted-foreground">
                No incidents recorded
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
