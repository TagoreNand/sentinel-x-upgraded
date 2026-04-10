import { nanoid } from "nanoid";
import * as db from "../db";

export async function executeSoarPlaybook(input: {
  playbookId: number;
  incidentId?: number;
  triggerEntityType?: string;
  triggerEntityId?: string;
  userId?: number;
}) {
  const playbook = await db.getSoarPlaybookById(input.playbookId);
  if (!playbook) {
    throw new Error("SOAR playbook not found");
  }

  const steps = Array.isArray(playbook.steps) ? playbook.steps : [];
  const output = steps.map((step: any, index: number) => ({
    step: index + 1,
    name: step.name ?? `Step ${index + 1}`,
    action: step.action ?? "observe",
    status: "completed",
    note: step.action === "contain-host"
      ? "Containment action simulated and recorded"
      : step.action === "disable-user"
        ? "Identity disablement prepared for analyst approval"
        : step.action === "create-ticket"
          ? "Ticket payload generated"
          : "Action completed in simulation mode",
  }));

  const executionInsert = await db.createSoarExecution({
    executionId: nanoid(),
    playbookId: input.playbookId,
    incidentId: input.incidentId,
    triggerEntityType: input.triggerEntityType,
    triggerEntityId: input.triggerEntityId,
    status: "completed",
    output,
    startedAt: new Date(),
    completedAt: new Date(),
    createdAt: new Date(),
  });

  if (input.incidentId) {
    await db.addIncidentAuditTrail({
      incidentId: input.incidentId,
      action: `SOAR playbook executed: ${playbook.name}`,
      performedBy: input.userId,
      details: { playbookId: playbook.playbookId, steps: output },
      timestamp: new Date(),
    });
  }

  return {
    executionId: Number((executionInsert as any)?.insertId || 0),
    playbook: { id: playbook.id, name: playbook.name },
    output,
  };
}
