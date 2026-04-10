import { eq, desc, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertUser,
  users,
  InsertSecurityEvent,
  securityEvents,
  InsertAlert,
  alerts,
  InsertIncident,
  incidents,
  incidentPlaybooks,
  incidentAuditTrail,
  InsertIndicatorOfCompromise,
  indicatorsOfCompromise,
  threatActors,
  InsertVulnerabilityScan,
  vulnerabilityScans,
  vulnerabilities,
  InsertIdsRule,
  idsRules,
  idsDetections,
  InsertForensicsEvidence,
  forensicsEvidence,
  forensicsTimeline,
  forensicsCustodyEvents,
  investigationArtifacts,
  InsertAsset,
  assets,
  InsertHoneypot,
  honeypots,
  honeypotInteractions,
  iamEvents,
  endpointTelemetry,
  cloudFindings,
  phishingAnalyses,
  soarPlaybooks,
  soarExecutions,
  platformAuditLogs,
  cveDatabase,
} from "../drizzle/schema";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

// ============================================================================
// ASSETS
// ============================================================================

export async function createAsset(asset: InsertAsset) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(assets).values(asset);
}

export async function getAssets(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(assets).orderBy(desc(assets.updatedAt)).limit(limit);
}

export async function getAssetById(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(assets).where(eq(assets.id, id)).limit(1);
  return result[0];
}

export async function findAssetByHostnameOrIp(hostname?: string | null, ipAddress?: string | null) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  if (hostname) {
    const hostResult = await db.select().from(assets).where(eq(assets.hostname, hostname)).limit(1);
    if (hostResult[0]) return hostResult[0];
  }

  if (ipAddress) {
    const ipResult = await db.select().from(assets).where(eq(assets.ipAddress, ipAddress)).limit(1);
    if (ipResult[0]) return ipResult[0];
  }

  return undefined;
}

// ============================================================================
// SECURITY EVENTS & ALERTS
// ============================================================================

export async function createSecurityEvent(event: InsertSecurityEvent) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(securityEvents).values(event);
}

export async function getSecurityEvents(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(securityEvents).orderBy(desc(securityEvents.timestamp)).limit(limit).offset(offset);
}

export async function getSecurityEventsBySeverity(severity: string, limit = 50) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(securityEvents).where(eq(securityEvents.severity, severity as any)).orderBy(desc(securityEvents.timestamp)).limit(limit);
}

export async function getRecentSecurityEvents(limit = 250) {
  return getSecurityEvents(limit, 0);
}

export async function createAlert(alert: InsertAlert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(alerts).values(alert);
}

export async function getAlerts(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(alerts).orderBy(desc(alerts.timestamp)).limit(limit).offset(offset);
}

export async function updateAlertIncident(alertId: number, incidentId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.update(alerts).set({ incidentId, updatedAt: new Date() }).where(eq(alerts.id, alertId));
}

export async function getAlertStats() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  return await db
    .select({
      severity: alerts.severity,
      count: sql<number>`COUNT(*)`,
    })
    .from(alerts)
    .groupBy(alerts.severity);
}

// ============================================================================
// INCIDENTS
// ============================================================================

export async function createIncident(incident: InsertIncident) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(incidents).values(incident);
}

export async function getIncidents(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(incidents).orderBy(desc(incidents.createdAt)).limit(limit).offset(offset);
}

export async function getIncidentById(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(incidents).where(eq(incidents.id, id));
  return result[0];
}

export async function getIncidentsByStatus(status: string) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(incidents).where(eq(incidents.status, status as any)).orderBy(desc(incidents.createdAt));
}

export async function updateIncidentStatus(id: number, status: string) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.update(incidents).set({ status: status as any, updatedAt: new Date() }).where(eq(incidents.id, id));
}

export async function getIncidentStats() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db
    .select({
      status: incidents.status,
      count: sql<number>`COUNT(*)`,
    })
    .from(incidents)
    .groupBy(incidents.status);
}

export async function addIncidentPlaybookStep(step: typeof incidentPlaybooks.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(incidentPlaybooks).values(step);
}

export async function getIncidentPlaybookSteps(incidentId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(incidentPlaybooks).where(eq(incidentPlaybooks.incidentId, incidentId)).orderBy(incidentPlaybooks.stepNumber);
}

export async function addIncidentAuditTrail(entry: typeof incidentAuditTrail.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(incidentAuditTrail).values(entry);
}

export async function getIncidentAuditTrail(incidentId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(incidentAuditTrail).where(eq(incidentAuditTrail.incidentId, incidentId)).orderBy(desc(incidentAuditTrail.timestamp));
}

// ============================================================================
// THREAT INTELLIGENCE
// ============================================================================

export async function createIOC(ioc: InsertIndicatorOfCompromise) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(indicatorsOfCompromise).values(ioc);
}

export async function getIOCs(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(indicatorsOfCompromise).orderBy(desc(indicatorsOfCompromise.createdAt)).limit(limit).offset(offset);
}

export async function searchIOC(value: string) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(indicatorsOfCompromise).where(sql`${indicatorsOfCompromise.iocValue} LIKE ${`%${value}%`}`);
}

export async function createThreatActor(actor: typeof threatActors.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(threatActors).values(actor);
}

export async function getThreatActors(limit = 50) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(threatActors).orderBy(desc(threatActors.knownIncidents)).limit(limit);
}

export async function getCVEs(limit = 100, offset = 0) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(cveDatabase).orderBy(desc(cveDatabase.publishedDate)).limit(limit).offset(offset);
}

export async function getAllCVEs(limit = 1000) {
  return getCVEs(limit, 0);
}

export async function searchCVE(cveId: string) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(cveDatabase).where(eq(cveDatabase.cveId, cveId));
  return result[0];
}

// ============================================================================
// VULNERABILITY SCANNING
// ============================================================================

export async function createVulnerabilityScan(scan: InsertVulnerabilityScan) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(vulnerabilityScans).values(scan);
}

export async function updateVulnerabilityScan(id: number, changes: Partial<typeof vulnerabilityScans.$inferInsert>) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.update(vulnerabilityScans).set(changes as any).where(eq(vulnerabilityScans.id, id));
}

export async function getVulnerabilityScans(limit = 50) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(vulnerabilityScans).orderBy(desc(vulnerabilityScans.createdAt)).limit(limit);
}

export async function getVulnerabilitiesByScan(scanId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));
}

export async function createVulnerability(vuln: typeof vulnerabilities.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(vulnerabilities).values(vuln);
}

// ============================================================================
// INTRUSION DETECTION
// ============================================================================

export async function createIdsRule(rule: InsertIdsRule) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(idsRules).values(rule);
}

export async function getIdsRules(enabled = true) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(idsRules).where(eq(idsRules.enabled, enabled)).orderBy(desc(idsRules.updatedAt));
}

export async function createIdsDetection(detection: typeof idsDetections.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(idsDetections).values(detection);
}

export async function getIdsDetections(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(idsDetections).orderBy(desc(idsDetections.timestamp)).limit(limit);
}

// ============================================================================
// DIGITAL FORENSICS
// ============================================================================

export async function createForensicsEvidence(evidence: InsertForensicsEvidence) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(forensicsEvidence).values(evidence);
}

export async function getForensicsEvidenceByIncident(incidentId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(forensicsEvidence).where(eq(forensicsEvidence.incidentId, incidentId));
}

export async function getEvidenceById(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(forensicsEvidence).where(eq(forensicsEvidence.id, id)).limit(1);
  return result[0];
}

export async function createForensicsCustodyEvent(event: typeof forensicsCustodyEvents.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(forensicsCustodyEvents).values(event);
}

export async function getForensicsCustodyEvents(evidenceId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(forensicsCustodyEvents).where(eq(forensicsCustodyEvents.evidenceId, evidenceId)).orderBy(desc(forensicsCustodyEvents.timestamp));
}

export async function createForensicsTimeline(timeline: typeof forensicsTimeline.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(forensicsTimeline).values(timeline);
}

export async function getForensicsTimeline(incidentId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(forensicsTimeline).where(eq(forensicsTimeline.incidentId, incidentId)).orderBy(forensicsTimeline.eventTimestamp);
}

export async function createInvestigationArtifact(artifact: typeof investigationArtifacts.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(investigationArtifacts).values(artifact);
}

export async function getInvestigationArtifacts(incidentId: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(investigationArtifacts).where(eq(investigationArtifacts.incidentId, incidentId)).orderBy(desc(investigationArtifacts.createdAt));
}

// ============================================================================
// HONEYPOT
// ============================================================================

export async function createHoneypot(honeypot: InsertHoneypot) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(honeypots).values(honeypot);
}

export async function getHoneypots() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(honeypots);
}

export async function createHoneypotInteraction(interaction: typeof honeypotInteractions.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(honeypotInteractions).values(interaction);
}

export async function getHoneypotInteractions(honeypotId: number, limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(honeypotInteractions).where(eq(honeypotInteractions.honeypotId, honeypotId)).orderBy(desc(honeypotInteractions.timestamp)).limit(limit);
}

export async function getHoneypotInteractionsByAttackerIp(ip: string) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(honeypotInteractions).where(eq(honeypotInteractions.attackerIp, ip)).orderBy(desc(honeypotInteractions.timestamp));
}

// ============================================================================
// IAM / ENDPOINT / CLOUD / PHISHING / SOAR
// ============================================================================

export async function createIamEvent(event: typeof iamEvents.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(iamEvents).values(event);
}

export async function getIamEvents(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(iamEvents).orderBy(desc(iamEvents.timestamp)).limit(limit);
}

export async function createEndpointTelemetry(telemetry: typeof endpointTelemetry.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(endpointTelemetry).values(telemetry);
}

export async function getEndpointTelemetry(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(endpointTelemetry).orderBy(desc(endpointTelemetry.timestamp)).limit(limit);
}

export async function createCloudFinding(finding: typeof cloudFindings.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(cloudFindings).values(finding);
}

export async function getCloudFindings(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(cloudFindings).orderBy(desc(cloudFindings.timestamp)).limit(limit);
}

export async function createPhishingAnalysis(analysis: typeof phishingAnalyses.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(phishingAnalyses).values(analysis);
}

export async function getPhishingAnalyses(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(phishingAnalyses).orderBy(desc(phishingAnalyses.createdAt)).limit(limit);
}

export async function createSoarPlaybook(playbook: typeof soarPlaybooks.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(soarPlaybooks).values(playbook);
}

export async function getSoarPlaybooks(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(soarPlaybooks).orderBy(desc(soarPlaybooks.updatedAt)).limit(limit);
}

export async function getSoarPlaybookById(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(soarPlaybooks).where(eq(soarPlaybooks.id, id)).limit(1);
  return result[0];
}

export async function createSoarExecution(execution: typeof soarExecutions.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(soarExecutions).values(execution);
}

export async function getSoarExecutions(limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(soarExecutions).orderBy(desc(soarExecutions.startedAt)).limit(limit);
}

// ============================================================================
// AUDIT
// ============================================================================

export async function createPlatformAuditLog(entry: typeof platformAuditLogs.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.insert(platformAuditLogs).values(entry);
}

export async function getPlatformAuditLogs(limit = 200) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(platformAuditLogs).orderBy(desc(platformAuditLogs.createdAt)).limit(limit);
}
