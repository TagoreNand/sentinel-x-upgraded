import { and, eq, desc, gte, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import mysql, { type Pool } from "mysql2/promise";
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
  ingestJobs,
  type IngestJob,
  notificationChannels,
  type NotificationChannel,
  type InsertNotificationChannel,
  notificationDeliveries,
  type InsertNotificationDelivery,
} from "../drizzle/schema";
import { ENV, envNumber, resolveDefaultRole } from "./_core/env";
import type { Role } from "@shared/roles";
import { DatabaseUnavailableError } from "./_core/errors";
import { logger } from "./_core/logger";

const log = logger.child({ component: "db" });

/**
 * Connection management.
 *
 * A single explicit mysql2 pool, sized via env, shared by the whole process.
 * Why explicit instead of `drizzle(DATABASE_URL)`: the implicit form gives no
 * control over pool size or queueing. Under ingestion load, an unbounded
 * connection queue converts a slow database into unbounded memory growth and
 * multi-second latencies that outlive the spike. A bounded `queueLimit`
 * fails the excess requests fast instead — callers get a retryable error and
 * the pod stays healthy (backpressure, not buffering).
 *
 * `getDb()` THROWS when the database is unconfigured/unavailable. The old
 * behavior returned null and let each caller decide — which is how a silent
 * user-record drop shipped in `upsertUser`. Availability is not a per-call
 * policy decision; it is an invariant.
 */
function createDrizzle(pool: Pool) {
  return drizzle(pool);
}
type Db = ReturnType<typeof createDrizzle>;

let _pool: Pool | null = null;
let _db: Db | null = null;

export async function getDb(): Promise<Db> {
  // No await between the check and the assignments below, so concurrent
  // callers cannot double-initialize the pool (single-threaded event loop).
  if (_db) return _db;
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new DatabaseUnavailableError("DATABASE_URL is not configured");
  }
  const connectionLimit = envNumber("DB_POOL_SIZE", 10);
  const pool = mysql.createPool({
    uri: url,
    connectionLimit,
    waitForConnections: true,
    queueLimit: envNumber("DB_POOL_QUEUE_LIMIT", 200),
    enableKeepAlive: true,
    keepAliveInitialDelay: 10_000,
  });
  const db = createDrizzle(pool);
  _pool = pool;
  _db = db;
  log.info("database pool initialized", { connectionLimit });
  return db;
}

/** Readiness-probe hook: cheap round-trip with a hard deadline. */
export async function pingDb(timeoutMs = 2000): Promise<void> {
  const db = await getDb();
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      db.execute(sql`SELECT 1`),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new DatabaseUnavailableError("Database ping timed out")), timeoutMs);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Graceful-shutdown hook: drains in-flight queries, then closes sockets. */
export async function closeDb(): Promise<void> {
  if (_pool) {
    const pool = _pool;
    _pool = null;
    _db = null;
    await pool.end();
    log.info("database pool closed");
  }
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  // Fail loudly if the database is down. Pretending a login succeeded while
  // dropping the user record corrupts the identity source of truth.
  const db = await getDb();

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
      // Explicit role from the caller (e.g. an admin-initiated role change).
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      // Owner is a permanent admin anchor, re-asserted on every login so the
      // platform can never be left without an admin.
      values.role = "admin";
      updateSet.role = "admin";
    } else {
      // New user: assign the configured default on INSERT only. Deliberately
      // absent from updateSet so a returning user's assigned role (an admin
      // promotion, a lead grant) survives their next login instead of being
      // reset to the default.
      values.role = resolveDefaultRole();
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
    log.error("failed to upsert user", error, { openId: user.openId });
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

export async function getUserById(id: number) {
  const db = await getDb();
  const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return result[0];
}

/** User directory for the admin role-management surface. */
export async function getUsers(limit = 200) {
  const db = await getDb();
  return await db
    .select({
      id: users.id,
      openId: users.openId,
      name: users.name,
      email: users.email,
      role: users.role,
      loginMethod: users.loginMethod,
      lastSignedIn: users.lastSignedIn,
      createdAt: users.createdAt,
    })
    .from(users)
    .orderBy(desc(users.createdAt))
    .limit(limit);
}

export async function updateUserRole(id: number, role: Role): Promise<void> {
  const db = await getDb();
  await db.update(users).set({ role, updatedAt: new Date() }).where(eq(users.id, id));
}

// ============================================================================
// ASSETS
// ============================================================================

export async function createAsset(asset: InsertAsset) {
  const db = await getDb();
  return await db.insert(assets).values(asset);
}

export async function getAssets(limit = 100) {
  const db = await getDb();
  return await db.select().from(assets).orderBy(desc(assets.updatedAt)).limit(limit);
}

export async function getAssetById(id: number) {
  const db = await getDb();
  const result = await db.select().from(assets).where(eq(assets.id, id)).limit(1);
  return result[0];
}

/** Escape LIKE wildcards so a hostname containing % or _ cannot widen the match. */
function escapeLikePattern(value: string): string {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

export async function findAssetByHostnameOrIp(hostname?: string | null, ipAddress?: string | null) {
  const db = await getDb();

  if (hostname) {
    const hostResult = await db.select().from(assets).where(eq(assets.hostname, hostname)).limit(1);
    if (hostResult[0]) return hostResult[0];

    // Syslog reports short hostnames ("web-01") while asset inventories are
    // typically keyed by FQDN ("web-01.prod.internal"). Fall back to an
    // FQDN-prefix match — a leading-anchored LIKE, so idx_asset_hostname
    // still serves it as a range scan. Only for short names: prefixing an
    // already-qualified name would invite cross-domain false positives.
    if (!hostname.includes(".")) {
      const fqdnResult = await db
        .select()
        .from(assets)
        .where(sql`${assets.hostname} LIKE ${`${escapeLikePattern(hostname)}.%`}`)
        .limit(1);
      if (fqdnResult[0]) return fqdnResult[0];
    }
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
  return await db.insert(securityEvents).values(event);
}

export async function getSecurityEvents(limit = 100, offset = 0) {
  const db = await getDb();
  return await db.select().from(securityEvents).orderBy(desc(securityEvents.timestamp)).limit(limit).offset(offset);
}

export async function getSecurityEventsBySeverity(severity: string, limit = 50) {
  const db = await getDb();
  return await db.select().from(securityEvents).where(eq(securityEvents.severity, severity as any)).orderBy(desc(securityEvents.timestamp)).limit(limit);
}

export async function getRecentSecurityEvents(limit = 250) {
  return getSecurityEvents(limit, 0);
}

/**
 * Threshold-rule support: SQL COUNT over an indexed (field, timestamp) range
 * instead of loading the latest N events into application memory. Counting in
 * the database is O(matching rows via index) and — critically — sees every
 * committed event, not a 300-row snapshot that silently under-counts during
 * a burst (exactly when threshold rules matter most).
 */
export async function countRecentEventsByField(
  field: "sourceIp" | "username",
  value: string,
  since: Date,
): Promise<number> {
  const db = await getDb();
  const column = field === "sourceIp" ? securityEvents.sourceIp : securityEvents.username;
  const rows = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(securityEvents)
    .where(and(eq(column, value), gte(securityEvents.timestamp, since)));
  return Number(rows[0]?.count ?? 0);
}

export async function createAlert(alert: InsertAlert) {
  const db = await getDb();
  return await db.insert(alerts).values(alert);
}

export async function getAlerts(limit = 100, offset = 0) {
  const db = await getDb();
  return await db.select().from(alerts).orderBy(desc(alerts.timestamp)).limit(limit).offset(offset);
}

export async function updateAlertIncident(alertId: number, incidentId: number) {
  const db = await getDb();
  return await db.update(alerts).set({ incidentId, updatedAt: new Date() }).where(eq(alerts.id, alertId));
}

export async function getAlertStats() {
  const db = await getDb();

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

/**
 * Returns the numeric PK of the created incident. Callers previously read
 * `.insertId` off the raw driver result — which is a [ResultSetHeader,
 * FieldPacket[]] tuple, so that property was always undefined and every
 * downstream link (detections, phishing analyses) silently stored 0/NULL.
 * $returningId() is the typed, driver-shape-proof way to get the PK.
 */
export async function createIncident(incident: InsertIncident): Promise<number> {
  const db = await getDb();
  const [row] = await db.insert(incidents).values(incident).$returningId();
  return row.id;
}

export async function getIncidents(limit = 100, offset = 0) {
  const db = await getDb();
  return await db.select().from(incidents).orderBy(desc(incidents.createdAt)).limit(limit).offset(offset);
}

export async function getIncidentById(id: number) {
  const db = await getDb();
  const result = await db.select().from(incidents).where(eq(incidents.id, id));
  return result[0];
}

/**
 * Idempotency lookup for pipeline-created incidents. The unique index on
 * correlationKey is the actual dedup guarantee (survives concurrent writers);
 * this query is how the losing writer finds the incident that won.
 */
export async function findIncidentByCorrelationKey(correlationKey: string) {
  const db = await getDb();
  const result = await db.select().from(incidents).where(eq(incidents.correlationKey, correlationKey)).limit(1);
  return result[0];
}

export async function getIncidentsByStatus(status: string) {
  const db = await getDb();
  return await db.select().from(incidents).where(eq(incidents.status, status as any)).orderBy(desc(incidents.createdAt));
}

export async function updateIncidentStatus(id: number, status: string) {
  const db = await getDb();
  return await db.update(incidents).set({ status: status as any, updatedAt: new Date() }).where(eq(incidents.id, id));
}

export async function getIncidentStats() {
  const db = await getDb();
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
  return await db.insert(incidentPlaybooks).values(step);
}

export async function getIncidentPlaybookSteps(incidentId: number) {
  const db = await getDb();
  return await db.select().from(incidentPlaybooks).where(eq(incidentPlaybooks.incidentId, incidentId)).orderBy(incidentPlaybooks.stepNumber);
}

export async function addIncidentAuditTrail(entry: typeof incidentAuditTrail.$inferInsert) {
  const db = await getDb();
  return await db.insert(incidentAuditTrail).values(entry);
}

export async function getIncidentAuditTrail(incidentId: number) {
  const db = await getDb();
  return await db.select().from(incidentAuditTrail).where(eq(incidentAuditTrail.incidentId, incidentId)).orderBy(desc(incidentAuditTrail.timestamp));
}

// ============================================================================
// THREAT INTELLIGENCE
// ============================================================================

export async function createIOC(ioc: InsertIndicatorOfCompromise) {
  const db = await getDb();
  return await db.insert(indicatorsOfCompromise).values(ioc);
}

export async function getIOCs(limit = 100, offset = 0) {
  const db = await getDb();
  return await db.select().from(indicatorsOfCompromise).orderBy(desc(indicatorsOfCompromise.createdAt)).limit(limit).offset(offset);
}

/**
 * Analyst-facing free-text IOC search. Bounded because a leading-wildcard
 * LIKE cannot use idx_ioc_value and will scan; the LIMIT caps the damage on
 * this low-frequency UI path. The hot path (per-event enrichment) must never
 * use this — it uses findIOCsByValues below, which is an exact indexed match.
 */
export async function searchIOC(value: string) {
  const db = await getDb();
  return await db
    .select()
    .from(indicatorsOfCompromise)
    .where(sql`${indicatorsOfCompromise.iocValue} LIKE ${`%${value}%`}`)
    .limit(100);
}

/**
 * Exact-match IOC lookup for pipeline enrichment: one indexed IN() query for
 * all candidate observables of an event, instead of paging 500 IOC rows into
 * memory per event. Only "active" indicators participate in detection.
 */
export async function findIOCsByValues(values: string[]) {
  if (values.length === 0) return [];
  const db = await getDb();
  return await db
    .select()
    .from(indicatorsOfCompromise)
    .where(and(inArray(indicatorsOfCompromise.iocValue, values), eq(indicatorsOfCompromise.status, "active")))
    .limit(100);
}

export async function createThreatActor(actor: typeof threatActors.$inferInsert) {
  const db = await getDb();
  return await db.insert(threatActors).values(actor);
}

export async function getThreatActors(limit = 50) {
  const db = await getDb();
  return await db.select().from(threatActors).orderBy(desc(threatActors.knownIncidents)).limit(limit);
}

export async function getCVEs(limit = 100, offset = 0) {
  const db = await getDb();
  return await db.select().from(cveDatabase).orderBy(desc(cveDatabase.publishedDate)).limit(limit).offset(offset);
}

export async function getAllCVEs(limit = 1000) {
  return getCVEs(limit, 0);
}

export async function searchCVE(cveId: string) {
  const db = await getDb();
  const result = await db.select().from(cveDatabase).where(eq(cveDatabase.cveId, cveId));
  return result[0];
}

// ============================================================================
// VULNERABILITY SCANNING
// ============================================================================

/** Returns the numeric PK so findings can be linked to their scan. */
export async function createVulnerabilityScan(scan: InsertVulnerabilityScan): Promise<number> {
  const db = await getDb();
  const [row] = await db.insert(vulnerabilityScans).values(scan).$returningId();
  return row.id;
}

export async function updateVulnerabilityScan(id: number, changes: Partial<typeof vulnerabilityScans.$inferInsert>) {
  const db = await getDb();
  return await db.update(vulnerabilityScans).set(changes as any).where(eq(vulnerabilityScans.id, id));
}

export async function getVulnerabilityScans(limit = 50) {
  const db = await getDb();
  return await db.select().from(vulnerabilityScans).orderBy(desc(vulnerabilityScans.createdAt)).limit(limit);
}

export async function getVulnerabilitiesByScan(scanId: number) {
  const db = await getDb();
  return await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));
}

export async function createVulnerability(vuln: typeof vulnerabilities.$inferInsert) {
  const db = await getDb();
  return await db.insert(vulnerabilities).values(vuln);
}

// ============================================================================
// INTRUSION DETECTION
// ============================================================================

export async function createIdsRule(rule: InsertIdsRule) {
  const db = await getDb();
  return await db.insert(idsRules).values(rule);
}

export async function getIdsRules(enabled = true) {
  const db = await getDb();
  return await db.select().from(idsRules).where(eq(idsRules.enabled, enabled)).orderBy(desc(idsRules.updatedAt));
}

export async function createIdsDetection(detection: typeof idsDetections.$inferInsert) {
  const db = await getDb();
  return await db.insert(idsDetections).values(detection);
}

export async function getIdsDetections(limit = 100) {
  const db = await getDb();
  return await db.select().from(idsDetections).orderBy(desc(idsDetections.timestamp)).limit(limit);
}

// ============================================================================
// DIGITAL FORENSICS
// ============================================================================

/**
 * Returns the numeric PK. The chain-of-custody trail hangs off this id —
 * with the old broken insertId extraction it was never written at all.
 */
export async function createForensicsEvidence(evidence: InsertForensicsEvidence): Promise<number> {
  const db = await getDb();
  const [row] = await db.insert(forensicsEvidence).values(evidence).$returningId();
  return row.id;
}

export async function getForensicsEvidenceByIncident(incidentId: number) {
  const db = await getDb();
  return await db.select().from(forensicsEvidence).where(eq(forensicsEvidence.incidentId, incidentId));
}

export async function getEvidenceById(id: number) {
  const db = await getDb();
  const result = await db.select().from(forensicsEvidence).where(eq(forensicsEvidence.id, id)).limit(1);
  return result[0];
}

export async function createForensicsCustodyEvent(event: typeof forensicsCustodyEvents.$inferInsert) {
  const db = await getDb();
  return await db.insert(forensicsCustodyEvents).values(event);
}

export async function getForensicsCustodyEvents(evidenceId: number) {
  const db = await getDb();
  return await db.select().from(forensicsCustodyEvents).where(eq(forensicsCustodyEvents.evidenceId, evidenceId)).orderBy(desc(forensicsCustodyEvents.timestamp));
}

export async function createForensicsTimeline(timeline: typeof forensicsTimeline.$inferInsert) {
  const db = await getDb();
  return await db.insert(forensicsTimeline).values(timeline);
}

export async function getForensicsTimeline(incidentId: number) {
  const db = await getDb();
  return await db.select().from(forensicsTimeline).where(eq(forensicsTimeline.incidentId, incidentId)).orderBy(forensicsTimeline.eventTimestamp);
}

export async function createInvestigationArtifact(artifact: typeof investigationArtifacts.$inferInsert) {
  const db = await getDb();
  return await db.insert(investigationArtifacts).values(artifact);
}

export async function getInvestigationArtifacts(incidentId: number) {
  const db = await getDb();
  return await db.select().from(investigationArtifacts).where(eq(investigationArtifacts.incidentId, incidentId)).orderBy(desc(investigationArtifacts.createdAt));
}

// ============================================================================
// HONEYPOT
// ============================================================================

export async function createHoneypot(honeypot: InsertHoneypot) {
  const db = await getDb();
  return await db.insert(honeypots).values(honeypot);
}

export async function getHoneypots() {
  const db = await getDb();
  return await db.select().from(honeypots);
}

export async function createHoneypotInteraction(interaction: typeof honeypotInteractions.$inferInsert) {
  const db = await getDb();
  return await db.insert(honeypotInteractions).values(interaction);
}

export async function getHoneypotInteractions(honeypotId: number, limit = 100) {
  const db = await getDb();
  return await db.select().from(honeypotInteractions).where(eq(honeypotInteractions.honeypotId, honeypotId)).orderBy(desc(honeypotInteractions.timestamp)).limit(limit);
}

export async function getHoneypotInteractionsByAttackerIp(ip: string) {
  const db = await getDb();
  return await db.select().from(honeypotInteractions).where(eq(honeypotInteractions.attackerIp, ip)).orderBy(desc(honeypotInteractions.timestamp));
}

// ============================================================================
// IAM / ENDPOINT / CLOUD / PHISHING / SOAR
// ============================================================================

export async function createIamEvent(event: typeof iamEvents.$inferInsert) {
  const db = await getDb();
  return await db.insert(iamEvents).values(event);
}

export async function getIamEvents(limit = 100) {
  const db = await getDb();
  return await db.select().from(iamEvents).orderBy(desc(iamEvents.timestamp)).limit(limit);
}

export async function createEndpointTelemetry(telemetry: typeof endpointTelemetry.$inferInsert) {
  const db = await getDb();
  return await db.insert(endpointTelemetry).values(telemetry);
}

export async function getEndpointTelemetry(limit = 100) {
  const db = await getDb();
  return await db.select().from(endpointTelemetry).orderBy(desc(endpointTelemetry.timestamp)).limit(limit);
}

export async function createCloudFinding(finding: typeof cloudFindings.$inferInsert) {
  const db = await getDb();
  return await db.insert(cloudFindings).values(finding);
}

export async function getCloudFindings(limit = 100) {
  const db = await getDb();
  return await db.select().from(cloudFindings).orderBy(desc(cloudFindings.timestamp)).limit(limit);
}

export async function createPhishingAnalysis(analysis: typeof phishingAnalyses.$inferInsert): Promise<number> {
  const db = await getDb();
  const [row] = await db.insert(phishingAnalyses).values(analysis).$returningId();
  return row.id;
}

export async function getPhishingAnalyses(limit = 100) {
  const db = await getDb();
  return await db.select().from(phishingAnalyses).orderBy(desc(phishingAnalyses.createdAt)).limit(limit);
}

export async function createSoarPlaybook(playbook: typeof soarPlaybooks.$inferInsert) {
  const db = await getDb();
  return await db.insert(soarPlaybooks).values(playbook);
}

export async function getSoarPlaybooks(limit = 100) {
  const db = await getDb();
  return await db.select().from(soarPlaybooks).orderBy(desc(soarPlaybooks.updatedAt)).limit(limit);
}

export async function getSoarPlaybookById(id: number) {
  const db = await getDb();
  const result = await db.select().from(soarPlaybooks).where(eq(soarPlaybooks.id, id)).limit(1);
  return result[0];
}

export async function createSoarExecution(execution: typeof soarExecutions.$inferInsert): Promise<number> {
  const db = await getDb();
  const [row] = await db.insert(soarExecutions).values(execution).$returningId();
  return row.id;
}

export async function getSoarExecutions(limit = 100) {
  const db = await getDb();
  return await db.select().from(soarExecutions).orderBy(desc(soarExecutions.startedAt)).limit(limit);
}

// ============================================================================
// INGEST JOBS (async ingestion ledger)
// ============================================================================

export async function createIngestJob(job: typeof ingestJobs.$inferInsert): Promise<void> {
  const db = await getDb();
  await db.insert(ingestJobs).values(job);
}

/**
 * Atomic claim: flips queued → processing and bumps attempts in ONE
 * statement. The WHERE clause is the concurrency guard — a duplicate queue
 * delivery (reaper re-enqueue, BullMQ stalled-job recovery) loses the UPDATE
 * race, gets matchedRows=0, and skips. Returns the claimed row or undefined.
 */
export async function claimIngestJob(ingestId: string): Promise<IngestJob | undefined> {
  const db = await getDb();
  const [header] = await db
    .update(ingestJobs)
    .set({ status: "processing", startedAt: new Date(), attempts: sql`${ingestJobs.attempts} + 1` })
    .where(and(eq(ingestJobs.ingestId, ingestId), eq(ingestJobs.status, "queued")));
  if (!header.affectedRows) return undefined;
  const rows = await db.select().from(ingestJobs).where(eq(ingestJobs.ingestId, ingestId)).limit(1);
  return rows[0];
}

export async function completeIngestJob(ingestId: string, result: Record<string, unknown>): Promise<void> {
  const db = await getDb();
  await db
    .update(ingestJobs)
    .set({ status: "completed", result, error: null, completedAt: new Date() })
    .where(eq(ingestJobs.ingestId, ingestId));
}

/**
 * Terminal failure, or back to queued when the attempt budget remains.
 * Guarded to non-terminal states: the reaper calls this WITHOUT owning a
 * claim, and a job it read as stale may have completed in the meantime —
 * a completed row must never be overwritten to 'failed' (the client would
 * resubmit work that already committed).
 */
export async function markIngestJobFailure(ingestId: string, errorMessage: string, terminal: boolean): Promise<void> {
  const db = await getDb();
  await db
    .update(ingestJobs)
    .set({
      status: terminal ? "failed" : "queued",
      error: errorMessage.slice(0, 2_000),
      completedAt: terminal ? new Date() : null,
    })
    .where(and(eq(ingestJobs.ingestId, ingestId), inArray(ingestJobs.status, ["queued", "processing"])));
}

export async function getIngestJobByIngestId(ingestId: string): Promise<IngestJob | undefined> {
  const db = await getDb();
  const rows = await db.select().from(ingestJobs).where(eq(ingestJobs.ingestId, ingestId)).limit(1);
  return rows[0];
}

/**
 * Reaper feed. Two flavors of stuck job:
 * - queued rows never delivered (enqueue crashed between INSERT and queue
 *   add, or the in-memory channel died with the process);
 * - processing rows whose worker crashed mid-job (claimed, never finished).
 * Both are safe to re-dispatch: claim is atomic and the pipeline's
 * caller-supplied eventId makes replays of committed work no-ops.
 */
export async function findStaleIngestJobs(olderThan: Date, limit = 50): Promise<IngestJob[]> {
  const db = await getDb();
  const staleQueued = await db
    .select()
    .from(ingestJobs)
    .where(and(eq(ingestJobs.status, "queued"), sql`${ingestJobs.queuedAt} < ${olderThan}`))
    .orderBy(ingestJobs.queuedAt)
    .limit(limit);
  const staleProcessing = await db
    .select()
    .from(ingestJobs)
    .where(and(eq(ingestJobs.status, "processing"), sql`${ingestJobs.startedAt} < ${olderThan}`))
    .orderBy(ingestJobs.startedAt)
    .limit(limit);
  return [...staleQueued, ...staleProcessing];
}

/** Reaper helper: put a crashed 'processing' row back in the queue state. */
export async function requeueIngestJob(ingestId: string): Promise<void> {
  const db = await getDb();
  await db
    .update(ingestJobs)
    .set({ status: "queued", startedAt: null })
    .where(and(eq(ingestJobs.ingestId, ingestId), eq(ingestJobs.status, "processing")));
}

// ============================================================================
// NOTIFICATION CHANNELS & DELIVERIES
// ============================================================================

export async function createNotificationChannel(channel: InsertNotificationChannel): Promise<number> {
  const db = await getDb();
  const [row] = await db.insert(notificationChannels).values(channel).$returningId();
  return row.id;
}

export async function getNotificationChannels(limit = 100): Promise<NotificationChannel[]> {
  const db = await getDb();
  return await db.select().from(notificationChannels).orderBy(desc(notificationChannels.createdAt)).limit(limit);
}

/** Enabled channels only — the dispatch hot path. */
export async function getActiveNotificationChannels(): Promise<NotificationChannel[]> {
  const db = await getDb();
  return await db.select().from(notificationChannels).where(eq(notificationChannels.enabled, true));
}

export async function getNotificationChannelById(id: number): Promise<NotificationChannel | undefined> {
  const db = await getDb();
  const result = await db.select().from(notificationChannels).where(eq(notificationChannels.id, id)).limit(1);
  return result[0];
}

export async function updateNotificationChannel(id: number, changes: Partial<InsertNotificationChannel>): Promise<void> {
  const db = await getDb();
  await db.update(notificationChannels).set({ ...changes, updatedAt: new Date() }).where(eq(notificationChannels.id, id));
}

export async function deleteNotificationChannel(id: number): Promise<void> {
  const db = await getDb();
  await db.delete(notificationChannels).where(eq(notificationChannels.id, id));
}

export async function createNotificationDelivery(delivery: InsertNotificationDelivery): Promise<void> {
  const db = await getDb();
  await db.insert(notificationDeliveries).values(delivery);
}

export async function getNotificationDeliveries(limit = 200) {
  const db = await getDb();
  return await db.select().from(notificationDeliveries).orderBy(desc(notificationDeliveries.createdAt)).limit(limit);
}

// ============================================================================
// AUDIT
// ============================================================================

export async function createPlatformAuditLog(entry: typeof platformAuditLogs.$inferInsert) {
  const db = await getDb();
  return await db.insert(platformAuditLogs).values(entry);
}

export async function getPlatformAuditLogs(limit = 200) {
  const db = await getDb();
  return await db.select().from(platformAuditLogs).orderBy(desc(platformAuditLogs.createdAt)).limit(limit);
}
