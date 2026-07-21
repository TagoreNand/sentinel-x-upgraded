import { COOKIE_NAME } from "@shared/const";
import { TRPCError } from "@trpc/server";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { adminProcedure, analystProcedure, ingestProcedure, leadProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { logger } from "./_core/logger";
import { ENV } from "./_core/env";
import { assertRoleAssignable, ROLES } from "@shared/roles";
import { z } from "zod";
import { nanoid } from "nanoid";
import * as db from "./db";
import { ingestAndDetect } from "./security/pipeline";
import { enqueueIngest } from "./queue/ingestQueue";
import { runVulnerabilityScan } from "./security/vulnerability";
import { analyzePhishingEmail } from "./security/phishing";
import { executeSoarPlaybook } from "./security/soar";
import { seedDemoSecurityData } from "./security/demoData";

const jsonRecord = z.record(z.string(), z.any());
const severitySchema = z.enum(["critical", "high", "medium", "low"]);

const auditLog = logger.child({ component: "audit" });

/**
 * Platform audit trail. Runs AFTER the domain write has committed, so a
 * failure here must not fail the request — that would report an error for an
 * operation that already happened, and retries would double-apply it. The
 * failure is logged at error level instead; the log stream is the backstop
 * audit record. (If regulatory scope ever requires atomic audit, move the
 * audit insert into the same transaction as the domain write.)
 */
async function audit(userId: number | undefined, action: string, entityType: string, entityId?: string, details?: Record<string, any>) {
  try {
    await db.createPlatformAuditLog({
      auditId: nanoid(),
      actorUserId: userId,
      action,
      entityType,
      entityId,
      details,
      outcome: "success",
      createdAt: new Date(),
    });
  } catch (error) {
    auditLog.error("audit log write failed", error, { action, entityType, entityId, userId });
  }
}

const detectionLog = logger.child({ component: "detection-sidechannel" });

/**
 * Detection for side-channel ingestion (IAM/endpoint/cloud/phishing) is
 * best-effort BY DESIGN: the domain record has already committed by the time
 * this runs, so throwing here would tell the client "not recorded" about a
 * write that happened — and a well-behaved client's retry would then
 * duplicate the domain row. Telemetry must keep flowing when the detection
 * pipeline is degraded; the failure is logged loudly and surfaced to the
 * caller as detectionTriggered=false instead. (siem.ingestRawEvent is the
 * opposite case — detection IS its purpose — and stays fail-loud.)
 */
async function runDetectionBestEffort(params: Parameters<typeof ingestAndDetect>[0]): Promise<boolean> {
  try {
    await ingestAndDetect(params);
    return true;
  } catch (error) {
    detectionLog.error("detection pipeline failed for side-channel ingest", error, { sourceType: params.sourceType });
    return false;
  }
}

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  assets: router({
    create: analystProcedure
      .input(z.object({
        hostname: z.string(),
        ipAddress: z.string().optional(),
        assetType: z.string().optional(),
        environment: z.string().optional(),
        businessOwner: z.string().optional(),
        operatingSystem: z.string().optional(),
        criticality: severitySchema.default("medium"),
        services: z.array(jsonRecord).optional(),
        tags: z.array(z.string()).optional(),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const assetId = nanoid();
        await db.createAsset({
          assetId,
          hostname: input.hostname,
          ipAddress: input.ipAddress,
          assetType: input.assetType,
          environment: input.environment,
          businessOwner: input.businessOwner,
          operatingSystem: input.operatingSystem,
          criticality: input.criticality,
          services: input.services,
          tags: input.tags,
          metadata: input.metadata,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "asset.create", "asset", assetId, { hostname: input.hostname });
        return { assetId, success: true };
      }),

    list: protectedProcedure
      .input(z.object({ limit: z.number().default(100) }))
      .query(async ({ input }) => db.getAssets(input.limit)),
  }),

  siem: router({
    createEvent: analystProcedure
      .input(z.object({
        sourceIp: z.string().optional(),
        destinationIp: z.string().optional(),
        sourcePort: z.number().optional(),
        destinationPort: z.number().optional(),
        protocol: z.string().optional(),
        eventType: z.string(),
        eventCategory: z.string().optional(),
        rawLog: z.string().optional(),
        parsedData: jsonRecord.optional(),
        enrichment: jsonRecord.optional(),
        severity: severitySchema.default("low"),
        hostname: z.string().optional(),
        username: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const eventId = nanoid();
        await db.createSecurityEvent({
          eventId,
          sourceType: "manual",
          sourceIp: input.sourceIp,
          destinationIp: input.destinationIp,
          sourcePort: input.sourcePort,
          destinationPort: input.destinationPort,
          protocol: input.protocol,
          eventType: input.eventType,
          eventCategory: input.eventCategory,
          rawLog: input.rawLog,
          parsedData: input.parsedData,
          enrichment: input.enrichment,
          severity: input.severity,
          hostname: input.hostname,
          username: input.username,
          status: "new",
          userId: ctx.user?.id,
          timestamp: new Date(),
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "siem.event.create", "security_event", eventId, { eventType: input.eventType });
        return { eventId, success: true };
      }),

    ingestRawEvent: ingestProcedure
      .input(z.object({
        sourceType: z.enum(["json", "syslog", "raw", "iam", "endpoint", "cloud", "phishing"]),
        // Bounded payload: a single "event" the size of a novel is either a
        // misconfigured shipper or an attack on the parser; reject at the
        // edge instead of feeding it to normalization and the database.
        // The object branch is bounded by its serialized size — without the
        // refine, the string cap was trivially bypassable by sending the
        // same bytes as a JSON object.
        payload: z.union([
          z.string().min(1).max(64_000),
          jsonRecord.refine((value) => JSON.stringify(value).length <= 64_000, {
            message: "Event payload exceeds the 64KB ingestion limit",
          }),
        ]),
        assetId: z.number().int().positive().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Async by design: the request path validates and durably records
        // the job, then returns. Detection cost (enrichment queries, rule
        // evaluation, the persist transaction) is paid by the queue worker,
        // not the caller. Poll siem.getIngestJob for the outcome.
        const ingestId = await enqueueIngest({
          sourceType: input.sourceType,
          payload: input.payload,
          assetId: input.assetId,
          userId: ctx.user?.id,
        });
        await audit(ctx.user?.id, "siem.ingest.enqueue", "ingest_job", ingestId, { sourceType: input.sourceType });
        return { accepted: true as const, ingestId };
      }),

    getIngestJob: protectedProcedure
      .input(z.object({ ingestId: z.string().min(1).max(64) }))
      .query(async ({ input }) => {
        const job = await db.getIngestJobByIngestId(input.ingestId);
        if (!job) return null;
        // Deliberately excludes the raw payload — pollers need status and
        // outcome, not a 64KB echo of what they sent.
        return {
          ingestId: job.ingestId,
          sourceType: job.sourceType,
          status: job.status,
          attempts: job.attempts,
          result: job.result,
          error: job.error,
          queuedAt: job.queuedAt,
          startedAt: job.startedAt,
          completedAt: job.completedAt,
        };
      }),

    getEvents: protectedProcedure
      .input(z.object({ limit: z.number().default(100), offset: z.number().default(0) }))
      .query(async ({ input }) => db.getSecurityEvents(input.limit, input.offset)),

    getEventsBySeverity: protectedProcedure
      .input(z.object({ severity: severitySchema, limit: z.number().default(50) }))
      .query(async ({ input }) => db.getSecurityEventsBySeverity(input.severity, input.limit)),

    createAlert: analystProcedure
      .input(z.object({
        title: z.string(),
        description: z.string().optional(),
        severity: severitySchema,
        ruleId: z.string().optional(),
        ruleName: z.string().optional(),
        sourceEvents: z.array(z.number()).optional(),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const alertId = nanoid();
        await db.createAlert({
          alertId,
          title: input.title,
          description: input.description,
          severity: input.severity,
          ruleId: input.ruleId,
          ruleName: input.ruleName,
          sourceEvents: input.sourceEvents,
          metadata: input.metadata,
          status: "new",
          timestamp: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "siem.alert.create", "alert", alertId, { title: input.title });
        return { alertId, success: true };
      }),

    getAlerts: protectedProcedure
      .input(z.object({ limit: z.number().default(100), offset: z.number().default(0) }))
      .query(async ({ input }) => db.getAlerts(input.limit, input.offset)),

    getAlertStats: protectedProcedure.query(async () => db.getAlertStats()),

    seedDemo: adminProcedure.mutation(async ({ ctx }) => {
      const result = await seedDemoSecurityData(ctx.user?.id);
      await audit(ctx.user?.id, "siem.seed_demo", "platform", undefined, result);
      return { success: true, ...result };
    }),
  }),

  incidents: router({
    create: analystProcedure
      .input(z.object({
        title: z.string(),
        description: z.string().optional(),
        severity: severitySchema,
        classification: z.string().optional(),
        affectedAssets: z.array(z.string()).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const incidentId = nanoid();
        await db.createIncident({
          incidentId,
          title: input.title,
          description: input.description,
          severity: input.severity,
          classification: input.classification,
          affectedAssets: input.affectedAssets,
          status: "open",
          createdBy: ctx.user?.id,
          detectedAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "incident.create", "incident", incidentId, { title: input.title });
        return { incidentId, success: true };
      }),

    list: protectedProcedure
      .input(z.object({ limit: z.number().default(100), offset: z.number().default(0) }))
      .query(async ({ input }) => db.getIncidents(input.limit, input.offset)),

    getById: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ input }) => db.getIncidentById(input.id)),
    getByStatus: protectedProcedure.input(z.object({ status: z.enum(["open", "investigating", "contained", "resolved"]) })).query(async ({ input }) => db.getIncidentsByStatus(input.status)),

    updateStatus: analystProcedure
      .input(z.object({ id: z.number(), status: z.enum(["open", "investigating", "contained", "resolved"]) }))
      .mutation(async ({ input, ctx }) => {
        await db.updateIncidentStatus(input.id, input.status);
        await db.addIncidentAuditTrail({
          incidentId: input.id,
          action: `Status changed to ${input.status}`,
          performedBy: ctx.user?.id,
          details: { newStatus: input.status },
          timestamp: new Date(),
        });
        await audit(ctx.user?.id, "incident.status.update", "incident", String(input.id), { status: input.status });
        return { success: true };
      }),

    getStats: protectedProcedure.query(async () => db.getIncidentStats()),

    addPlaybookStep: analystProcedure
      .input(z.object({
        incidentId: z.number(),
        stepNumber: z.number(),
        title: z.string(),
        description: z.string().optional(),
        assignedTo: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.addIncidentPlaybookStep({
          incidentId: input.incidentId,
          stepNumber: input.stepNumber,
          title: input.title,
          description: input.description,
          assignedTo: input.assignedTo,
          status: "pending",
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "incident.playbook.add", "incident", String(input.incidentId), { step: input.title });
        return { success: true };
      }),

    getPlaybookSteps: protectedProcedure.input(z.object({ incidentId: z.number() })).query(async ({ input }) => db.getIncidentPlaybookSteps(input.incidentId)),
    getAuditTrail: protectedProcedure.input(z.object({ incidentId: z.number() })).query(async ({ input }) => db.getIncidentAuditTrail(input.incidentId)),
  }),

  threatIntel: router({
    createIOC: analystProcedure
      .input(z.object({
        iocType: z.enum(["ip", "domain", "url", "hash", "email", "file", "process", "registry"]),
        iocValue: z.string(),
        threatLevel: severitySchema.default("medium"),
        source: z.string().optional(),
        threatActorId: z.number().optional(),
        confidence: z.number().default(50),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const iocId = nanoid();
        await db.createIOC({
          iocId,
          iocType: input.iocType,
          iocValue: input.iocValue,
          threatLevel: input.threatLevel,
          source: input.source,
          threatActorId: input.threatActorId,
          confidence: input.confidence,
          metadata: input.metadata,
          status: "active",
          firstSeen: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "threat_intel.ioc.create", "ioc", iocId, { value: input.iocValue });
        return { iocId, success: true };
      }),

    getIOCs: protectedProcedure
      .input(z.object({ limit: z.number().default(100), offset: z.number().default(0) }))
      .query(async ({ input }) => db.getIOCs(input.limit, input.offset)),

    searchIOC: protectedProcedure.input(z.object({ value: z.string() })).query(async ({ input }) => db.searchIOC(input.value)),

    createThreatActor: analystProcedure
      .input(z.object({
        name: z.string(),
        aliases: z.array(z.string()).optional(),
        description: z.string().optional(),
        sophistication: z.enum(["novice", "intermediate", "advanced", "expert"]).default("intermediate"),
        motivations: z.array(z.string()).optional(),
        targetedIndustries: z.array(z.string()).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const actorId = nanoid();
        await db.createThreatActor({
          actorId,
          name: input.name,
          aliases: input.aliases,
          description: input.description,
          sophistication: input.sophistication,
          motivations: input.motivations,
          targetedIndustries: input.targetedIndustries,
          knownIncidents: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "threat_intel.actor.create", "threat_actor", actorId, { name: input.name });
        return { actorId, success: true };
      }),

    getThreatActors: protectedProcedure.input(z.object({ limit: z.number().default(50) })).query(async ({ input }) => db.getThreatActors(input.limit)),
    getCVEs: protectedProcedure.input(z.object({ limit: z.number().default(100), offset: z.number().default(0) })).query(async ({ input }) => db.getCVEs(input.limit, input.offset)),
    searchCVE: protectedProcedure.input(z.object({ cveId: z.string() })).query(async ({ input }) => db.searchCVE(input.cveId)),
  }),

  vulnerabilityScanning: router({
    createScan: analystProcedure
      .input(z.object({
        targetHost: z.string(),
        targetIp: z.string().optional(),
        assetId: z.number().optional(),
        scanType: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const scanId = nanoid();
        await db.createVulnerabilityScan({
          scanId,
          targetHost: input.targetHost,
          targetIp: input.targetIp,
          assetId: input.assetId,
          scanType: input.scanType,
          executionMode: "simulation",
          disclaimer: "Placeholder scan created manually.",
          status: "pending",
          startTime: new Date(),
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "vuln.scan.create", "vulnerability_scan", scanId, { targetHost: input.targetHost });
        return { scanId, success: true };
      }),

    runScan: analystProcedure
      .input(z.object({
        targetHost: z.string(),
        targetIp: z.string().optional(),
        assetId: z.number().optional(),
        scanType: z.string().optional(),
        observedServices: z.array(z.object({
          port: z.number(),
          service: z.string(),
          product: z.string().optional(),
          version: z.string().optional(),
          banner: z.string().optional(),
        })).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const result = await runVulnerabilityScan(input);
        await audit(ctx.user?.id, "vuln.scan.run", "vulnerability_scan", String(result.scanId), {
          executionMode: result.executionMode,
          findings: result.matchedFindings.length,
        });
        return { success: true, ...result };
      }),

    getScans: protectedProcedure.input(z.object({ limit: z.number().default(50) })).query(async ({ input }) => db.getVulnerabilityScans(input.limit)),
    getVulnerabilities: protectedProcedure.input(z.object({ scanId: z.number() })).query(async ({ input }) => db.getVulnerabilitiesByScan(input.scanId)),

    addVulnerability: analystProcedure
      .input(z.object({
        scanId: z.number(),
        cveId: z.string().optional(),
        title: z.string(),
        description: z.string().optional(),
        severity: severitySchema,
        affectedService: z.string().optional(),
        affectedPort: z.number().optional(),
        remediationSteps: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const vulnerabilityId = nanoid();
        await db.createVulnerability({
          vulnerabilityId,
          scanId: input.scanId,
          cveId: input.cveId,
          title: input.title,
          description: input.description,
          severity: input.severity,
          affectedService: input.affectedService,
          affectedPort: input.affectedPort,
          remediationSteps: input.remediationSteps,
          status: "open",
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "vuln.finding.add", "vulnerability", vulnerabilityId, { title: input.title });
        return { vulnerabilityId, success: true };
      }),
  }),

  ids: router({
    // leadProcedure: IDS rules carry regex/keyword logic the ingestion
    // pipeline EXECUTES against every event. Authoring one changes what the
    // platform does, not just what it records — a lead-tier capability, and
    // the specific privilege-escalation this RBAC pass closes.
    createRule: leadProcedure
      .input(z.object({
        ruleName: z.string(),
        description: z.string().optional(),
        ruleType: z.string().optional(),
        dataSource: z.string().optional(),
        pattern: z.string(),
        detectionLogic: jsonRecord.optional(),
        severity: severitySchema.default("medium"),
        attackTechnique: z.string().optional(),
        attackTactic: z.string().optional(),
        thresholdCount: z.number().optional(),
        thresholdWindowMinutes: z.number().optional(),
        confidenceWeight: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const ruleId = nanoid();
        await db.createIdsRule({
          ruleId,
          ruleName: input.ruleName,
          description: input.description,
          ruleType: input.ruleType,
          dataSource: input.dataSource,
          pattern: input.pattern,
          detectionLogic: input.detectionLogic,
          severity: input.severity,
          attackTechnique: input.attackTechnique,
          attackTactic: input.attackTactic,
          thresholdCount: input.thresholdCount,
          thresholdWindowMinutes: input.thresholdWindowMinutes,
          confidenceWeight: input.confidenceWeight,
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "ids.rule.create", "ids_rule", ruleId, { ruleName: input.ruleName });
        return { ruleId, success: true };
      }),

    getRules: protectedProcedure.input(z.object({ enabled: z.boolean().default(true) })).query(async ({ input }) => db.getIdsRules(input.enabled)),

    createDetection: analystProcedure
      .input(z.object({
        ruleId: z.number(),
        eventId: z.number().optional(),
        sourceIp: z.string().optional(),
        destinationIp: z.string().optional(),
        confidence: z.number().default(50),
        matchReasons: z.array(z.string()).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const detectionId = nanoid();
        let incidentId: number | undefined;

        if (input.confidence >= 75) {
          incidentId = await db.createIncident({
            incidentId: nanoid(),
            title: `IDS Detection - Rule ${input.ruleId}`,
            severity: "high",
            status: "open",
            detectedAt: new Date(),
            createdBy: ctx.user?.id,
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        }

        await db.createIdsDetection({
          detectionId,
          ruleId: input.ruleId,
          eventId: input.eventId,
          sourceIp: input.sourceIp,
          destinationIp: input.destinationIp,
          confidence: input.confidence,
          incidentId,
          matchReasons: input.matchReasons,
          timestamp: new Date(),
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "ids.detection.create", "ids_detection", detectionId, { incidentId });
        return { detectionId, incidentId, success: true };
      }),

    getDetections: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getIdsDetections(input.limit)),
  }),

  forensics: router({
    createEvidence: analystProcedure
      .input(z.object({
        incidentId: z.number().optional(),
        filename: z.string(),
        fileType: z.string().optional(),
        classification: z.string().optional(),
        storagePath: z.string().optional(),
        fileSize: z.number().optional(),
        md5Hash: z.string().optional(),
        sha1Hash: z.string().optional(),
        sha256Hash: z.string().optional(),
        sha512Hash: z.string().optional(),
        collectionMethod: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const evidenceId = nanoid();
        const evidencePk = await db.createForensicsEvidence({
          evidenceId,
          incidentId: input.incidentId,
          filename: input.filename,
          fileType: input.fileType,
          classification: input.classification,
          storagePath: input.storagePath,
          fileSize: input.fileSize,
          md5Hash: input.md5Hash,
          sha1Hash: input.sha1Hash,
          sha256Hash: input.sha256Hash,
          sha512Hash: input.sha512Hash,
          collectionMethod: input.collectionMethod,
          collectedBy: ctx.user?.id,
          collectedAt: new Date(),
          chainOfCustody: [{ action: "collected", by: ctx.user?.name, at: new Date() }],
          createdAt: new Date(),
        });
        if (evidencePk) {
          await db.createForensicsCustodyEvent({
            custodyEventId: nanoid(),
            evidenceId: evidencePk,
            action: "collected",
            actorUserId: ctx.user?.id,
            notes: "Initial collection",
            hashSnapshot: {
              md5: input.md5Hash,
              sha1: input.sha1Hash,
              sha256: input.sha256Hash,
              sha512: input.sha512Hash,
            },
            timestamp: new Date(),
          });
        }
        await audit(ctx.user?.id, "forensics.evidence.create", "evidence", evidenceId, { filename: input.filename });
        return { evidenceId, success: true, evidencePk };
      }),

    getEvidenceByIncident: protectedProcedure.input(z.object({ incidentId: z.number() })).query(async ({ input }) => db.getForensicsEvidenceByIncident(input.incidentId)),

    addCustodyEvent: analystProcedure
      .input(z.object({
        evidenceId: z.number(),
        action: z.string(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const evidence = await db.getEvidenceById(input.evidenceId);
        await db.createForensicsCustodyEvent({
          custodyEventId: nanoid(),
          evidenceId: input.evidenceId,
          action: input.action,
          actorUserId: ctx.user?.id,
          notes: input.notes,
          hashSnapshot: evidence
            ? {
                md5: evidence.md5Hash,
                sha1: evidence.sha1Hash,
                sha256: evidence.sha256Hash,
                sha512: evidence.sha512Hash,
              }
            : undefined,
          timestamp: new Date(),
        });
        await audit(ctx.user?.id, "forensics.custody.add", "evidence", String(input.evidenceId), { action: input.action });
        return { success: true };
      }),

    getCustody: protectedProcedure.input(z.object({ evidenceId: z.number() })).query(async ({ input }) => db.getForensicsCustodyEvents(input.evidenceId)),

    addTimelineEvent: analystProcedure
      .input(z.object({
        incidentId: z.number(),
        eventDescription: z.string(),
        eventTimestamp: z.date().optional(),
        source: z.string().optional(),
        severity: severitySchema.default("low"),
        details: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const timelineId = nanoid();
        await db.createForensicsTimeline({
          timelineId,
          incidentId: input.incidentId,
          eventDescription: input.eventDescription,
          eventTimestamp: input.eventTimestamp ?? new Date(),
          source: input.source,
          severity: input.severity,
          details: input.details,
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "forensics.timeline.add", "incident", String(input.incidentId), { event: input.eventDescription });
        return { timelineId, success: true };
      }),

    getTimeline: protectedProcedure.input(z.object({ incidentId: z.number() })).query(async ({ input }) => db.getForensicsTimeline(input.incidentId)),

    linkArtifact: analystProcedure
      .input(z.object({
        incidentId: z.number(),
        artifactType: z.string(),
        title: z.string(),
        sourceTable: z.string().optional(),
        sourceRecordId: z.string().optional(),
        tags: z.array(z.string()).optional(),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const artifactId = nanoid();
        await db.createInvestigationArtifact({
          artifactId,
          incidentId: input.incidentId,
          artifactType: input.artifactType,
          title: input.title,
          sourceTable: input.sourceTable,
          sourceRecordId: input.sourceRecordId,
          tags: input.tags,
          metadata: input.metadata,
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "forensics.artifact.link", "incident", String(input.incidentId), { artifactType: input.artifactType });
        return { artifactId, success: true };
      }),

    getArtifactsByIncident: protectedProcedure.input(z.object({ incidentId: z.number() })).query(async ({ input }) => db.getInvestigationArtifacts(input.incidentId)),

    getCaseOverview: protectedProcedure
      .input(z.object({ incidentId: z.number() }))
      .query(async ({ input }) => {
        const [incident, evidence, timeline, artifacts, auditTrail] = await Promise.all([
          db.getIncidentById(input.incidentId),
          db.getForensicsEvidenceByIncident(input.incidentId),
          db.getForensicsTimeline(input.incidentId),
          db.getInvestigationArtifacts(input.incidentId),
          db.getIncidentAuditTrail(input.incidentId),
        ]);
        return { incident, evidence, timeline, artifacts, auditTrail };
      }),
  }),

  honeypot: router({
    create: analystProcedure
      .input(z.object({
        name: z.string(),
        description: z.string().optional(),
        serviceType: z.string(),
        bindPort: z.number(),
        bindIp: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const honeypotId = nanoid();
        await db.createHoneypot({
          honeypotId,
          name: input.name,
          description: input.description,
          serviceType: input.serviceType,
          bindPort: input.bindPort,
          bindIp: input.bindIp,
          enabled: true,
          interactionCount: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "honeypot.create", "honeypot", honeypotId, { name: input.name });
        return { honeypotId, success: true };
      }),

    list: protectedProcedure.query(async () => db.getHoneypots()),

    recordInteraction: analystProcedure
      .input(z.object({
        honeypotId: z.number(),
        attackerIp: z.string(),
        attackerPort: z.number().optional(),
        attackerCountry: z.string().optional(),
        attackerCity: z.string().optional(),
        attackerLatitude: z.string().optional(),
        attackerLongitude: z.string().optional(),
        interactionType: z.string().optional(),
        payload: z.string().optional(),
        credentials: z.record(z.string(), z.string()).optional(),
        userAgent: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const interactionId = nanoid();
        await db.createHoneypotInteraction({
          interactionId,
          ...input,
          timestamp: new Date(),
          createdAt: new Date(),
        });
        await audit(ctx.user?.id, "honeypot.interaction.record", "honeypot_interaction", interactionId, { attackerIp: input.attackerIp });
        return { interactionId, success: true };
      }),

    getInteractions: protectedProcedure.input(z.object({ honeypotId: z.number(), limit: z.number().default(100) })).query(async ({ input }) => db.getHoneypotInteractions(input.honeypotId, input.limit)),
    getInteractionsByAttackerIp: protectedProcedure.input(z.object({ ip: z.string() })).query(async ({ input }) => db.getHoneypotInteractionsByAttackerIp(input.ip)),
  }),

  iam: router({
    // ingestProcedure (not protectedProcedure): this route feeds
    // ingestAndDetect, and every door into the detection pipeline shares
    // the same rate budget — otherwise the front door's limit is theater.
    createEvent: ingestProcedure
      .input(z.object({
        provider: z.string().default("okta"),
        actor: z.string(),
        action: z.string(),
        target: z.string().optional(),
        sourceIp: z.string().optional(),
        status: z.string().optional(),
        anomalyScore: z.number().default(0),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const iamEventId = nanoid();
        await db.createIamEvent({
          iamEventId,
          provider: input.provider,
          actor: input.actor,
          action: input.action,
          target: input.target,
          sourceIp: input.sourceIp,
          status: input.status,
          anomalyScore: input.anomalyScore,
          metadata: input.metadata,
          timestamp: new Date(),
          createdAt: new Date(),
        });
        const detectionTriggered = await runDetectionBestEffort({
          sourceType: "iam",
          payload: {
            eventType: input.anomalyScore >= 75 ? "suspicious_login" : "authentication_failed",
            eventCategory: "identity",
            message: `${input.provider} ${input.action} by ${input.actor}`,
            sourceIp: input.sourceIp,
            username: input.actor,
            severity: input.anomalyScore >= 75 ? "high" : "medium",
          },
          userId: ctx.user?.id,
        });
        await audit(ctx.user?.id, "iam.event.create", "iam_event", iamEventId, { actor: input.actor, action: input.action });
        return { iamEventId, success: true, detectionTriggered };
      }),

    list: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getIamEvents(input.limit)),
  }),

  endpoint: router({
    // Rate-limited: invokes the detection pipeline (see iam.createEvent).
    createTelemetry: ingestProcedure
      .input(z.object({
        endpointId: z.string().optional(),
        hostname: z.string(),
        username: z.string().optional(),
        processName: z.string().optional(),
        parentProcess: z.string().optional(),
        processHash: z.string().optional(),
        commandLine: z.string().optional(),
        destinationIp: z.string().optional(),
        severity: severitySchema.default("low"),
        status: z.string().optional(),
        tags: z.array(z.string()).optional(),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const telemetryId = nanoid();
        await db.createEndpointTelemetry({
          telemetryId,
          endpointId: input.endpointId,
          hostname: input.hostname,
          username: input.username,
          processName: input.processName,
          parentProcess: input.parentProcess,
          processHash: input.processHash,
          commandLine: input.commandLine,
          destinationIp: input.destinationIp,
          severity: input.severity,
          status: input.status,
          tags: input.tags,
          metadata: input.metadata,
          timestamp: new Date(),
          createdAt: new Date(),
        });
        const detectionTriggered = await runDetectionBestEffort({
          sourceType: "endpoint",
          payload: {
            eventType: input.processName?.toLowerCase().includes("powershell") ? "suspicious_powershell" : "suspicious_process",
            eventCategory: "endpoint",
            message: `${input.processName || "process"} observed on ${input.hostname}`,
            hostname: input.hostname,
            username: input.username,
            destinationIp: input.destinationIp,
            severity: input.severity,
            commandLine: input.commandLine,
          },
          userId: ctx.user?.id,
        });
        await audit(ctx.user?.id, "endpoint.telemetry.create", "endpoint_telemetry", telemetryId, { hostname: input.hostname });
        return { telemetryId, success: true, detectionTriggered };
      }),

    list: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getEndpointTelemetry(input.limit)),
  }),

  cloud: router({
    // Rate-limited: invokes the detection pipeline (see iam.createEvent).
    createFinding: ingestProcedure
      .input(z.object({
        provider: z.string().default("aws"),
        accountId: z.string().optional(),
        resourceId: z.string(),
        service: z.string().optional(),
        findingType: z.string(),
        severity: severitySchema.default("medium"),
        status: z.string().optional(),
        metadata: jsonRecord.optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const findingId = nanoid();
        await db.createCloudFinding({
          findingId,
          provider: input.provider,
          accountId: input.accountId,
          resourceId: input.resourceId,
          service: input.service,
          findingType: input.findingType,
          severity: input.severity,
          status: input.status,
          metadata: input.metadata,
          timestamp: new Date(),
          createdAt: new Date(),
        });
        const detectionTriggered = await runDetectionBestEffort({
          sourceType: "cloud",
          payload: {
            eventType: "cloud_misconfiguration",
            eventCategory: "cloud",
            message: `${input.provider} ${input.service || "resource"} finding: ${input.findingType}`,
            hostname: input.resourceId,
            severity: input.severity,
          },
          userId: ctx.user?.id,
        });
        await audit(ctx.user?.id, "cloud.finding.create", "cloud_finding", findingId, { findingType: input.findingType });
        return { findingId, success: true, detectionTriggered };
      }),

    list: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getCloudFindings(input.limit)),
  }),

  phishing: router({
    // Rate-limited: invokes the detection pipeline (see iam.createEvent).
    analyze: ingestProcedure
      .input(z.object({
        subject: z.string(),
        sender: z.string(),
        recipient: z.string().optional(),
        body: z.string(),
        attachmentCount: z.number().optional(),
        createIncident: z.boolean().default(true),
      }))
      .mutation(async ({ input, ctx }) => {
        const result = await analyzePhishingEmail({ ...input, userId: ctx.user?.id });
        const detectionTriggered = await runDetectionBestEffort({
          sourceType: "phishing",
          payload: {
            eventType: "phishing_email",
            eventCategory: "email",
            message: `${input.subject} from ${input.sender}`,
            username: input.recipient,
            severity: result.verdict === "malicious" ? "high" : result.verdict === "suspicious" ? "medium" : "low",
          },
          userId: ctx.user?.id,
        });
        await audit(ctx.user?.id, "phishing.analyze", "phishing_analysis", String(result.analysisId), { verdict: result.verdict });
        return { success: true, detectionTriggered, ...result };
      }),

    list: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getPhishingAnalyses(input.limit)),
  }),

  soar: router({
    // leadProcedure: SOAR playbooks encode automated response actions.
    createPlaybook: leadProcedure
      .input(z.object({
        name: z.string(),
        description: z.string().optional(),
        triggerType: z.string(),
        enabled: z.boolean().default(true),
        steps: z.array(jsonRecord),
      }))
      .mutation(async ({ input, ctx }) => {
        const playbookId = nanoid();
        await db.createSoarPlaybook({
          playbookId,
          name: input.name,
          description: input.description,
          triggerType: input.triggerType,
          enabled: input.enabled,
          steps: input.steps,
          createdBy: ctx.user?.id,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        await audit(ctx.user?.id, "soar.playbook.create", "soar_playbook", playbookId, { name: input.name });
        return { playbookId, success: true };
      }),

    listPlaybooks: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getSoarPlaybooks(input.limit)),

    // leadProcedure: executing a playbook fires (simulated) response actions.
    execute: leadProcedure
      .input(z.object({
        playbookId: z.number(),
        incidentId: z.number().optional(),
        triggerEntityType: z.string().optional(),
        triggerEntityId: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const result = await executeSoarPlaybook({ ...input, userId: ctx.user?.id });
        await audit(ctx.user?.id, "soar.playbook.execute", "soar_execution", String(result.executionId), { playbookId: input.playbookId });
        return { success: true, ...result };
      }),

    listExecutions: protectedProcedure.input(z.object({ limit: z.number().default(100) })).query(async ({ input }) => db.getSoarExecutions(input.limit)),
  }),

  platform: router({
    getAuditLogs: adminProcedure.input(z.object({ limit: z.number().default(200) })).query(async ({ input }) => db.getPlatformAuditLogs(input.limit)),
  }),

  admin: router({
    listUsers: adminProcedure
      .input(z.object({ limit: z.number().int().positive().max(500).default(200) }))
      .query(async ({ input }) => db.getUsers(input.limit)),

    setUserRole: adminProcedure
      .input(z.object({ userId: z.number().int().positive(), role: z.enum(ROLES) }))
      .mutation(async ({ input, ctx }) => {
        const target = await db.getUserById(input.userId);
        if (!target) {
          throw new TRPCError({ code: "NOT_FOUND", message: "User not found" });
        }
        // Policy is a pure, tested function (assertRoleAssignable): no
        // self-role-change, the owner stays a permanent admin anchor, and the
        // target role must be a real tier. adminProcedure already guarantees
        // the caller is an admin; passing actorRole keeps the policy honest
        // even if this endpoint is ever re-gated.
        const decision = assertRoleAssignable({
          actorRole: ctx.user.role,
          actorUserId: ctx.user.id,
          targetUserId: target.id,
          targetOpenId: target.openId,
          ownerOpenId: ENV.ownerOpenId,
          newRole: input.role,
        });
        if (!decision.ok) {
          throw new TRPCError({ code: "FORBIDDEN", message: decision.reason });
        }
        await db.updateUserRole(target.id, input.role);
        await audit(ctx.user.id, "admin.user.role.set", "user", String(target.id), {
          targetOpenId: target.openId,
          previousRole: target.role,
          newRole: input.role,
        });
        return { success: true, userId: target.id, role: input.role };
      }),
  }),

  dashboard: router({
    getMetrics: protectedProcedure.query(async () => {
      const [alertStats, incidentStats, recentAlerts, recentIncidents, detections, assets, phishing, cloudFindings, endpointTelemetry] = await Promise.all([
        db.getAlertStats(),
        db.getIncidentStats(),
        db.getAlerts(10),
        db.getIncidents(10),
        db.getIdsDetections(10),
        db.getAssets(10),
        db.getPhishingAnalyses(10),
        db.getCloudFindings(10),
        db.getEndpointTelemetry(10),
      ]);

      return {
        alertStats,
        incidentStats,
        recentAlerts,
        recentIncidents,
        recentDetections: detections,
        assetCount: assets.length,
        phishingCount: phishing.length,
        cloudFindingCount: cloudFindings.length,
        endpointTelemetryCount: endpointTelemetry.length,
        timestamp: new Date(),
      };
    }),

    getEventFeed: protectedProcedure.input(z.object({ limit: z.number().default(50) })).query(async ({ input }) => db.getSecurityEvents(input.limit)),
  }),
});

export type AppRouter = typeof appRouter;
