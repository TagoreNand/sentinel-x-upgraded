import { int, mysqlEnum, mysqlTable, text, timestamp, varchar, decimal, boolean, json, bigint, index } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

// ============================================================================
// SIEM & EVENT MANAGEMENT TABLES
// ============================================================================

export const securityEvents = mysqlTable("security_events", {
  id: int("id").autoincrement().primaryKey(),
  eventId: varchar("eventId", { length: 64 }).notNull().unique(),
  sourceType: varchar("sourceType", { length: 32 }).default("manual"),
  sourceIp: varchar("sourceIp", { length: 45 }),
  destinationIp: varchar("destinationIp", { length: 45 }),
  sourcePort: int("sourcePort"),
  destinationPort: int("destinationPort"),
  protocol: varchar("protocol", { length: 20 }),
  eventType: varchar("eventType", { length: 100 }).notNull(),
  eventCategory: varchar("eventCategory", { length: 100 }),
  rawLog: text("rawLog"),
  parsedData: json("parsedData"),
  enrichment: json("enrichment"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).default("low"),
  status: varchar("status", { length: 50 }).default("new"),
  correlationId: varchar("correlationId", { length: 64 }),
  userId: int("userId"),
  hostname: varchar("hostname", { length: 255 }),
  username: varchar("username", { length: 255 }),
  timestamp: timestamp("timestamp").defaultNow(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (table) => ({
  sourceIpIdx: index("idx_source_ip").on(table.sourceIp),
  severityIdx: index("idx_severity").on(table.severity),
  timestampIdx: index("idx_timestamp").on(table.timestamp),
}));

export type SecurityEvent = typeof securityEvents.$inferSelect;
export type InsertSecurityEvent = typeof securityEvents.$inferInsert;

export const alerts = mysqlTable("alerts", {
  id: int("id").autoincrement().primaryKey(),
  alertId: varchar("alertId", { length: 64 }).notNull().unique(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  ruleId: varchar("ruleId", { length: 64 }),
  ruleName: varchar("ruleName", { length: 255 }),
  sourceEvents: json("sourceEvents"),
  status: varchar("status", { length: 50 }).default("new"),
  assignedTo: int("assignedTo"),
  incidentId: int("incidentId"),
  metadata: json("metadata"),
  timestamp: timestamp("timestamp").defaultNow(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
}, (table) => ({
  severityIdx: index("idx_alert_severity").on(table.severity),
  statusIdx: index("idx_alert_status").on(table.status),
  timestampIdx: index("idx_alert_timestamp").on(table.timestamp),
}));

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;

// ============================================================================
// ASSET INVENTORY
// ============================================================================

export const assets = mysqlTable("assets", {
  id: int("id").autoincrement().primaryKey(),
  assetId: varchar("assetId", { length: 64 }).notNull().unique(),
  hostname: varchar("hostname", { length: 255 }).notNull(),
  ipAddress: varchar("ipAddress", { length: 45 }),
  assetType: varchar("assetType", { length: 100 }).default("server"),
  environment: varchar("environment", { length: 64 }).default("production"),
  businessOwner: varchar("businessOwner", { length: 255 }),
  operatingSystem: varchar("operatingSystem", { length: 255 }),
  criticality: mysqlEnum("criticality", ["critical", "high", "medium", "low"]).default("medium"),
  services: json("services"),
  tags: json("tags"),
  metadata: json("metadata"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
}, (table) => ({
  hostnameIdx: index("idx_asset_hostname").on(table.hostname),
  ipIdx: index("idx_asset_ip").on(table.ipAddress),
}));

export type Asset = typeof assets.$inferSelect;
export type InsertAsset = typeof assets.$inferInsert;

// ============================================================================
// INCIDENT MANAGEMENT TABLES
// ============================================================================

export const incidents = mysqlTable("incidents", {
  id: int("id").autoincrement().primaryKey(),
  incidentId: varchar("incidentId", { length: 64 }).notNull().unique(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  status: mysqlEnum("status", ["open", "investigating", "contained", "resolved"]).default("open"),
  classification: varchar("classification", { length: 100 }),
  assignedTo: int("assignedTo"),
  createdBy: int("createdBy"),
  detectedAt: timestamp("detectedAt"),
  containedAt: timestamp("containedAt"),
  resolvedAt: timestamp("resolvedAt"),
  affectedAssets: json("affectedAssets"),
  rootCause: text("rootCause"),
  timeline: json("timeline"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
}, (table) => ({
  statusIdx: index("idx_incident_status").on(table.status),
  severityIdx: index("idx_incident_severity").on(table.severity),
}));

export type Incident = typeof incidents.$inferSelect;
export type InsertIncident = typeof incidents.$inferInsert;

export const incidentPlaybooks = mysqlTable("incident_playbooks", {
  id: int("id").autoincrement().primaryKey(),
  incidentId: int("incidentId").notNull(),
  stepNumber: int("stepNumber").notNull(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  status: varchar("status", { length: 50 }).default("pending"),
  assignedTo: int("assignedTo"),
  completedAt: timestamp("completedAt"),
  notes: text("notes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type IncidentPlaybook = typeof incidentPlaybooks.$inferSelect;
export type InsertIncidentPlaybook = typeof incidentPlaybooks.$inferInsert;

export const incidentAuditTrail = mysqlTable("incident_audit_trail", {
  id: int("id").autoincrement().primaryKey(),
  incidentId: int("incidentId").notNull(),
  action: varchar("action", { length: 100 }).notNull(),
  performedBy: int("performedBy"),
  details: json("details"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
});

export type IncidentAuditTrail = typeof incidentAuditTrail.$inferSelect;
export type InsertIncidentAuditTrail = typeof incidentAuditTrail.$inferInsert;

// ============================================================================
// THREAT INTELLIGENCE TABLES
// ============================================================================

export const indicatorsOfCompromise = mysqlTable("indicators_of_compromise", {
  id: int("id").autoincrement().primaryKey(),
  iocId: varchar("iocId", { length: 64 }).notNull().unique(),
  iocType: mysqlEnum("iocType", ["ip", "domain", "url", "hash", "email", "file", "process", "registry"]).notNull(),
  iocValue: varchar("iocValue", { length: 512 }).notNull(),
  threatLevel: mysqlEnum("threatLevel", ["critical", "high", "medium", "low"]).default("medium"),
  source: varchar("source", { length: 255 }),
  threatActorId: int("threatActorId"),
  firstSeen: timestamp("firstSeen"),
  lastSeen: timestamp("lastSeen"),
  confidence: int("confidence").default(50),
  status: varchar("status", { length: 50 }).default("active"),
  metadata: json("metadata"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
}, (table) => ({
  iocValueIdx: index("idx_ioc_value").on(table.iocValue),
  iocTypeIdx: index("idx_ioc_type").on(table.iocType),
}));

export type IndicatorOfCompromise = typeof indicatorsOfCompromise.$inferSelect;
export type InsertIndicatorOfCompromise = typeof indicatorsOfCompromise.$inferInsert;

export const threatActors = mysqlTable("threat_actors", {
  id: int("id").autoincrement().primaryKey(),
  actorId: varchar("actorId", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  aliases: json("aliases"),
  description: text("description"),
  sophistication: mysqlEnum("sophistication", ["novice", "intermediate", "advanced", "expert"]).default("intermediate"),
  motivations: json("motivations"),
  targetedIndustries: json("targetedIndustries"),
  attackTechniques: json("attackTechniques"),
  knownIncidents: int("knownIncidents").default(0),
  firstSeen: timestamp("firstSeen"),
  lastSeen: timestamp("lastSeen"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
});

export type ThreatActor = typeof threatActors.$inferSelect;
export type InsertThreatActor = typeof threatActors.$inferInsert;

export const cveDatabase = mysqlTable("cve_database", {
  id: int("id").autoincrement().primaryKey(),
  cveId: varchar("cveId", { length: 20 }).notNull().unique(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  cvssScore: decimal("cvssScore", { precision: 3, scale: 1 }),
  affectedProducts: json("affectedProducts"),
  publishedDate: timestamp("publishedDate"),
  updatedDate: timestamp("updatedDate"),
  references: json("references"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (table) => ({
  cveIdIdx: index("idx_cve_id").on(table.cveId),
  severityIdx: index("idx_cve_severity").on(table.severity),
}));

export type CveEntry = typeof cveDatabase.$inferSelect;
export type InsertCveEntry = typeof cveDatabase.$inferInsert;

// ============================================================================
// VULNERABILITY & SCANNING TABLES
// ============================================================================

export const vulnerabilityScans = mysqlTable("vulnerability_scans", {
  id: int("id").autoincrement().primaryKey(),
  scanId: varchar("scanId", { length: 64 }).notNull().unique(),
  targetHost: varchar("targetHost", { length: 255 }).notNull(),
  targetIp: varchar("targetIp", { length: 45 }),
  assetId: int("assetId"),
  scanType: varchar("scanType", { length: 100 }),
  executionMode: mysqlEnum("executionMode", ["evidence-driven", "simulation"]).default("simulation"),
  disclaimer: text("disclaimer"),
  targetServices: json("targetServices"),
  status: varchar("status", { length: 50 }).default("pending"),
  startTime: timestamp("startTime"),
  endTime: timestamp("endTime"),
  vulnerabilitiesFound: int("vulnerabilitiesFound").default(0),
  criticalCount: int("criticalCount").default(0),
  highCount: int("highCount").default(0),
  mediumCount: int("mediumCount").default(0),
  lowCount: int("lowCount").default(0),
  riskScore: decimal("riskScore", { precision: 5, scale: 2 }).default("0.00"),
  results: json("results"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type VulnerabilityScan = typeof vulnerabilityScans.$inferSelect;
export type InsertVulnerabilityScan = typeof vulnerabilityScans.$inferInsert;

export const vulnerabilities = mysqlTable("vulnerabilities", {
  id: int("id").autoincrement().primaryKey(),
  vulnerabilityId: varchar("vulnerabilityId", { length: 64 }).notNull().unique(),
  scanId: int("scanId").notNull(),
  cveId: varchar("cveId", { length: 20 }),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  affectedService: varchar("affectedService", { length: 255 }),
  affectedPort: int("affectedPort"),
  remediationSteps: text("remediationSteps"),
  status: varchar("status", { length: 50 }).default("open"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = typeof vulnerabilities.$inferInsert;

// ============================================================================
// INTRUSION DETECTION & IDS TABLES
// ============================================================================

export const idsRules = mysqlTable("ids_rules", {
  id: int("id").autoincrement().primaryKey(),
  ruleId: varchar("ruleId", { length: 64 }).notNull().unique(),
  ruleName: varchar("ruleName", { length: 255 }).notNull(),
  description: text("description"),
  ruleType: varchar("ruleType", { length: 100 }),
  dataSource: varchar("dataSource", { length: 64 }).default("siem"),
  pattern: text("pattern"),
  detectionLogic: json("detectionLogic"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).default("medium"),
  enabled: boolean("enabled").default(true),
  attackTechnique: varchar("attackTechnique", { length: 100 }),
  attackTactic: varchar("attackTactic", { length: 100 }),
  thresholdCount: int("thresholdCount").default(1),
  thresholdWindowMinutes: int("thresholdWindowMinutes").default(5),
  confidenceWeight: int("confidenceWeight").default(50),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
});

export type IdsRule = typeof idsRules.$inferSelect;
export type InsertIdsRule = typeof idsRules.$inferInsert;

export const idsDetections = mysqlTable("ids_detections", {
  id: int("id").autoincrement().primaryKey(),
  detectionId: varchar("detectionId", { length: 64 }).notNull().unique(),
  ruleId: int("ruleId").notNull(),
  eventId: int("eventId"),
  sourceIp: varchar("sourceIp", { length: 45 }),
  destinationIp: varchar("destinationIp", { length: 45 }),
  incidentId: int("incidentId"),
  confidence: int("confidence").default(50),
  matchReasons: json("matchReasons"),
  mitreTechnique: varchar("mitreTechnique", { length: 100 }),
  mitreTactic: varchar("mitreTactic", { length: 100 }),
  timestamp: timestamp("timestamp").defaultNow(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (table) => ({
  ruleIdIdx: index("idx_detection_rule").on(table.ruleId),
  sourceIpIdx: index("idx_detection_source").on(table.sourceIp),
}));

export type IdsDetection = typeof idsDetections.$inferSelect;
export type InsertIdsDetection = typeof idsDetections.$inferInsert;

// ============================================================================
// DIGITAL FORENSICS TABLES
// ============================================================================

export const forensicsEvidence = mysqlTable("forensics_evidence", {
  id: int("id").autoincrement().primaryKey(),
  evidenceId: varchar("evidenceId", { length: 64 }).notNull().unique(),
  incidentId: int("incidentId"),
  filename: varchar("filename", { length: 255 }).notNull(),
  fileType: varchar("fileType", { length: 100 }),
  classification: varchar("classification", { length: 100 }),
  storagePath: varchar("storagePath", { length: 255 }),
  fileSize: bigint("fileSize", { mode: "number" }),
  md5Hash: varchar("md5Hash", { length: 32 }),
  sha1Hash: varchar("sha1Hash", { length: 40 }),
  sha256Hash: varchar("sha256Hash", { length: 64 }),
  sha512Hash: varchar("sha512Hash", { length: 128 }),
  collectionMethod: varchar("collectionMethod", { length: 255 }),
  collectedBy: int("collectedBy"),
  collectedAt: timestamp("collectedAt"),
  chainOfCustody: json("chainOfCustody"),
  metadata: json("metadata"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ForensicsEvidence = typeof forensicsEvidence.$inferSelect;
export type InsertForensicsEvidence = typeof forensicsEvidence.$inferInsert;

export const forensicsCustodyEvents = mysqlTable("forensics_custody_events", {
  id: int("id").autoincrement().primaryKey(),
  custodyEventId: varchar("custodyEventId", { length: 64 }).notNull().unique(),
  evidenceId: int("evidenceId").notNull(),
  action: varchar("action", { length: 100 }).notNull(),
  actorUserId: int("actorUserId"),
  notes: text("notes"),
  hashSnapshot: json("hashSnapshot"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
});

export type ForensicsCustodyEvent = typeof forensicsCustodyEvents.$inferSelect;
export type InsertForensicsCustodyEvent = typeof forensicsCustodyEvents.$inferInsert;

export const forensicsTimeline = mysqlTable("forensics_timeline", {
  id: int("id").autoincrement().primaryKey(),
  timelineId: varchar("timelineId", { length: 64 }).notNull().unique(),
  incidentId: int("incidentId").notNull(),
  eventDescription: varchar("eventDescription", { length: 255 }).notNull(),
  eventTimestamp: timestamp("eventTimestamp"),
  source: varchar("source", { length: 100 }),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).default("low"),
  details: json("details"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ForensicsTimeline = typeof forensicsTimeline.$inferSelect;
export type InsertForensicsTimeline = typeof forensicsTimeline.$inferInsert;

export const investigationArtifacts = mysqlTable("investigation_artifacts", {
  id: int("id").autoincrement().primaryKey(),
  artifactId: varchar("artifactId", { length: 64 }).notNull().unique(),
  incidentId: int("incidentId").notNull(),
  artifactType: varchar("artifactType", { length: 100 }).notNull(),
  title: varchar("title", { length: 255 }).notNull(),
  sourceTable: varchar("sourceTable", { length: 100 }),
  sourceRecordId: varchar("sourceRecordId", { length: 64 }),
  tags: json("tags"),
  metadata: json("metadata"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type InvestigationArtifact = typeof investigationArtifacts.$inferSelect;
export type InsertInvestigationArtifact = typeof investigationArtifacts.$inferInsert;

// ============================================================================
// HONEYPOT TABLES
// ============================================================================

export const honeypots = mysqlTable("honeypots", {
  id: int("id").autoincrement().primaryKey(),
  honeypotId: varchar("honeypotId", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  serviceType: varchar("serviceType", { length: 100 }).notNull(),
  bindPort: int("bindPort").notNull(),
  bindIp: varchar("bindIp", { length: 45 }),
  enabled: boolean("enabled").default(true),
  interactionCount: int("interactionCount").default(0),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
});

export type Honeypot = typeof honeypots.$inferSelect;
export type InsertHoneypot = typeof honeypots.$inferInsert;

export const honeypotInteractions = mysqlTable("honeypot_interactions", {
  id: int("id").autoincrement().primaryKey(),
  interactionId: varchar("interactionId", { length: 64 }).notNull().unique(),
  honeypotId: int("honeypotId").notNull(),
  attackerIp: varchar("attackerIp", { length: 45 }).notNull(),
  attackerPort: int("attackerPort"),
  attackerCountry: varchar("attackerCountry", { length: 100 }),
  attackerCity: varchar("attackerCity", { length: 100 }),
  attackerLatitude: decimal("attackerLatitude", { precision: 10, scale: 6 }),
  attackerLongitude: decimal("attackerLongitude", { precision: 10, scale: 6 }),
  interactionType: varchar("interactionType", { length: 100 }),
  payload: text("payload"),
  credentials: json("credentials"),
  userAgent: text("userAgent"),
  timestamp: timestamp("timestamp").defaultNow(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (table) => ({
  attackerIpIdx: index("idx_attacker_ip").on(table.attackerIp),
  honeypotIdIdx: index("idx_honeypot_id").on(table.honeypotId),
}));

export type HoneypotInteraction = typeof honeypotInteractions.$inferSelect;
export type InsertHoneypotInteraction = typeof honeypotInteractions.$inferInsert;

// ============================================================================
// ADDITIONAL SECURITY DOMAINS
// ============================================================================

export const iamEvents = mysqlTable("iam_events", {
  id: int("id").autoincrement().primaryKey(),
  iamEventId: varchar("iamEventId", { length: 64 }).notNull().unique(),
  provider: varchar("provider", { length: 100 }).default("okta"),
  actor: varchar("actor", { length: 255 }).notNull(),
  action: varchar("action", { length: 255 }).notNull(),
  target: varchar("target", { length: 255 }),
  sourceIp: varchar("sourceIp", { length: 45 }),
  status: varchar("status", { length: 50 }).default("observed"),
  anomalyScore: int("anomalyScore").default(0),
  metadata: json("metadata"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type IamEvent = typeof iamEvents.$inferSelect;
export type InsertIamEvent = typeof iamEvents.$inferInsert;

export const endpointTelemetry = mysqlTable("endpoint_telemetry", {
  id: int("id").autoincrement().primaryKey(),
  telemetryId: varchar("telemetryId", { length: 64 }).notNull().unique(),
  endpointId: varchar("endpointId", { length: 100 }),
  hostname: varchar("hostname", { length: 255 }).notNull(),
  username: varchar("username", { length: 255 }),
  processName: varchar("processName", { length: 255 }),
  parentProcess: varchar("parentProcess", { length: 255 }),
  processHash: varchar("processHash", { length: 128 }),
  commandLine: text("commandLine"),
  destinationIp: varchar("destinationIp", { length: 45 }),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).default("low"),
  status: varchar("status", { length: 50 }).default("observed"),
  tags: json("tags"),
  metadata: json("metadata"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type EndpointTelemetry = typeof endpointTelemetry.$inferSelect;
export type InsertEndpointTelemetry = typeof endpointTelemetry.$inferInsert;

export const cloudFindings = mysqlTable("cloud_findings", {
  id: int("id").autoincrement().primaryKey(),
  findingId: varchar("findingId", { length: 64 }).notNull().unique(),
  provider: varchar("provider", { length: 64 }).default("aws"),
  accountId: varchar("accountId", { length: 64 }),
  resourceId: varchar("resourceId", { length: 255 }).notNull(),
  service: varchar("service", { length: 100 }),
  findingType: varchar("findingType", { length: 255 }).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).default("medium"),
  status: varchar("status", { length: 50 }).default("open"),
  metadata: json("metadata"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type CloudFinding = typeof cloudFindings.$inferSelect;
export type InsertCloudFinding = typeof cloudFindings.$inferInsert;

export const phishingAnalyses = mysqlTable("phishing_analyses", {
  id: int("id").autoincrement().primaryKey(),
  analysisId: varchar("analysisId", { length: 64 }).notNull().unique(),
  emailSubject: varchar("emailSubject", { length: 255 }).notNull(),
  sender: varchar("sender", { length: 320 }).notNull(),
  recipient: varchar("recipient", { length: 320 }),
  urlCount: int("urlCount").default(0),
  attachmentCount: int("attachmentCount").default(0),
  verdict: mysqlEnum("verdict", ["malicious", "suspicious", "benign"]).default("suspicious"),
  confidence: int("confidence").default(50),
  reasons: json("reasons"),
  indicators: json("indicators"),
  linkedIncidentId: int("linkedIncidentId"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type PhishingAnalysis = typeof phishingAnalyses.$inferSelect;
export type InsertPhishingAnalysis = typeof phishingAnalyses.$inferInsert;

export const soarPlaybooks = mysqlTable("soar_playbooks", {
  id: int("id").autoincrement().primaryKey(),
  playbookId: varchar("playbookId", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  triggerType: varchar("triggerType", { length: 100 }).notNull(),
  enabled: boolean("enabled").default(true),
  steps: json("steps").notNull(),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow(),
});

export type SoarPlaybook = typeof soarPlaybooks.$inferSelect;
export type InsertSoarPlaybook = typeof soarPlaybooks.$inferInsert;

export const soarExecutions = mysqlTable("soar_executions", {
  id: int("id").autoincrement().primaryKey(),
  executionId: varchar("executionId", { length: 64 }).notNull().unique(),
  playbookId: int("playbookId").notNull(),
  incidentId: int("incidentId"),
  triggerEntityType: varchar("triggerEntityType", { length: 100 }),
  triggerEntityId: varchar("triggerEntityId", { length: 64 }),
  status: varchar("status", { length: 50 }).default("pending"),
  output: json("output"),
  startedAt: timestamp("startedAt").defaultNow().notNull(),
  completedAt: timestamp("completedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type SoarExecution = typeof soarExecutions.$inferSelect;
export type InsertSoarExecution = typeof soarExecutions.$inferInsert;

export const platformAuditLogs = mysqlTable("platform_audit_logs", {
  id: int("id").autoincrement().primaryKey(),
  auditId: varchar("auditId", { length: 64 }).notNull().unique(),
  actorUserId: int("actorUserId"),
  action: varchar("action", { length: 255 }).notNull(),
  entityType: varchar("entityType", { length: 100 }).notNull(),
  entityId: varchar("entityId", { length: 100 }),
  outcome: varchar("outcome", { length: 50 }).default("success"),
  details: json("details"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type PlatformAuditLog = typeof platformAuditLogs.$inferSelect;
export type InsertPlatformAuditLog = typeof platformAuditLogs.$inferInsert;
