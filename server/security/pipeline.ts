/**
 * Sentinel-X ingestion & detection pipeline.
 *
 * Invariants this module enforces (each one maps to a production incident
 * class the previous implementation was exposed to):
 *
 * 1. IDEMPOTENT INCIDENTS — pipeline-created incidents carry a deterministic
 *    correlationKey (rule × entity × time-bucket). The UNIQUE index on that
 *    column is the dedup guarantee; concurrent writers converge on one
 *    incident instead of creating one per matching event (incident storms).
 * 2. BOUNDED WORK PER EVENT — enrichment uses exact indexed lookups (IN() on
 *    ioc value, SQL COUNT over a composite index) instead of paging IOC/CVE/
 *    event tables into memory per event. Cost per event is O(rules), not
 *    O(table sizes).
 * 3. NO UNTRUSTED REGEX ON THE EVENT LOOP — rule regexes are length-capped,
 *    screened for catastrophic-backtracking constructs, compiled once
 *    (cached), and run against a bounded slice of the log. A hostile or
 *    careless rule must not be able to freeze the process. (For hard
 *    guarantees swap the engine for RE2; the seam is compileSafeRegex.)
 * 4. ATOMIC PERSISTENCE — the event, its detections, alerts, and incident
 *    links commit in one transaction. No more orphaned alerts pointing at
 *    events that failed to persist.
 * 5. FAIL-CLOSED RULES — a rule whose detectionLogic fails validation, or
 *    that constrains nothing (would match every event), is skipped and
 *    logged, never evaluated permissively.
 */
import { createHash } from "node:crypto";
import { nanoid } from "nanoid";
import { z } from "zod";
import { and, eq, gte, sql } from "drizzle-orm";
import {
  alerts as alertsTable,
  idsDetections,
  incidentAuditTrail,
  incidents as incidentsTable,
  securityEvents,
  type Asset,
  type IdsRule,
  type IndicatorOfCompromise,
} from "../../drizzle/schema";
import * as db from "../db";
import { getDb } from "../db";
import { PipelineError } from "../_core/errors";
import { logger } from "../_core/logger";

const log = logger.child({ component: "pipeline" });

export type IngestSourceType = "json" | "syslog" | "raw" | "iam" | "endpoint" | "cloud" | "phishing";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
type Severity = (typeof SEVERITIES)[number];

export type NormalizedEvent = {
  eventType: string;
  eventCategory: string;
  severity: Severity;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  hostname?: string;
  username?: string;
  rawLog?: string;
  parsedData: Record<string, unknown>;
};

// ============================================================================
// NORMALIZATION
// ============================================================================

const MITRE_LOOKUP: Record<string, { technique: string; tactic: string }> = {
  authentication_failed: { technique: "T1110", tactic: "Credential Access" },
  brute_force: { technique: "T1110", tactic: "Credential Access" },
  suspicious_powershell: { technique: "T1059.001", tactic: "Execution" },
  suspicious_process: { technique: "T1059", tactic: "Execution" },
  privilege_escalation: { technique: "T1068", tactic: "Privilege Escalation" },
  port_scan: { technique: "T1046", tactic: "Discovery" },
  malware_detected: { technique: "T1105", tactic: "Command and Control" },
  lateral_movement: { technique: "T1021", tactic: "Lateral Movement" },
  phishing_email: { technique: "T1566", tactic: "Initial Access" },
  suspicious_login: { technique: "T1078", tactic: "Defense Evasion" },
};

function safeJsonParse(payload: unknown): Record<string, unknown> {
  if (typeof payload === "object" && payload !== null) return payload as Record<string, unknown>;
  if (typeof payload !== "string") return { value: payload };
  try {
    const parsed: unknown = JSON.parse(payload);
    if (typeof parsed === "object" && parsed !== null) return parsed as Record<string, unknown>;
    return { value: parsed };
  } catch {
    return { message: payload };
  }
}

function extractIps(text: string): string[] {
  const matches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  return matches ?? [];
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}

function extractPort(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * External payloads must not be trusted to name a valid severity — an
 * arbitrary string here previously flowed straight into a MySQL enum column
 * (insert error at best, silent truncation at worst).
 */
export function parseSeverity(value: unknown): Severity | undefined {
  return SEVERITIES.includes(value as Severity) ? (value as Severity) : undefined;
}

function inferSeverity(message: string): Severity {
  const lower = message.toLowerCase();
  if (/(ransom|exfil|domain admin|critical|root compromise)/.test(lower)) return "critical";
  if (/(malware|lateral|suspicious|powershell|privilege|high)/.test(lower)) return "high";
  if (/(failed|denied|scan|warning|medium)/.test(lower)) return "medium";
  return "low";
}

function inferType(message: string): { eventType: string; eventCategory: string } {
  const lower = message.toLowerCase();
  if (/(failed password|login failed|authentication failure|invalid user)/.test(lower)) {
    return { eventType: "authentication_failed", eventCategory: "identity" };
  }
  if (/(powershell|encodedcommand|invoke-webrequest)/.test(lower)) {
    return { eventType: "suspicious_powershell", eventCategory: "endpoint" };
  }
  if (/(sudo|whoami \/priv|setuid|privilege escalation)/.test(lower)) {
    return { eventType: "privilege_escalation", eventCategory: "endpoint" };
  }
  if (/(nmap|masscan|port scan|scan detected)/.test(lower)) {
    return { eventType: "port_scan", eventCategory: "network" };
  }
  if (/(c2|beacon|malware|trojan|ransomware)/.test(lower)) {
    return { eventType: "malware_detected", eventCategory: "endpoint" };
  }
  if (/(rlogin|psexec|smb session|winrm|lateral)/.test(lower)) {
    return { eventType: "lateral_movement", eventCategory: "network" };
  }
  if (/(email|invoice|urgent action|verify your account)/.test(lower)) {
    return { eventType: "phishing_email", eventCategory: "email" };
  }
  return { eventType: "generic_security_event", eventCategory: "security" };
}

function normalizeSyslog(payload: string): NormalizedEvent {
  const syslogMatch = payload.match(/^(?:<\d+>)?(\w{3}\s+\d+\s+[\d:]+)?\s*([^\s]+)?\s*([^:]+)?:?\s*(.*)$/);
  const message = syslogMatch?.[4] || payload;
  const inferred = inferType(message);
  const ips = extractIps(message);
  const usernameMatch = message.match(/user(?:name)?[=:\s]+([\w.-]+)/i) || message.match(/for\s+([\w.-]+)\s+from/i);
  return {
    eventType: inferred.eventType,
    eventCategory: inferred.eventCategory,
    severity: inferSeverity(message),
    sourceIp: ips[0],
    destinationIp: ips[1],
    hostname: syslogMatch?.[2],
    username: usernameMatch?.[1],
    rawLog: payload,
    parsedData: { syslogHost: syslogMatch?.[2], syslogApp: syslogMatch?.[3], message },
  };
}

export function normalizeEvent(sourceType: IngestSourceType, payload: unknown): NormalizedEvent {
  if (sourceType === "syslog" && typeof payload === "string") {
    return normalizeSyslog(payload);
  }

  const parsed = safeJsonParse(payload);
  const message = String(parsed.message ?? parsed.log ?? parsed.event ?? payload ?? "");
  const inferred = inferType(message);
  const ips = extractIps(`${message} ${JSON.stringify(parsed)}`);

  return {
    eventType: asOptionalString(parsed.eventType) ?? inferred.eventType,
    eventCategory: asOptionalString(parsed.eventCategory) ?? asOptionalString(parsed.category) ?? inferred.eventCategory,
    severity: parseSeverity(parsed.severity) ?? inferSeverity(message),
    sourceIp: asOptionalString(parsed.sourceIp) ?? asOptionalString(parsed.src_ip) ?? ips[0],
    destinationIp: asOptionalString(parsed.destinationIp) ?? asOptionalString(parsed.dst_ip) ?? ips[1],
    sourcePort: extractPort(parsed.sourcePort ?? parsed.src_port),
    destinationPort: extractPort(parsed.destinationPort ?? parsed.dst_port),
    protocol: asOptionalString(parsed.protocol),
    hostname: asOptionalString(parsed.hostname) ?? asOptionalString(parsed.host),
    username: asOptionalString(parsed.username) ?? asOptionalString(parsed.user),
    rawLog: typeof payload === "string" ? payload : JSON.stringify(payload),
    parsedData: parsed,
  };
}

// ============================================================================
// ENRICHMENT
// ============================================================================

function isPrivateIp(ip?: string | null): boolean {
  if (!ip) return false;
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) || /^127\./.test(ip);
}

type GeoResult = {
  ip: string;
  scope: "private" | "public";
  country: string;
  city: string;
  latitude: number | null;
  longitude: number | null;
};

/** Offline, deterministic geo classification (documented demo boundary). */
function lookupGeo(ip?: string | null): GeoResult | null {
  if (!ip) return null;
  if (isPrivateIp(ip)) {
    return { ip, scope: "private", country: "internal", city: "internal", latitude: null, longitude: null };
  }
  const firstOctet = Number(ip.split(".")[0] || 0);
  if (firstOctet < 64) return { ip, scope: "public", country: "United States", city: "Ashburn", latitude: 39.0438, longitude: -77.4874 };
  if (firstOctet < 128) return { ip, scope: "public", country: "Germany", city: "Frankfurt", latitude: 50.1109, longitude: 8.6821 };
  if (firstOctet < 192) return { ip, scope: "public", country: "Singapore", city: "Singapore", latitude: 1.3521, longitude: 103.8198 };
  return { ip, scope: "public", country: "Australia", city: "Sydney", latitude: -33.8688, longitude: 151.2093 };
}

/** Candidate observables of an event that can match an IOC value exactly. */
export function collectIocCandidates(event: NormalizedEvent): string[] {
  const candidates = new Set<string>();
  for (const value of [event.sourceIp, event.destinationIp, event.username, event.hostname]) {
    if (value) candidates.add(value);
  }
  if (event.rawLog) {
    for (const ip of extractIps(event.rawLog)) candidates.add(ip);
  }
  return Array.from(candidates);
}

type CveRecord = { cveId: string; severity: string; title: string; affectedProducts: unknown };

function buildCveCandidates(asset: Asset | undefined, cves: CveRecord[]): CveRecord[] {
  const services = Array.isArray(asset?.services) ? (asset.services as unknown[]) : [];
  if (!services.length) return [];
  const flattened = JSON.stringify(services).toLowerCase();
  return cves
    .filter((cve) => {
      const affected = Array.isArray(cve.affectedProducts) ? (cve.affectedProducts as unknown[]) : [];
      return affected.some((product) => flattened.includes(String(product).toLowerCase()));
    })
    .slice(0, 5);
}

// ============================================================================
// RULE LOGIC — validated, fail-closed
// ============================================================================

/**
 * The persisted `detectionLogic` JSON is analyst-authored input. It is
 * validated at the trust boundary (here), not trusted because it came from
 * our own database — a malformed rule must degrade to "rule skipped, loudly",
 * never to "pipeline crashed" or "rule matched everything".
 */
export const ruleLogicSchema = z.object({
  eventTypes: z.array(z.string()).max(50).optional(),
  categories: z.array(z.string()).max(50).optional(),
  protocols: z.array(z.string()).max(50).optional(),
  destinationPorts: z.array(z.coerce.number().int()).max(100).optional(),
  sourcePorts: z.array(z.coerce.number().int()).max(100).optional(),
  usernames: z.array(z.string()).max(100).optional(),
  allKeywords: z.array(z.string().min(1).max(256)).max(25).optional(),
  anyKeywords: z.array(z.string().min(1).max(256)).max(25).optional(),
  rawRegex: z.string().min(1).max(256).optional(),
  matchIoc: z.boolean().optional(),
  assetCriticalities: z.array(z.enum(SEVERITIES)).optional(),
  threshold: z
    .object({
      count: z.coerce.number().int().min(1).max(100_000).optional(),
      windowMinutes: z.coerce.number().int().min(1).max(1_440).optional(),
      field: z.enum(["sourceIp", "username"]).optional(),
    })
    .optional(),
});

export type RuleLogic = z.infer<typeof ruleLogicSchema>;

const CONSTRAINING_KEYS: (keyof RuleLogic)[] = [
  "eventTypes",
  "categories",
  "protocols",
  "destinationPorts",
  "sourcePorts",
  "usernames",
  "allKeywords",
  "anyKeywords",
  "rawRegex",
  "matchIoc",
  "assetCriticalities",
];

/**
 * Resolve a rule's logic. Returns null when the rule must be skipped:
 * invalid logic (fail-closed) or vacuous logic that constrains nothing —
 * the old implementation happily let such a rule match every event, which
 * combined with auto-incident creation is a self-inflicted alert flood.
 */
export function parseRuleLogic(rule: Pick<IdsRule, "detectionLogic" | "pattern">): RuleLogic | null {
  let logic: RuleLogic;

  if (rule.detectionLogic && typeof rule.detectionLogic === "object") {
    const result = ruleLogicSchema.safeParse(rule.detectionLogic);
    if (!result.success) return null;
    logic = result.data;
  } else if (rule.pattern) {
    const parts = String(rule.pattern)
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
      .slice(0, 25);
    logic = parts.length ? { anyKeywords: parts } : {};
  } else {
    logic = {};
  }

  const constrains =
    CONSTRAINING_KEYS.some((key) => {
      const value = logic[key];
      return Array.isArray(value) ? value.length > 0 : value !== undefined;
    }) || (logic.threshold?.count ?? 0) > 1;

  return constrains ? logic : null;
}

// ============================================================================
// SAFE REGEX — screened, cached, bounded
// ============================================================================

const MAX_REGEX_SOURCE_LENGTH = 256;
const MAX_REGEX_HAYSTACK_LENGTH = 8_192;
const REGEX_CACHE_MAX = 500;

// Conservative screens for the constructs behind catastrophic backtracking:
// a quantified group that is itself quantified — (a+)+, (a*)*, (?:x+){2,} —
// and quantified backreferences. False positives are acceptable; a rejected
// rule is logged and skipped. False negatives are bounded by the haystack
// cap. For a hard non-backtracking guarantee, replace `new RegExp` with RE2
// here — this function is the single seam.
const NESTED_QUANTIFIER = /(?:[*+]|\{\d+(?:,\d*)?\})\)+[*+{?]/;
const QUANTIFIED_BACKREFERENCE = /\\[1-9]\d*\s*(?:[*+{]|$)/;

const regexCache = new Map<string, RegExp | null>();

/** Compile an analyst-supplied pattern, or return null if it is unsafe. */
export function compileSafeRegex(pattern: string): RegExp | null {
  if (regexCache.has(pattern)) return regexCache.get(pattern) ?? null;

  let compiled: RegExp | null = null;
  if (
    pattern.length <= MAX_REGEX_SOURCE_LENGTH &&
    !NESTED_QUANTIFIER.test(pattern) &&
    !QUANTIFIED_BACKREFERENCE.test(pattern)
  ) {
    try {
      compiled = new RegExp(pattern, "i");
    } catch {
      compiled = null;
    }
  }

  if (regexCache.size >= REGEX_CACHE_MAX) {
    // Simple FIFO eviction; the cache exists to avoid recompiling per event,
    // not to be a perfect LRU.
    const oldest = regexCache.keys().next().value;
    if (oldest !== undefined) regexCache.delete(oldest);
  }
  regexCache.set(pattern, compiled);
  return compiled;
}

// ============================================================================
// RULE EVALUATION
// ============================================================================

function containsAllKeywords(haystack: string, keywords: string[]): boolean {
  return keywords.every((keyword) => haystack.includes(keyword.toLowerCase()));
}

function containsAnyKeyword(haystack: string, keywords: string[]): boolean {
  return keywords.some((keyword) => haystack.includes(keyword.toLowerCase()));
}

function pickSeverityWeight(severity: Severity): number {
  return severity === "critical" ? 35 : severity === "high" ? 25 : severity === "medium" ? 15 : 5;
}

export type RuleMatch = {
  confidence: number;
  reasons: string[];
  mitreTechnique: string | null;
  mitreTactic: string | null;
};

type ThresholdCounter = (field: "sourceIp" | "username", value: string, since: Date) => Promise<number>;

/**
 * Evaluate one rule against one event. Static conditions are pure; the
 * threshold condition counts committed events via the injected counter
 * (indexed SQL COUNT) so bursts are measured against the real table, not an
 * in-memory snapshot. The counter is injected to keep this testable without
 * a database.
 */
async function evaluateRule(params: {
  rule: IdsRule;
  logic: RuleLogic;
  event: NormalizedEvent;
  iocHits: IndicatorOfCompromise[];
  asset: Asset | undefined;
  countEvents: ThresholdCounter;
  now: Date;
}): Promise<RuleMatch | null> {
  const { rule, logic, event, iocHits, asset, countEvents, now } = params;
  const searchable = `${event.rawLog ?? ""} ${JSON.stringify(event.parsedData ?? {})} ${event.eventType} ${event.eventCategory}`.toLowerCase();
  const reasons: string[] = [];

  if (logic.eventTypes?.length && !logic.eventTypes.includes(event.eventType)) return null;
  if (logic.categories?.length && !logic.categories.includes(event.eventCategory)) return null;
  if (logic.protocols?.length && (!event.protocol || !logic.protocols.includes(event.protocol))) return null;
  if (logic.destinationPorts?.length && (event.destinationPort === undefined || !logic.destinationPorts.includes(event.destinationPort))) return null;
  if (logic.sourcePorts?.length && (event.sourcePort === undefined || !logic.sourcePorts.includes(event.sourcePort))) return null;
  if (logic.usernames?.length && (!event.username || !logic.usernames.includes(event.username))) return null;
  if (logic.allKeywords?.length && !containsAllKeywords(searchable, logic.allKeywords)) return null;
  if (logic.anyKeywords?.length && !containsAnyKeyword(searchable, logic.anyKeywords)) return null;

  if (logic.rawRegex) {
    const regex = compileSafeRegex(logic.rawRegex);
    if (!regex) {
      log.warn("rule skipped: unsafe or invalid regex", { ruleId: rule.ruleId, ruleName: rule.ruleName });
      return null;
    }
    if (!regex.test((event.rawLog ?? "").slice(0, MAX_REGEX_HAYSTACK_LENGTH))) return null;
    reasons.push(`Matched regex ${logic.rawRegex}`);
  }

  if (logic.matchIoc && iocHits.length === 0) return null;
  if (logic.matchIoc && iocHits.length > 0) reasons.push("Matched IOC enrichment hit");

  if (logic.assetCriticalities?.length) {
    if (!asset?.criticality || !logic.assetCriticalities.includes(asset.criticality)) return null;
    reasons.push(`Asset criticality ${asset.criticality}`);
  }

  const thresholdCount = logic.threshold?.count ?? rule.thresholdCount ?? 1;
  const thresholdWindowMinutes = logic.threshold?.windowMinutes ?? rule.thresholdWindowMinutes ?? 5;
  const thresholdField = logic.threshold?.field ?? "sourceIp";
  if (thresholdCount > 1) {
    const compareValue = thresholdField === "username" ? event.username : event.sourceIp;
    // No correlatable entity on the event → the threshold condition cannot
    // be satisfied. Fail closed rather than matching on a technicality.
    if (!compareValue) return null;
    const since = new Date(now.getTime() - thresholdWindowMinutes * 60_000);
    const matchCount = await countEvents(thresholdField, compareValue, since);
    if (matchCount < thresholdCount) return null;
    reasons.push(`Threshold met on ${thresholdField}: ${matchCount}/${thresholdCount} in ${thresholdWindowMinutes}m`);
  }

  const mitre =
    MITRE_LOOKUP[event.eventType] ||
    (rule.attackTechnique ? { technique: rule.attackTechnique, tactic: rule.attackTactic || "Detection" } : undefined);

  const confidence = Math.min(
    99,
    (rule.confidenceWeight ?? 50) +
      pickSeverityWeight(event.severity) +
      (iocHits.length > 0 ? 15 : 0) +
      (asset?.criticality === "critical" ? 12 : asset?.criticality === "high" ? 8 : 0) +
      reasons.length * 3,
  );

  if (reasons.length === 0) {
    reasons.push(`Matched Sigma-like logic for ${rule.ruleName}`);
  }

  return {
    confidence,
    reasons,
    mitreTechnique: mitre?.technique || rule.attackTechnique || null,
    mitreTactic: mitre?.tactic || rule.attackTactic || null,
  };
}

// ============================================================================
// INCIDENT CORRELATION
// ============================================================================

const INCIDENT_CONFIDENCE_THRESHOLD = 85;
const DEFAULT_CORRELATION_BUCKET_MINUTES = 15;

/**
 * Deterministic idempotency key: every event that matches the same rule for
 * the same entity within the same time bucket computes the same key, so the
 * UNIQUE index collapses them onto one incident. The bucket bounds how long
 * an ongoing attack aggregates before a fresh incident is opened — an
 * SSH brute-force spraying 10k events becomes one incident per window, not
 * 10k incidents.
 */
export function buildCorrelationKey(params: {
  ruleId: string;
  entity: string;
  bucketMinutes?: number;
  now?: Date;
}): string {
  const bucketMinutes = params.bucketMinutes ?? DEFAULT_CORRELATION_BUCKET_MINUTES;
  const nowMs = (params.now ?? new Date()).getTime();
  const bucket = Math.floor(nowMs / (bucketMinutes * 60_000));
  return createHash("sha256").update(`${params.ruleId}|${params.entity}|${bucket}`).digest("hex");
}

/** The most specific stable identity the event offers for correlation. */
export function correlationEntityFor(event: NormalizedEvent): string {
  return event.sourceIp ?? event.username ?? event.hostname ?? event.eventType;
}

// ============================================================================
// INGESTION ORCHESTRATION
// ============================================================================

export type IngestResult = {
  normalized: NormalizedEvent;
  enrichment: Record<string, unknown>;
  eventId: number;
  alerts: { id: number; title: string; severity: Severity; incidentId?: number }[];
  detections: {
    ruleName: string;
    confidence: number;
    reasons: string[];
    incidentId?: number;
    mitreTechnique: string | null;
    mitreTactic: string | null;
  }[];
  incidentIds: number[];
};

/**
 * InnoDB can deadlock when several transactions race an insert on the same
 * unique key (the correlationKey dedup path does exactly that during an
 * event burst). MySQL resolves it by rolling back one victim — which, left
 * unhandled, silently drops that victim's EVENT, not just its incident
 * link. Deadlock victims are safe to retry: nothing committed.
 */
const RETRYABLE_MYSQL_ERRNOS = new Set([1213 /* ER_LOCK_DEADLOCK */, 1205 /* ER_LOCK_WAIT_TIMEOUT */]);

/** Drizzle wraps driver errors (error.cause); walk a short cause chain. */
function findMysqlErrno(error: unknown): number | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < 3 && current; depth++) {
    const errno = (current as { errno?: unknown }).errno;
    if (typeof errno === "number") return errno;
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

export function isRetryableTxError(error: unknown): boolean {
  const errno = findMysqlErrno(error);
  return errno !== undefined && RETRYABLE_MYSQL_ERRNOS.has(errno);
}

/**
 * ER_DUP_ENTRY on the event insert is the idempotency signal for queue
 * replays: the persist transaction is atomic, so if a caller-supplied
 * eventId already exists, the ENTIRE outcome (event + alerts + detections +
 * incident links) committed on a previous attempt. The retry must be
 * acknowledged as success, not reprocessed.
 */
export function isDuplicateEntryError(error: unknown): boolean {
  return findMysqlErrno(error) === 1062 /* ER_DUP_ENTRY */;
}

export async function ingestAndDetect(input: {
  sourceType: IngestSourceType;
  payload: unknown;
  assetId?: number;
  userId?: number;
  /**
   * Caller-supplied idempotency key for the security_events UNIQUE eventId.
   * Queue workers pass a key derived from the job id so a retry after a
   * crash-post-commit hits ER_DUP_ENTRY (see isDuplicateEntryError) instead
   * of double-ingesting. Omitted → fresh nanoid (interactive path).
   */
  eventId?: string;
}): Promise<IngestResult> {
  const pipelineId = nanoid(12);
  const plog = log.child({ pipelineId, sourceType: input.sourceType });
  const totalTimer = plog.startTimer();
  let stage = "normalize";

  try {
    const now = new Date();
    const normalized = normalizeEvent(input.sourceType, input.payload);

    // ---- Enrichment: exact, indexed lookups only ----
    stage = "enrich";
    const enrichTimer = plog.startTimer();
    const iocCandidates = collectIocCandidates(normalized);
    const [asset, iocHits] = await Promise.all([
      input.assetId
        ? db.getAssetById(input.assetId)
        : db.findAssetByHostnameOrIp(normalized.hostname, normalized.sourceIp || normalized.destinationIp),
      db.findIOCsByValues(iocCandidates),
    ]);
    // CVE mapping is only meaningful when the asset declares services; skip
    // the fetch entirely otherwise. (Roadmap: replace the JSON scan with an
    // asset_service ↔ cve join table; this bounded fetch is the interim.)
    const cves = Array.isArray(asset?.services) && (asset.services as unknown[]).length > 0 ? await db.getAllCVEs(500) : [];
    const cveCandidates = buildCveCandidates(asset, cves as CveRecord[]);
    const mitre = MITRE_LOOKUP[normalized.eventType];

    const enrichment = {
      geo: { source: lookupGeo(normalized.sourceIp), destination: lookupGeo(normalized.destinationIp) },
      assetContext: asset
        ? {
            id: asset.id,
            assetId: asset.assetId,
            hostname: asset.hostname,
            criticality: asset.criticality,
            owner: asset.businessOwner,
            environment: asset.environment,
          }
        : null,
      iocHits: iocHits.map((ioc) => ({
        value: ioc.iocValue,
        type: ioc.iocType,
        threatLevel: ioc.threatLevel,
        confidence: ioc.confidence,
      })),
      cveCandidates: cveCandidates.map((cve) => ({ cveId: cve.cveId, severity: cve.severity, title: cve.title })),
      mitre: mitre ?? null,
    };
    enrichTimer("enrichment complete", { iocHits: iocHits.length, assetMatched: Boolean(asset) });

    stage = "load-rules";
    const activeRules = await db.getIdsRules(true);

    // ---- Persistence: one transaction for the whole outcome ----
    stage = "persist";
    const dbi = await getDb();
    const runTransaction = () => dbi.transaction(async (tx): Promise<IngestResult> => {
      const [eventRow] = await tx
        .insert(securityEvents)
        .values({
          eventId: input.eventId ?? nanoid(),
          sourceType: input.sourceType,
          sourceIp: normalized.sourceIp,
          destinationIp: normalized.destinationIp,
          sourcePort: normalized.sourcePort,
          destinationPort: normalized.destinationPort,
          protocol: normalized.protocol,
          eventType: normalized.eventType,
          eventCategory: normalized.eventCategory,
          rawLog: normalized.rawLog,
          parsedData: normalized.parsedData,
          enrichment,
          severity: normalized.severity,
          status: "normalized",
          userId: input.userId,
          hostname: normalized.hostname,
          username: normalized.username,
          timestamp: now,
          createdAt: now,
        })
        .$returningId();
      const eventPk = eventRow.id;

      // Threshold counts run on the transaction connection so the count sees
      // this event's own (uncommitted) row — no off-by-one fudging.
      const countEvents: ThresholdCounter = async (field, value, since) => {
        const column = field === "sourceIp" ? securityEvents.sourceIp : securityEvents.username;
        const rows = await tx
          .select({ count: sql<number>`COUNT(*)` })
          .from(securityEvents)
          .where(and(eq(column, value), gte(securityEvents.timestamp, since)));
        return Number(rows[0]?.count ?? 0);
      };

      const detections: IngestResult["detections"] = [];
      const alertsOut: IngestResult["alerts"] = [];
      const incidentIds: number[] = [];

      for (const rule of activeRules) {
        const logic = parseRuleLogic(rule);
        if (!logic) {
          log.warn("rule skipped: invalid or vacuous detection logic", { ruleId: rule.ruleId, ruleName: rule.ruleName });
          continue;
        }

        const match = await evaluateRule({ rule, logic, event: normalized, iocHits, asset, countEvents, now });
        if (!match) continue;

        const ruleSeverity: Severity = rule.severity ?? normalized.severity;

        // ---- Idempotent incident creation ----
        let incidentPk: number | undefined;
        if (match.confidence >= INCIDENT_CONFIDENCE_THRESHOLD || rule.severity === "critical") {
          const correlationKey = buildCorrelationKey({
            ruleId: rule.ruleId,
            entity: correlationEntityFor(normalized),
            bucketMinutes: logic.threshold?.windowMinutes ?? DEFAULT_CORRELATION_BUCKET_MINUTES,
            now,
          });

          // Atomic get-or-create: `LAST_INSERT_ID(id)` makes the duplicate
          // path surface the EXISTING row's id through insertId, so two
          // concurrent writers both leave with the same incident id without
          // a read-check-write race or snapshot-visibility problems.
          const attemptedIncidentId = nanoid();
          const [header] = await tx
            .insert(incidentsTable)
            .values({
              incidentId: attemptedIncidentId,
              title: `Detection: ${rule.ruleName}`,
              description: `Auto-created from ingestion pipeline for ${normalized.eventType}`,
              severity: ruleSeverity,
              status: "open",
              classification: normalized.eventCategory,
              createdBy: input.userId,
              detectedAt: now,
              affectedAssets: asset ? [asset.hostname] : undefined,
              correlationKey,
              createdAt: now,
              updatedAt: now,
            })
            .onDuplicateKeyUpdate({ set: { id: sql`LAST_INSERT_ID(${incidentsTable.id})` } });

          incidentPk = header.insertId || undefined;

          if (incidentPk) {
            // created-vs-correlated cannot be inferred from affectedRows:
            // mysql2 negotiates CLIENT_FOUND_ROWS by default, so the
            // duplicate no-change path ALSO reports affectedRows=1 —
            // indistinguishable from a fresh insert. Compare the persisted
            // row's incidentId against the nanoid THIS call tried to insert
            // instead: deterministic, and immune to driver flags and
            // timestamp precision. (Read-own-write inside the transaction.)
            const [persisted] = await tx
              .select({ incidentId: incidentsTable.incidentId })
              .from(incidentsTable)
              .where(eq(incidentsTable.id, incidentPk))
              .limit(1);
            const isNewIncident = persisted?.incidentId === attemptedIncidentId;
            incidentIds.push(incidentPk);
            if (isNewIncident) {
              await tx.insert(incidentAuditTrail).values({
                incidentId: incidentPk,
                action: "Auto-created from detection pipeline",
                performedBy: input.userId,
                details: { rule: rule.ruleName, eventType: normalized.eventType, correlationKey },
                timestamp: now,
              });
              plog.info("incident created", { incidentId: incidentPk, ruleId: rule.ruleId, confidence: match.confidence });
            } else {
              plog.info("event correlated into existing incident", { incidentId: incidentPk, ruleId: rule.ruleId });
            }
          }
        }

        const [alertRow] = await tx
          .insert(alertsTable)
          .values({
            alertId: nanoid(),
            title: `${rule.ruleName} matched on ${normalized.hostname || normalized.sourceIp || normalized.eventType}`,
            description: match.reasons.join("; "),
            severity: ruleSeverity,
            ruleId: rule.ruleId,
            ruleName: rule.ruleName,
            sourceEvents: [eventPk],
            status: incidentPk ? "triaged" : "new",
            incidentId: incidentPk,
            metadata: {
              confidence: match.confidence,
              reasons: match.reasons,
              mitreTechnique: match.mitreTechnique,
              mitreTactic: match.mitreTactic,
              enrichment,
            },
            timestamp: now,
            createdAt: now,
            updatedAt: now,
          })
          .$returningId();

        await tx.insert(idsDetections).values({
          detectionId: nanoid(),
          ruleId: rule.id,
          eventId: eventPk,
          sourceIp: normalized.sourceIp,
          destinationIp: normalized.destinationIp,
          incidentId: incidentPk,
          confidence: match.confidence,
          matchReasons: match.reasons,
          mitreTechnique: match.mitreTechnique || undefined,
          mitreTactic: match.mitreTactic || undefined,
          timestamp: now,
          createdAt: now,
        });

        detections.push({
          ruleName: rule.ruleName,
          confidence: match.confidence,
          reasons: match.reasons,
          incidentId: incidentPk,
          mitreTechnique: match.mitreTechnique,
          mitreTactic: match.mitreTactic,
        });
        alertsOut.push({ id: alertRow.id, title: rule.ruleName, severity: ruleSeverity, incidentId: incidentPk });
      }

      return { normalized, enrichment, eventId: eventPk, alerts: alertsOut, detections, incidentIds };
    });

    // Single bounded retry: a deadlock victim committed nothing, and the
    // correlation key is derived from `now` (captured above), so the retry
    // converges on the same incident. More than one retry under sustained
    // contention just adds load — fail and let the shipper's 500-handling
    // take over.
    let result: IngestResult;
    try {
      result = await runTransaction();
    } catch (error) {
      if (!isRetryableTxError(error)) throw error;
      plog.warn("persist transaction deadlocked, retrying once", {
        eventType: normalized.eventType,
        sourceIp: normalized.sourceIp,
      });
      result = await runTransaction();
    }

    totalTimer("event ingested", {
      eventId: result.eventId,
      eventType: normalized.eventType,
      detections: result.detections.length,
      incidents: result.incidentIds.length,
    });
    return result;
  } catch (error) {
    // Full diagnostics stay server-side; callers receive a typed error whose
    // safeMessage is all a client will ever see.
    const pipelineError =
      error instanceof PipelineError ? error : new PipelineError(stage, `Ingestion failed at stage '${stage}'`, { cause: error });
    plog.error("ingestion failed", error, { stage });
    throw pipelineError;
  }
}
