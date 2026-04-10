import { nanoid } from "nanoid";
import * as db from "../db";

export type IngestSourceType = "json" | "syslog" | "raw" | "iam" | "endpoint" | "cloud" | "phishing";

type Severity = "critical" | "high" | "medium" | "low";

type NormalizedEvent = {
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
  parsedData: Record<string, any>;
};

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

function safeJsonParse(payload: unknown): Record<string, any> {
  if (typeof payload === "object" && payload !== null) return payload as Record<string, any>;
  if (typeof payload !== "string") return { value: payload };
  try {
    return JSON.parse(payload);
  } catch {
    return { message: payload };
  }
}

function extractIps(text: string): string[] {
  const matches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  return matches ?? [];
}

function extractPort(value: any): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
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
    eventType: String(parsed.eventType ?? inferred.eventType),
    eventCategory: String(parsed.eventCategory ?? parsed.category ?? inferred.eventCategory),
    severity: (parsed.severity as Severity) ?? inferSeverity(message),
    sourceIp: parsed.sourceIp ?? parsed.src_ip ?? ips[0],
    destinationIp: parsed.destinationIp ?? parsed.dst_ip ?? ips[1],
    sourcePort: extractPort(parsed.sourcePort ?? parsed.src_port),
    destinationPort: extractPort(parsed.destinationPort ?? parsed.dst_port),
    protocol: parsed.protocol,
    hostname: parsed.hostname ?? parsed.host,
    username: parsed.username ?? parsed.user,
    rawLog: typeof payload === "string" ? payload : JSON.stringify(payload),
    parsedData: parsed,
  };
}

function isPrivateIp(ip?: string | null) {
  if (!ip) return false;
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) || /^127\./.test(ip);
}

function lookupGeo(ip?: string | null) {
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

function containsKeyword(haystack: string, keywords?: string[]) {
  if (!keywords || keywords.length === 0) return true;
  return keywords.every((keyword) => haystack.includes(keyword.toLowerCase()));
}

function containsAnyKeyword(haystack: string, keywords?: string[]) {
  if (!keywords || keywords.length === 0) return true;
  return keywords.some((keyword) => haystack.includes(keyword.toLowerCase()));
}

function normalizeLogic(rule: any) {
  if (rule.detectionLogic && typeof rule.detectionLogic === "object") return rule.detectionLogic as Record<string, any>;
  if (!rule.pattern) return {};
  const parts = String(rule.pattern)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return { anyKeywords: parts };
}

function pickSeverityWeight(severity: Severity) {
  return severity === "critical" ? 35 : severity === "high" ? 25 : severity === "medium" ? 15 : 5;
}

async function evaluateRuleMatch(params: {
  rule: any;
  event: NormalizedEvent;
  recentEvents: any[];
  iocHits: any[];
  asset: any;
}) {
  const { rule, event, recentEvents, iocHits, asset } = params;
  const logic = normalizeLogic(rule);
  const searchable = `${event.rawLog ?? ""} ${JSON.stringify(event.parsedData ?? {})} ${event.eventType} ${event.eventCategory}`.toLowerCase();
  const reasons: string[] = [];

  if (logic.eventTypes?.length && !logic.eventTypes.includes(event.eventType)) return null;
  if (logic.categories?.length && !logic.categories.includes(event.eventCategory)) return null;
  if (logic.protocols?.length && !logic.protocols.includes(event.protocol)) return null;
  if (logic.destinationPorts?.length && !logic.destinationPorts.includes(event.destinationPort)) return null;
  if (logic.sourcePorts?.length && !logic.sourcePorts.includes(event.sourcePort)) return null;
  if (logic.usernames?.length && !logic.usernames.includes(event.username)) return null;
  if (logic.allKeywords?.length && !containsKeyword(searchable, logic.allKeywords)) return null;
  if (logic.anyKeywords?.length && !containsAnyKeyword(searchable, logic.anyKeywords)) return null;

  if (logic.rawRegex) {
    const regex = new RegExp(String(logic.rawRegex), "i");
    if (!regex.test(event.rawLog ?? "")) return null;
    reasons.push(`Matched regex ${logic.rawRegex}`);
  }

  if (logic.matchIoc && iocHits.length === 0) return null;
  if (logic.matchIoc && iocHits.length > 0) reasons.push("Matched IOC enrichment hit");

  if (logic.assetCriticalities?.length) {
    if (!asset || !logic.assetCriticalities.includes(asset.criticality)) return null;
    reasons.push(`Asset criticality ${asset.criticality}`);
  }

  const thresholdCount = Number(logic.threshold?.count ?? rule.thresholdCount ?? 1);
  const thresholdWindowMinutes = Number(logic.threshold?.windowMinutes ?? rule.thresholdWindowMinutes ?? 5);
  const thresholdField = String(logic.threshold?.field ?? "sourceIp");
  if (thresholdCount > 1) {
    const cutoff = Date.now() - thresholdWindowMinutes * 60_000;
    const compareValue = thresholdField === "username" ? event.username : event.sourceIp;
    const matchCount = recentEvents.filter((recent) => {
      const recentTs = new Date(recent.timestamp).getTime();
      if (recentTs < cutoff) return false;
      return thresholdField === "username"
        ? recent.username && recent.username === compareValue
        : recent.sourceIp && recent.sourceIp === compareValue;
    }).length + 1;
    if (matchCount < thresholdCount) return null;
    reasons.push(`Threshold met on ${thresholdField}: ${matchCount}/${thresholdCount} in ${thresholdWindowMinutes}m`);
  }

  const mitre = MITRE_LOOKUP[event.eventType] || (rule.attackTechnique ? { technique: rule.attackTechnique, tactic: rule.attackTactic || "Detection" } : undefined);
  const confidence = Math.min(
    99,
    Number(rule.confidenceWeight ?? 50) +
      pickSeverityWeight(event.severity) +
      (iocHits.length > 0 ? 15 : 0) +
      (asset?.criticality === "critical" ? 12 : asset?.criticality === "high" ? 8 : 0) +
      (reasons.length * 3),
  );

  if (reasons.length === 0) {
    reasons.push(`Matched Sigma-like logic for ${rule.ruleName}`);
  }

  return {
    matched: true,
    confidence,
    reasons,
    mitreTechnique: mitre?.technique || rule.attackTechnique || null,
    mitreTactic: mitre?.tactic || rule.attackTactic || null,
  };
}

function buildIocHits(event: NormalizedEvent, iocs: any[]) {
  const candidates = [
    event.sourceIp,
    event.destinationIp,
    event.username,
    event.hostname,
    ...(event.rawLog ? extractIps(event.rawLog) : []),
  ].filter(Boolean);

  return iocs.filter((ioc) => candidates.includes(ioc.iocValue));
}

function buildCveCandidates(asset: any, cves: any[]) {
  const services = Array.isArray(asset?.services) ? asset.services : [];
  if (!services.length) return [];
  const flattened = JSON.stringify(services).toLowerCase();
  return cves.filter((cve) => {
    const affected = Array.isArray(cve.affectedProducts) ? cve.affectedProducts : [];
    return affected.some((product: string) => flattened.includes(String(product).toLowerCase()));
  }).slice(0, 5);
}

export async function ingestAndDetect(input: {
  sourceType: IngestSourceType;
  payload: unknown;
  assetId?: number;
  userId?: number;
}) {
  const normalized = normalizeEvent(input.sourceType, input.payload);
  const asset = input.assetId
    ? await db.getAssetById(input.assetId)
    : await db.findAssetByHostnameOrIp(normalized.hostname, normalized.sourceIp || normalized.destinationIp);
  const iocs = await db.getIOCs(500, 0);
  const recentEvents = await db.getRecentSecurityEvents(300);
  const activeRules = await db.getIdsRules(true);
  const cves = await db.getAllCVEs(500);
  const iocHits = buildIocHits(normalized, iocs);
  const geoSource = lookupGeo(normalized.sourceIp);
  const geoDestination = lookupGeo(normalized.destinationIp);
  const cveCandidates = buildCveCandidates(asset, cves);
  const mitre = MITRE_LOOKUP[normalized.eventType];

  const enrichment = {
    geo: {
      source: geoSource,
      destination: geoDestination,
    },
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
    iocHits: iocHits.map((ioc) => ({ value: ioc.iocValue, type: ioc.iocType, threatLevel: ioc.threatLevel, confidence: ioc.confidence })),
    cveCandidates: cveCandidates.map((cve) => ({ cveId: cve.cveId, severity: cve.severity, title: cve.title })),
    mitre: mitre ?? null,
  };

  const insertResult = await db.createSecurityEvent({
    eventId: nanoid(),
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
    timestamp: new Date(),
    createdAt: new Date(),
  });

  const eventPk = Number((insertResult as any)?.insertId || 0);
  const detections: any[] = [];
  const alerts: any[] = [];
  const incidentIds: number[] = [];

  for (const rule of activeRules) {
    const match = await evaluateRuleMatch({ rule, event: normalized, recentEvents, iocHits, asset });
    if (!match) continue;

    let incidentNumericId: number | undefined;
    if (match.confidence >= 85 || rule.severity === "critical") {
      const createdIncident = await db.createIncident({
        incidentId: nanoid(),
        title: `Detection: ${rule.ruleName}`,
        description: `Auto-created from ingestion pipeline for ${normalized.eventType}`,
        severity: rule.severity,
        status: "open",
        classification: normalized.eventCategory,
        createdBy: input.userId,
        detectedAt: new Date(),
        affectedAssets: asset ? [asset.hostname] : undefined,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      incidentNumericId = Number((createdIncident as any)?.insertId || 0) || undefined;
      if (incidentNumericId) {
        incidentIds.push(incidentNumericId);
        await db.addIncidentAuditTrail({
          incidentId: incidentNumericId,
          action: "Auto-created from detection pipeline",
          performedBy: input.userId,
          details: { rule: rule.ruleName, eventType: normalized.eventType },
          timestamp: new Date(),
        });
      }
    }

    const alertInsert = await db.createAlert({
      alertId: nanoid(),
      title: `${rule.ruleName} matched on ${normalized.hostname || normalized.sourceIp || normalized.eventType}`,
      description: match.reasons.join("; "),
      severity: rule.severity,
      ruleId: rule.ruleId,
      ruleName: rule.ruleName,
      sourceEvents: eventPk ? [eventPk] : [],
      status: incidentNumericId ? "triaged" : "new",
      incidentId: incidentNumericId,
      metadata: {
        confidence: match.confidence,
        reasons: match.reasons,
        mitreTechnique: match.mitreTechnique,
        mitreTactic: match.mitreTactic,
        enrichment,
      },
      timestamp: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const alertPk = Number((alertInsert as any)?.insertId || 0);

    await db.createIdsDetection({
      detectionId: nanoid(),
      ruleId: rule.id,
      eventId: eventPk || undefined,
      sourceIp: normalized.sourceIp,
      destinationIp: normalized.destinationIp,
      incidentId: incidentNumericId,
      confidence: match.confidence,
      matchReasons: match.reasons,
      mitreTechnique: match.mitreTechnique || undefined,
      mitreTactic: match.mitreTactic || undefined,
      timestamp: new Date(),
      createdAt: new Date(),
    });

    detections.push({
      ruleName: rule.ruleName,
      confidence: match.confidence,
      reasons: match.reasons,
      incidentId: incidentNumericId,
      mitreTechnique: match.mitreTechnique,
      mitreTactic: match.mitreTactic,
    });
    alerts.push({ id: alertPk, title: rule.ruleName, severity: rule.severity, incidentId: incidentNumericId });
  }

  return {
    normalized,
    enrichment,
    eventId: eventPk,
    alerts,
    detections,
    incidentIds,
  };
}
