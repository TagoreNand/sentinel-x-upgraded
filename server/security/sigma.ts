/**
 * Sigma → Sentinel-X rule translator.
 *
 * Sigma (https://sigmahq.io) is the de-facto portable detection format. This
 * module converts Sigma YAML into the `detectionLogic` shape the ingestion
 * pipeline already executes (ruleLogicSchema), so analysts can import
 * community rulesets instead of hand-authoring every detection.
 *
 * DESIGN STANCE — faithful subset, fail closed. Sigma's full grammar
 * (arbitrary boolean conditions, nested selections, `1 of`/`all of`, many
 * field modifiers, aggregations) does not map onto our flat rule model. Rather
 * than silently emit a rule that means something DIFFERENT from the Sigma
 * source — the worst outcome for a detection tool — anything outside the
 * supported subset is REJECTED with a specific reason the caller can surface.
 * A rule that imports means it means what it said.
 *
 * Supported:
 * - A single selection referenced by the condition (`condition: selection`),
 *   optionally with a count aggregation (`| count() by <field> > N`).
 * - Selection as a field map (AND across fields, OR within a field's list) or
 *   as a scalar list (keywords / OR).
 * - Field modifiers: |contains, |startswith, |endswith (substring approx),
 *   |all, |re (regex). Unmodified known fields map to structured slots.
 * - level → severity, attack.* tags → technique/tactic, logsource → category.
 *
 * Rejected (with reason): boolean conditions (and/or/not), `1 of`/`all of`,
 * list-of-maps selections, multiple OR keyword groups (unrepresentable),
 * unsupported modifiers (cidr/base64/numeric comparisons), and anything that
 * would exceed ruleLogicSchema's bounds.
 */
import { parseAllDocuments } from "yaml";
import { ruleLogicSchema, type RuleLogic } from "./pipeline";

export type Severity = "critical" | "high" | "medium" | "low";

export type SigmaRuleSpec = {
  ruleName: string;
  description?: string;
  severity: Severity;
  detectionLogic: RuleLogic;
  attackTechnique?: string;
  attackTactic?: string;
  thresholdCount?: number;
  thresholdWindowMinutes?: number;
  dataSource: string;
  ruleType: string;
};

export type SigmaTranslation =
  | { imported: true; title: string; rule: SigmaRuleSpec; warnings: string[] }
  | { imported: false; title: string; reason: string };

// ---- mapping tables --------------------------------------------------------

const LEVEL_TO_SEVERITY: Record<string, Severity> = {
  informational: "low",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

type StructuredSlot = "eventTypes" | "categories" | "protocols" | "usernames" | "destinationPorts" | "sourcePorts";

// Lowercased Sigma field name → structured RuleLogic slot. Only exact-match
// (unmodified) fields use these; a modified field (e.g. User|contains) takes
// the keyword path instead, since our structured slots are equality matches.
const STRUCTURED_FIELDS: Record<string, StructuredSlot> = {
  eventtype: "eventTypes",
  event_type: "eventTypes",
  category: "categories",
  eventcategory: "categories",
  protocol: "protocols",
  user: "usernames",
  username: "usernames",
  targetusername: "usernames",
  subjectusername: "usernames",
  accountname: "usernames",
  samaccountname: "usernames",
  destinationport: "destinationPorts",
  dstport: "destinationPorts",
  dst_port: "destinationPorts",
  dport: "destinationPorts",
  sourceport: "sourcePorts",
  srcport: "sourcePorts",
  src_port: "sourcePorts",
  sport: "sourcePorts",
};

const PORT_SLOTS = new Set<StructuredSlot>(["destinationPorts", "sourcePorts"]);

const SUPPORTED_MODIFIERS = new Set(["contains", "startswith", "endswith", "all", "re"]);

const THRESHOLD_FIELD_MAP: Record<string, "sourceIp" | "username"> = {
  sourceip: "sourceIp",
  src_ip: "sourceIp",
  srcip: "sourceIp",
  source_ip: "sourceIp",
  user: "username",
  username: "username",
  targetusername: "username",
  accountname: "username",
};

const ATTACK_TACTICS = new Set([
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
  "reconnaissance",
  "resource_development",
]);

// ---- helpers ---------------------------------------------------------------

function titleCase(slug: string): string {
  return slug
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function mapTags(tags: unknown): { attackTechnique?: string; attackTactic?: string } {
  if (!Array.isArray(tags)) return {};
  let attackTechnique: string | undefined;
  let attackTactic: string | undefined;
  for (const raw of tags) {
    const tag = String(raw).toLowerCase();
    const techMatch = tag.match(/^attack\.(t\d{4}(?:\.\d{3})?)$/);
    if (techMatch && !attackTechnique) {
      attackTechnique = techMatch[1].toUpperCase();
      continue;
    }
    const tacticSlug = tag.replace(/^attack\./, "");
    if (!attackTactic && ATTACK_TACTICS.has(tacticSlug)) {
      attackTactic = titleCase(tacticSlug);
    }
  }
  return { attackTechnique, attackTactic };
}

/** Split "Field|mod1|mod2" into a lowercased base and its modifiers. */
function splitField(key: string): { base: string; modifiers: string[] } {
  const parts = key.split("|");
  return { base: parts[0].toLowerCase(), modifiers: parts.slice(1).map((m) => m.toLowerCase()) };
}

function toStringValues(value: unknown): string[] {
  const arr = Array.isArray(value) ? value : [value];
  return arr.map((v) => String(v));
}

type ConditionPlan = {
  selectionName: string;
  thresholdCount?: number;
  thresholdField?: "sourceIp" | "username";
};

/**
 * Parse a Sigma `condition`. Accepts a single selection name, optionally with
 * a `count()` aggregation. Everything else (boolean logic, `1 of`, `all of`,
 * other aggregation functions) is rejected — we cannot represent it faithfully.
 */
function parseCondition(condition: string, selectionNames: string[]): ConditionPlan | { error: string } {
  const [rawLeft, ...aggParts] = condition.split("|");
  const left = rawLeft.trim();

  if (/\b(and|or|not)\b/i.test(left) || /[()]/.test(left)) {
    return { error: "Boolean conditions (and/or/not) are not supported" };
  }
  if (/\b(1|all)\s+of\b/i.test(left)) {
    return { error: "`1 of`/`all of` conditions are not supported" };
  }
  if (!selectionNames.includes(left)) {
    return { error: `condition references unknown selection '${left}'` };
  }

  if (aggParts.length === 0) {
    return { selectionName: left };
  }

  const agg = aggParts.join("|").trim();
  const match = agg.match(/^count\(\s*\)\s*(?:by\s+([A-Za-z0-9_]+)\s*)?(>=|>)\s*(\d+)$/i);
  if (!match) {
    return { error: `unsupported aggregation '${agg}' (only count() thresholds are supported)` };
  }
  const [, byField, op, nStr] = match;
  const n = Number(nStr);
  // `> N` fires on the (N+1)th event; `>= N` on the Nth. Our threshold is
  // "matchCount >= thresholdCount".
  const thresholdCount = op === ">" ? n + 1 : n;

  let thresholdField: "sourceIp" | "username" | undefined;
  if (byField) {
    const mapped = THRESHOLD_FIELD_MAP[byField.toLowerCase()];
    if (!mapped) {
      return { error: `count() by '${byField}' is not a supported grouping field` };
    }
    thresholdField = mapped;
  }
  return { selectionName: left, thresholdCount, thresholdField };
}

type LogicBuilder = {
  logic: RuleLogic;
  warnings: string[];
  anyKeywordsOwner?: string;
};

/** Fold one Sigma selection field into the RuleLogic under construction. */
function applyField(builder: LogicBuilder, key: string, value: unknown): string | null {
  const { base, modifiers } = splitField(key);
  const logic = builder.logic;

  const unsupported = modifiers.find((m) => !SUPPORTED_MODIFIERS.has(m));
  if (unsupported) {
    return `field modifier '|${unsupported}' on '${base}' is not supported`;
  }

  // Sigma `Field: null` is an ABSENCE test (the field is null/unset) — the
  // opposite of a positive match. Coercing it to the literal keyword "null"
  // would both false-match (JSON of most events contains "null") and
  // miss-match (a genuinely-absent field yields no "null" substring). We
  // cannot express absence in this model, so fail closed.
  const rawValues = Array.isArray(value) ? value : [value];
  if (rawValues.some((v) => v === null || v === undefined)) {
    return `null match on '${base}' is not supported (Sigma null tests field-absence, which this model cannot express)`;
  }

  if (modifiers.includes("re")) {
    if (Array.isArray(value)) return `regex field '${base}' must be a single pattern`;
    if (logic.rawRegex) return "only one regex condition is supported per rule";
    logic.rawRegex = String(value);
    // The pipeline compiles rule regex case-INSENSITIVELY and tests it against
    // the whole log line, not the named field — so anchors (^...$) and case
    // sensitivity from the Sigma source do not carry over. Flag it rather than
    // pretend the translation is exact.
    builder.warnings.push(`regex on '${base}' is applied case-insensitively to the whole log line, not scoped to the field`);
    return null;
  }

  const values = toStringValues(value);

  // Unmodified known field → structured equality slot.
  if (modifiers.length === 0 && STRUCTURED_FIELDS[base]) {
    const slot = STRUCTURED_FIELDS[base];
    const existing = (logic[slot] as unknown[]) ?? [];
    // Two DISTINCT Sigma fields mapping to the same slot would OR-merge, but
    // Sigma means AND across distinct fields — unrepresentable here. Fail
    // closed, consistent with the multiple-OR-keyword-groups rejection (a mere
    // warning here would silently broaden the rule into false positives).
    if (existing.length > 0) {
      return `field '${base}' maps to ${slot}, already used by another field; Sigma AND across distinct fields is not representable`;
    }
    if (PORT_SLOTS.has(slot)) {
      (logic[slot] as number[]) = values.map((v) => Number(v)).filter((n) => Number.isInteger(n));
    } else {
      (logic[slot] as string[]) = [...values];
    }
    return null;
  }

  // Keyword path (contains/startswith/endswith/all/unknown field).
  if (modifiers.includes("startswith") || modifiers.includes("endswith")) {
    builder.warnings.push(`'|${modifiers.join("|")}' on '${base}' approximated as substring match`);
  }

  // `|all`, or a single scalar, is an AND contribution.
  if (modifiers.includes("all") || values.length === 1) {
    logic.allKeywords = [...(logic.allKeywords ?? []), ...values];
    return null;
  }

  // A list value is OR within the field. RuleLogic has exactly one OR bucket
  // (anyKeywords), so a second OR group cannot be represented faithfully.
  if (builder.anyKeywordsOwner && builder.anyKeywordsOwner !== base) {
    return "multiple OR keyword groups are not representable in a single rule";
  }
  builder.anyKeywordsOwner = base;
  logic.anyKeywords = [...(logic.anyKeywords ?? []), ...values];
  return null;
}

function translateOne(doc: Record<string, unknown>): SigmaTranslation {
  const title = typeof doc.title === "string" && doc.title.length > 0 ? doc.title : "Untitled Sigma rule";

  const detection = doc.detection;
  if (!detection || typeof detection !== "object") {
    return { imported: false, title, reason: "missing detection block" };
  }
  const detectionObj = detection as Record<string, unknown>;

  const condition = detectionObj.condition;
  if (typeof condition !== "string") {
    return { imported: false, title, reason: "missing or non-string condition" };
  }

  const selectionNames = Object.keys(detectionObj).filter((k) => k !== "condition");
  const plan = parseCondition(condition, selectionNames);
  if ("error" in plan) {
    return { imported: false, title, reason: plan.error };
  }

  const selection = detectionObj[plan.selectionName];
  const builder: LogicBuilder = { logic: {}, warnings: [] };

  if (Array.isArray(selection)) {
    // A scalar list is the Sigma "keywords" pattern → OR.
    if (selection.some((v) => v !== null && typeof v === "object")) {
      return { imported: false, title, reason: "list-of-maps selections are not supported" };
    }
    if (selection.some((v) => v === null || v === undefined)) {
      return { imported: false, title, reason: "null entries in a keyword list are not supported" };
    }
    builder.logic.anyKeywords = selection.map((v) => String(v));
    builder.anyKeywordsOwner = "__keywords__";
  } else if (selection && typeof selection === "object") {
    for (const [key, value] of Object.entries(selection as Record<string, unknown>)) {
      const error = applyField(builder, key, value);
      if (error) return { imported: false, title, reason: error };
    }
  } else {
    return { imported: false, title, reason: `selection '${plan.selectionName}' is empty or malformed` };
  }

  // Enforce the pipeline's own bounds — a rule that imports must be one the
  // pipeline will actually accept and run.
  const validated = ruleLogicSchema.safeParse(builder.logic);
  if (!validated.success) {
    return { imported: false, title, reason: `translated logic exceeds rule limits: ${validated.error.issues[0]?.message ?? "invalid"}` };
  }
  const logic = validated.data;

  const constrains =
    Object.values(logic).some((v) => (Array.isArray(v) ? v.length > 0 : v !== undefined)) || plan.thresholdCount !== undefined;
  if (!constrains) {
    return { imported: false, title, reason: "no translatable detection conditions" };
  }

  if (plan.thresholdCount !== undefined) {
    const field = plan.thresholdField ?? "sourceIp";
    logic.threshold = { count: plan.thresholdCount, windowMinutes: 5, field };
    // Faithfulness caveat: the pipeline's threshold counts ALL events from the
    // entity in the window, not only those matching this selection. For the
    // common `count() by ip` brute-force idiom that can over-count. Surface it
    // rather than imply exact Sigma count() semantics.
    builder.warnings.push(`count() approximated: counts all events from the ${field} in the window, not only selection-matching events`);
  }

  const level = typeof doc.level === "string" ? doc.level.toLowerCase() : "medium";
  const severity = LEVEL_TO_SEVERITY[level] ?? "medium";
  const { attackTechnique, attackTactic } = mapTags(doc.tags);

  const logsource = doc.logsource as Record<string, unknown> | undefined;
  // logsource.category is advisory provenance, not a hard match condition —
  // recorded in the description rather than forced into the match logic, where
  // it could suppress a rule whose events are categorized differently by our
  // normalizer.
  const category = logsource && typeof logsource.category === "string" ? logsource.category : undefined;

  const descriptionParts: string[] = [];
  if (typeof doc.description === "string") descriptionParts.push(doc.description);
  descriptionParts.push(`[Imported from Sigma${typeof doc.id === "string" ? ` id=${doc.id}` : ""}${category ? `, logsource.category=${category}` : ""}]`);

  return {
    imported: true,
    title,
    warnings: builder.warnings,
    rule: {
      ruleName: title,
      description: descriptionParts.join(" "),
      severity,
      detectionLogic: logic,
      attackTechnique,
      attackTactic,
      thresholdCount: plan.thresholdCount,
      thresholdWindowMinutes: plan.thresholdCount !== undefined ? 5 : undefined,
      dataSource: "sigma",
      ruleType: "sigma",
    },
  };
}

/**
 * Translate a Sigma YAML document (or multi-document stream) into rule specs.
 * Never throws: a malformed document becomes a skip with a reason so one bad
 * rule in a bundle does not fail the whole import.
 */
export function translateSigmaRules(yamlText: string): SigmaTranslation[] {
  let documents: ReturnType<typeof parseAllDocuments>;
  try {
    documents = parseAllDocuments(yamlText);
  } catch (error) {
    return [{ imported: false, title: "unparseable input", reason: `YAML parse error: ${error instanceof Error ? error.message : "invalid"}` }];
  }

  const results: SigmaTranslation[] = [];
  for (const document of documents) {
    if (document.errors.length > 0) {
      results.push({ imported: false, title: "malformed document", reason: `YAML error: ${document.errors[0].message}` });
      continue;
    }
    // toJS() resolves anchors/aliases and can THROW (e.g. yaml's excessive-
    // alias guard against alias-bomb resource exhaustion). Keep it inside the
    // per-document guard so one hostile document becomes a skip, honoring the
    // "never throws" contract instead of failing the whole import.
    let obj: unknown;
    try {
      obj = document.toJS();
    } catch (error) {
      results.push({ imported: false, title: "unresolvable document", reason: `YAML composition error: ${error instanceof Error ? error.message : "invalid"}` });
      continue;
    }
    if (obj === null || obj === undefined) continue; // empty doc between `---` separators
    if (typeof obj !== "object" || Array.isArray(obj)) {
      results.push({ imported: false, title: "invalid document", reason: "document is not a Sigma rule object" });
      continue;
    }
    try {
      results.push(translateOne(obj as Record<string, unknown>));
    } catch (error) {
      const title = typeof (obj as Record<string, unknown>).title === "string" ? String((obj as Record<string, unknown>).title) : "Sigma rule";
      results.push({ imported: false, title, reason: `translation error: ${error instanceof Error ? error.message : "unknown"}` });
    }
  }
  return results;
}
