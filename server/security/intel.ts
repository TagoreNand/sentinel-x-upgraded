/**
 * External threat-intel feed ingestion — TAXII 2.x, STIX bundles, and MISP.
 *
 * Pulls indicators from external feeds into indicators_of_compromise so the
 * ingestion pipeline's IOC enrichment picks them up automatically. Same stance
 * as the Sigma importer: a documented, FAIL-CLOSED subset. An indicator whose
 * STIX pattern or MISP type we cannot map faithfully is SKIPPED and counted,
 * never coerced into a wrong IOC (a false indicator is worse than a missing
 * one — it poisons every future detection).
 *
 * Parsers are pure and heavily unit-tested; the HTTP fetch is injected so the
 * poller is integration-tested against a local sink without a live feed.
 */
import axios from "axios";
import { nanoid } from "nanoid";
import type { InsertIndicatorOfCompromise, IntelFeed } from "../../drizzle/schema";
import * as db from "../db";
import { envNumber } from "../_core/env";
import { logger } from "../_core/logger";

const log = logger.child({ component: "intel-feeds" });

export type IocType = "ip" | "domain" | "url" | "hash" | "email" | "file" | "process" | "registry";

export type ParsedIoc = { iocType: IocType; iocValue: string; confidence?: number };

export type ParseResult = { iocs: ParsedIoc[]; skipped: number };

// ---- STIX parsing ----------------------------------------------------------

/** Map a STIX Cyber-observable object type (+ property) to our IOC type. */
export function mapStixObjectType(objectType: string, property: string): IocType | null {
  switch (objectType.toLowerCase()) {
    case "ipv4-addr":
    case "ipv6-addr":
      return "ip";
    case "domain-name":
      return "domain";
    case "url":
      return "url";
    case "email-addr":
      return "email";
    case "windows-registry-key":
      return "registry";
    case "process":
      return "process";
    case "file":
      if (property.toLowerCase().includes("hashes")) return "hash";
      if (property.toLowerCase() === "name") return "file";
      return null;
    default:
      return null;
  }
}

/**
 * Extract IOC observables from a STIX 2.x pattern. Handles the common
 * comparison form `object-type:property = 'value'`, including AND/OR-joined
 * comparisons (each observable becomes its own IOC). Anything with no parsable
 * comparison yields nothing (the caller counts it as skipped).
 */
export function parseStixPattern(pattern: string, confidence?: number): ParsedIoc[] {
  const out: ParsedIoc[] = [];
  // Only the exact-equality operator is faithfully representable. LIKE/MATCHES
  // are wildcard/regex operators whose value (e.g. '10.0.0.%') is NOT a literal
  // observable; extracting it would store a garbage IOC that can never match on
  // the pipeline's exact IN() lookup, so those comparisons are left unmatched
  // (fail closed). The value group consumes STIX escape sequences (\\ \') so an
  // escaped quote doesn't truncate the value.
  const comparison = /([a-z0-9_-]+):([a-z0-9._'"-]+)\s*=\s*'((?:[^'\\]|\\.)*)'/gi;
  let match: RegExpExecArray | null;
  while ((match = comparison.exec(pattern)) !== null) {
    const [, objectType, property, rawValue] = match;
    const iocType = mapStixObjectType(objectType, property);
    // Decode STIX single-quoted string escapes: \\ -> \, \' -> '.
    const value = rawValue.replace(/\\(['\\])/g, "$1").trim();
    if (iocType && value.length > 0) {
      out.push({ iocType, iocValue: value, confidence });
    }
  }
  return out;
}

/** Pull the object list out of a STIX bundle or a TAXII envelope. */
export function extractStixObjects(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    if (Array.isArray(obj.objects)) return obj.objects; // bundle / TAXII envelope
  }
  return [];
}

export function parseStixObjects(objects: unknown[]): ParseResult {
  const iocs: ParsedIoc[] = [];
  let skipped = 0;
  for (const obj of objects) {
    if (!obj || typeof obj !== "object") {
      skipped += 1;
      continue;
    }
    const record = obj as Record<string, unknown>;
    if (record.type !== "indicator" || typeof record.pattern !== "string") {
      // Non-indicator SDO (identity, relationship, malware, …) — not an error.
      continue;
    }
    const confidence = typeof record.confidence === "number" ? record.confidence : undefined;
    const parsed = parseStixPattern(record.pattern, confidence);
    if (parsed.length === 0) skipped += 1;
    else iocs.push(...parsed);
  }
  return { iocs, skipped };
}

// ---- MISP parsing ----------------------------------------------------------

/** Map a MISP attribute type to our IOC type (composite types unsupported). */
export function mapMispType(mispType: string): IocType | null {
  switch (mispType.toLowerCase()) {
    case "ip-src":
    case "ip-dst":
    case "ip":
      return "ip";
    case "domain":
    case "hostname":
      return "domain";
    case "url":
    case "uri":
    case "link":
      return "url";
    case "md5":
    case "sha1":
    case "sha256":
    case "sha512":
    case "imphash":
    case "ssdeep":
      return "hash";
    case "email":
    case "email-src":
    case "email-dst":
      return "email";
    case "filename":
      return "file";
    case "regkey":
      return "registry";
    default:
      return null; // composite (filename|md5) and other types: fail closed
  }
}

/** Pull the attribute list out of a MISP restSearch response. */
export function extractMispAttributes(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    const response = obj.response;
    if (response && typeof response === "object" && Array.isArray((response as Record<string, unknown>).Attribute)) {
      return (response as Record<string, unknown>).Attribute as unknown[];
    }
    if (Array.isArray(obj.Attribute)) return obj.Attribute;
  }
  return [];
}

export function parseMispAttributes(attributes: unknown[]): ParseResult {
  const iocs: ParsedIoc[] = [];
  let skipped = 0;
  for (const attr of attributes) {
    if (!attr || typeof attr !== "object") {
      skipped += 1;
      continue;
    }
    const record = attr as Record<string, unknown>;
    const iocType = typeof record.type === "string" ? mapMispType(record.type) : null;
    const value = typeof record.value === "string" ? record.value.trim() : "";
    if (!iocType || value.length === 0) {
      skipped += 1;
      continue;
    }
    // MISP to_ids gates whether an attribute is meant for detection; honor it
    // when present.
    if (record.to_ids === false) {
      skipped += 1;
      continue;
    }
    iocs.push({ iocType, iocValue: value });
  }
  return { iocs, skipped };
}

// ---- fetch (injectable) ----------------------------------------------------

export type FeedFetcher = (feed: IntelFeed, timeoutMs: number) => Promise<unknown>;

const MAX_RESPONSE_BYTES = 32 * 1024 * 1024; // bound a hostile/huge feed body

// Hardened defaults shared by every feed request:
// - maxRedirects: 0 — the request carries a credential (Bearer / API key), so
//   following a 302 could ship that token to an attacker-controlled or internal
//   host the admin never configured. Refuse redirects outright.
// - maxContentLength/maxBodyLength — a feed that streams gigabytes must not OOM
//   the process.
const hardenedAxios = { maxRedirects: 0, maxContentLength: MAX_RESPONSE_BYTES, maxBodyLength: MAX_RESPONSE_BYTES } as const;

const defaultFetcher: FeedFetcher = async (feed, timeoutMs) => {
  if (feed.type === "misp") {
    const response = await axios.post(
      feed.url,
      { returnFormat: "json", limit: 5000, enforceWarninglist: true },
      {
        ...hardenedAxios,
        timeout: timeoutMs,
        headers: { Accept: "application/json", "content-type": "application/json", ...(feed.authToken ? { Authorization: feed.authToken } : {}) },
      },
    );
    return response.data;
  }
  // taxii / stix are both GET returning STIX JSON.
  const response = await axios.get(feed.url, {
    ...hardenedAxios,
    timeout: timeoutMs,
    headers: {
      Accept: feed.type === "taxii" ? "application/taxii+json;version=2.1" : "application/json",
      ...(feed.authToken ? { Authorization: `Bearer ${feed.authToken}` } : {}),
    },
  });
  return response.data;
};

// ---- poller ----------------------------------------------------------------

const MAX_IOCS_PER_POLL = 5000;

export type PollResult = { feedId: number; found: number; created: number; skipped: number; error?: string };

export type PollDeps = { fetcher: FeedFetcher; timeoutMs: number };

function defaultDeps(): PollDeps {
  return { fetcher: defaultFetcher, timeoutMs: envNumber("INTEL_FETCH_TIMEOUT_MS", 20_000) };
}

/**
 * Poll one feed: fetch, parse (fail-closed), dedup against existing IOCs, bulk
 * insert the new ones, and record the outcome on the feed row. Never throws —
 * a feed error is captured in lastStatus/lastError so one bad feed cannot
 * break a scheduled sweep.
 */
export async function pollFeed(feed: IntelFeed, deps: PollDeps = defaultDeps()): Promise<PollResult> {
  const flog = log.child({ feedId: feed.id, feedName: feed.name, type: feed.type });
  try {
    const raw = await deps.fetcher(feed, deps.timeoutMs);
    const parsed = feed.type === "misp" ? parseMispAttributes(extractMispAttributes(raw)) : parseStixObjects(extractStixObjects(raw));

    // Dedup within this poll, then against what already exists.
    const byValue = new Map<string, ParsedIoc>();
    for (const ioc of parsed.iocs.slice(0, MAX_IOCS_PER_POLL)) {
      if (!byValue.has(ioc.iocValue)) byValue.set(ioc.iocValue, ioc);
    }
    const existing = await db.findExistingIocValues(Array.from(byValue.keys()));
    const now = new Date();
    const toInsert: InsertIndicatorOfCompromise[] = [];
    for (const ioc of Array.from(byValue.values())) {
      if (existing.has(ioc.iocValue)) continue;
      toInsert.push({
        iocId: nanoid(),
        iocType: ioc.iocType,
        iocValue: ioc.iocValue,
        threatLevel: feed.defaultThreatLevel,
        source: `feed:${feed.name}`,
        confidence: ioc.confidence ?? 50,
        status: "active",
        firstSeen: now,
        lastSeen: now,
        createdAt: now,
        updatedAt: now,
      });
    }
    const created = await db.bulkCreateIOCs(toInsert);

    await db.updateIntelFeed(feed.id, { lastPolledAt: now, lastStatus: "success", lastError: null, lastIocCount: created });
    flog.info("feed polled", { found: parsed.iocs.length, created, skipped: parsed.skipped });
    return { feedId: feed.id, found: parsed.iocs.length, created, skipped: parsed.skipped };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    flog.error("feed poll failed", error);
    await db.updateIntelFeed(feed.id, { lastPolledAt: new Date(), lastStatus: "error", lastError: message.slice(0, 2000) }).catch(() => {});
    return { feedId: feed.id, found: 0, created: 0, skipped: 0, error: message };
  }
}

let sweeping = false;

/** Scheduler entry: poll every enabled feed once. Best-effort. */
export async function pollAllEnabledFeeds(deps: PollDeps = defaultDeps()): Promise<void> {
  // Guard against overlapping ticks: a sweep that runs longer than the poll
  // interval (many slow feeds) must not stack a second concurrent sweep on top
  // — that would double-poll and amplify the check-then-insert dedup window.
  if (sweeping) {
    log.warn("skipping intel sweep: previous sweep still running");
    return;
  }
  sweeping = true;
  try {
    const feeds = await db.getEnabledIntelFeeds();
    for (const feed of feeds) {
      await pollFeed(feed, deps);
    }
  } catch (error) {
    log.error("scheduled feed sweep failed", error);
  } finally {
    sweeping = false;
  }
}

let schedulerTimer: NodeJS.Timeout | null = null;

/**
 * Start the periodic poller. Disabled by default (interval 0) — a deployment
 * opts in via INTEL_POLL_INTERVAL_MINUTES. Manual polling via the router works
 * regardless.
 */
export function initIntelScheduler(): void {
  const minutes = envNumber("INTEL_POLL_INTERVAL_MINUTES", 0);
  if (minutes <= 0) {
    log.info("intel feed scheduler disabled (set INTEL_POLL_INTERVAL_MINUTES to enable)");
    return;
  }
  schedulerTimer = setInterval(() => void pollAllEnabledFeeds(), minutes * 60_000);
  schedulerTimer.unref();
  log.info("intel feed scheduler started", { intervalMinutes: minutes });
}

export function stopIntelScheduler(): void {
  if (schedulerTimer) {
    clearInterval(schedulerTimer);
    schedulerTimer = null;
  }
}
