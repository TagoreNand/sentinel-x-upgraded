import { describe, expect, it } from "vitest";
import {
  buildCorrelationKey,
  collectIocCandidates,
  compileSafeRegex,
  correlationEntityFor,
  isDuplicateEntryError,
  isRetryableTxError,
  normalizeEvent,
  parseRuleLogic,
  parseSeverity,
} from "./pipeline";
import { TokenBucketLimiter } from "../_core/rateLimit";
import { envNumber } from "../_core/env";

describe("parseSeverity", () => {
  it("accepts only known severities", () => {
    expect(parseSeverity("critical")).toBe("critical");
    expect(parseSeverity("low")).toBe("low");
    expect(parseSeverity("CRITICAL")).toBeUndefined();
    expect(parseSeverity("drop table")).toBeUndefined();
    expect(parseSeverity(42)).toBeUndefined();
    expect(parseSeverity(undefined)).toBeUndefined();
  });

  it("falls back to inferred severity when payload severity is garbage", () => {
    const event = normalizeEvent("json", {
      message: "Failed password for admin",
      severity: "catastrophic-doom", // not a valid enum member
    });
    expect(event.severity).toBe("medium"); // inferred from "failed"
  });
});

describe("parseRuleLogic", () => {
  it("parses valid structured detection logic", () => {
    const logic = parseRuleLogic({
      detectionLogic: {
        eventTypes: ["authentication_failed"],
        threshold: { count: 5, windowMinutes: 5, field: "sourceIp" },
      },
      pattern: null,
    });
    expect(logic).not.toBeNull();
    expect(logic?.eventTypes).toEqual(["authentication_failed"]);
    expect(logic?.threshold?.count).toBe(5);
  });

  it("fails closed on invalid detection logic", () => {
    const logic = parseRuleLogic({
      detectionLogic: { eventTypes: "not-an-array", threshold: { count: "many" } },
      pattern: null,
    });
    expect(logic).toBeNull();
  });

  it("rejects vacuous logic that would match every event", () => {
    expect(parseRuleLogic({ detectionLogic: {}, pattern: null })).toBeNull();
    expect(parseRuleLogic({ detectionLogic: null, pattern: "" })).toBeNull();
    expect(parseRuleLogic({ detectionLogic: null, pattern: "  ,  , " })).toBeNull();
  });

  it("falls back to comma-separated pattern keywords", () => {
    const logic = parseRuleLogic({ detectionLogic: null, pattern: "nmap, masscan" });
    expect(logic?.anyKeywords).toEqual(["nmap", "masscan"]);
  });

  it("accepts threshold-only rules as constraining", () => {
    const logic = parseRuleLogic({
      detectionLogic: { threshold: { count: 10, windowMinutes: 5 } },
      pattern: null,
    });
    expect(logic).not.toBeNull();
  });
});

describe("compileSafeRegex", () => {
  it("compiles reasonable patterns", () => {
    const regex = compileSafeRegex("failed password for \\w+");
    expect(regex).toBeInstanceOf(RegExp);
    expect(regex?.test("Failed password for admin")).toBe(true);
  });

  it("rejects catastrophic-backtracking constructs", () => {
    expect(compileSafeRegex("(a+)+$")).toBeNull();
    expect(compileSafeRegex("(x*)*y")).toBeNull();
    expect(compileSafeRegex("(?:\\d+){2,}z")).toBeNull();
  });

  it("rejects quantified backreferences", () => {
    expect(compileSafeRegex("(a)\\1+")).toBeNull();
  });

  it("rejects oversized and syntactically invalid patterns", () => {
    expect(compileSafeRegex("a".repeat(500))).toBeNull();
    expect(compileSafeRegex("([unclosed")).toBeNull();
  });
});

describe("buildCorrelationKey", () => {
  const now = new Date("2026-07-10T12:03:00Z");

  it("is deterministic for the same rule, entity, and time bucket", () => {
    const a = buildCorrelationKey({ ruleId: "r1", entity: "91.240.118.12", bucketMinutes: 15, now });
    const b = buildCorrelationKey({ ruleId: "r1", entity: "91.240.118.12", bucketMinutes: 15, now: new Date("2026-07-10T12:11:00Z") });
    expect(a).toBe(b); // same 15-minute bucket
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("differs across rules, entities, and buckets", () => {
    const base = buildCorrelationKey({ ruleId: "r1", entity: "e1", bucketMinutes: 15, now });
    expect(buildCorrelationKey({ ruleId: "r2", entity: "e1", bucketMinutes: 15, now })).not.toBe(base);
    expect(buildCorrelationKey({ ruleId: "r1", entity: "e2", bucketMinutes: 15, now })).not.toBe(base);
    expect(
      buildCorrelationKey({ ruleId: "r1", entity: "e1", bucketMinutes: 15, now: new Date("2026-07-10T12:31:00Z") }),
    ).not.toBe(base);
  });

  it("picks the most specific entity available", () => {
    const event = normalizeEvent(
      "syslog",
      "Apr 10 12:00:01 web-01 sshd[101]: Failed password for invalid user admin from 91.240.118.12 port 49222 ssh2",
    );
    expect(correlationEntityFor(event)).toBe("91.240.118.12");
  });
});

describe("collectIocCandidates", () => {
  it("collects unique observables including IPs embedded in the raw log", () => {
    const event = normalizeEvent(
      "syslog",
      "Apr 10 12:00:01 web-01 sshd[101]: Failed password for invalid user admin from 91.240.118.12 port 49222 ssh2",
    );
    const candidates = collectIocCandidates(event);
    expect(candidates).toContain("91.240.118.12");
    expect(candidates).toContain("web-01");
    // No duplicates even though the IP appears as sourceIp AND in rawLog.
    expect(new Set(candidates).size).toBe(candidates.length);
  });
});

describe("isRetryableTxError", () => {
  it("recognizes deadlock and lock-wait-timeout errnos", () => {
    expect(isRetryableTxError({ errno: 1213 })).toBe(true);
    expect(isRetryableTxError({ errno: 1205 })).toBe(true);
  });

  it("walks the drizzle cause chain to find the driver errno", () => {
    expect(isRetryableTxError({ message: "query failed", cause: { errno: 1213 } })).toBe(true);
  });

  it("does not retry non-transient errors", () => {
    expect(isRetryableTxError({ errno: 1062 })).toBe(false); // duplicate key: handled by upsert, never retried blindly
    expect(isRetryableTxError(new Error("boom"))).toBe(false);
    expect(isRetryableTxError(null)).toBe(false);
    expect(isRetryableTxError(undefined)).toBe(false);
  });
});

describe("isDuplicateEntryError", () => {
  it("recognizes ER_DUP_ENTRY directly and through the drizzle cause chain", () => {
    expect(isDuplicateEntryError({ errno: 1062 })).toBe(true);
    expect(isDuplicateEntryError({ message: "query failed", cause: { errno: 1062 } })).toBe(true);
  });

  it("does not classify other errors as replays", () => {
    expect(isDuplicateEntryError({ errno: 1213 })).toBe(false);
    expect(isDuplicateEntryError(new Error("boom"))).toBe(false);
    expect(isDuplicateEntryError(null)).toBe(false);
  });
});

describe("TokenBucketLimiter", () => {
  it("allows a burst up to capacity, then throttles", () => {
    const limiter = new TokenBucketLimiter({ capacity: 3, refillPerSecond: 1 });
    const t0 = 1_000_000;
    expect(limiter.tryConsume("k", t0)).toBe(true);
    expect(limiter.tryConsume("k", t0)).toBe(true);
    expect(limiter.tryConsume("k", t0)).toBe(true);
    expect(limiter.tryConsume("k", t0)).toBe(false);
  });

  it("refills over time and isolates keys", () => {
    const limiter = new TokenBucketLimiter({ capacity: 2, refillPerSecond: 1 });
    const t0 = 1_000_000;
    expect(limiter.tryConsume("a", t0)).toBe(true);
    expect(limiter.tryConsume("a", t0)).toBe(true);
    expect(limiter.tryConsume("a", t0)).toBe(false);
    expect(limiter.tryConsume("b", t0)).toBe(true); // different key unaffected
    expect(limiter.tryConsume("a", t0 + 1_000)).toBe(true); // 1s → 1 token back
  });

  it("sweeps idle buckets to bound memory", () => {
    const limiter = new TokenBucketLimiter({ capacity: 1, refillPerSecond: 1 });
    const t0 = 1_000_000;
    limiter.tryConsume("stale", t0);
    limiter.tryConsume("fresh", t0 + 11 * 60_000);
    limiter.sweep(t0 + 11 * 60_000);
    expect(limiter.size).toBe(1);
  });

  it("rejects NaN/non-finite config instead of failing open", () => {
    // NaN passes `< 1` and `<= 0` guards (both false), and a NaN bucket
    // never blocks — so without Number.isFinite the limiter silently
    // disables itself on a config typo.
    expect(() => new TokenBucketLimiter({ capacity: NaN, refillPerSecond: 5 })).toThrow();
    expect(() => new TokenBucketLimiter({ capacity: 20, refillPerSecond: NaN })).toThrow();
    expect(() => new TokenBucketLimiter({ capacity: Infinity, refillPerSecond: 5 })).toThrow();
  });
});

describe("envNumber", () => {
  it("parses valid values and falls back on garbage, negatives, and absence", () => {
    process.env.TEST_ENV_NUMBER = "42";
    expect(envNumber("TEST_ENV_NUMBER", 7)).toBe(42);
    process.env.TEST_ENV_NUMBER = "not-a-number";
    expect(envNumber("TEST_ENV_NUMBER", 7)).toBe(7);
    process.env.TEST_ENV_NUMBER = "-5";
    expect(envNumber("TEST_ENV_NUMBER", 7)).toBe(7);
    delete process.env.TEST_ENV_NUMBER;
    expect(envNumber("TEST_ENV_NUMBER", 7)).toBe(7);
  });
});
