import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nanoid } from "nanoid";
import { integrationDbAvailable, setupIntegrationDb, type IntegrationDb } from "../../test/integration/harness";
import * as db from "../db";
import { ingestAndDetect } from "./pipeline";

/**
 * End-to-end detection pipeline against real MySQL. This is where the
 * transactional writes, $returningId linkage, and — critically — the
 * incident correlation dedup are exercised for real. The dedup test is the
 * one that would have caught the CLIENT_FOUND_ROWS misclassification a review
 * found by hand: affectedRows cannot distinguish created-vs-correlated, so
 * the code compares the persisted incidentId nanoid instead, and this asserts
 * exactly one "Auto-created" audit row survives a correlated burst.
 */
describe.skipIf(!integrationDbAvailable())("ingestion pipeline (integration)", () => {
  let ctx: IntegrationDb;

  beforeAll(async () => {
    ctx = await setupIntegrationDb();
  });

  afterAll(async () => {
    await ctx?.teardown();
  });

  it("dedups a correlated burst into one incident with exactly one creation audit row", async () => {
    await db.createIdsRule({
      ruleId: nanoid(),
      ruleName: "SSH brute force",
      pattern: "failed password",
      severity: "critical", // critical => always opens an incident on match
      confidenceWeight: 90,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const payload = "Apr 10 12:00:01 web-01 sshd[101]: Failed password for admin from 91.240.118.12 port 22 ssh2";
    const first = await ingestAndDetect({ sourceType: "syslog", payload });
    const second = await ingestAndDetect({ sourceType: "syslog", payload });

    // Both events land on the SAME incident (same rule x sourceIp x bucket).
    expect(first.incidentIds[0]).toBeGreaterThan(0);
    expect(second.incidentIds[0]).toBe(first.incidentIds[0]);

    // $returningId linkage: the alert carries a real PK and links the event.
    expect(first.alerts[0]?.id).toBeGreaterThan(0);

    const conn = await ctx.connect();
    try {
      const [auditRows] = await conn.query(
        "SELECT COUNT(*) AS c FROM incident_audit_trail WHERE incidentId = ? AND action LIKE 'Auto-created%'",
        [first.incidentIds[0]],
      );
      // Exactly one creation entry — the correlated second event must NOT log
      // a duplicate "Auto-created" row (the CLIENT_FOUND_ROWS defect).
      expect((auditRows as Array<{ c: number }>)[0].c).toBe(1);

      const [incidentRows] = await conn.query("SELECT COUNT(*) AS c FROM incidents WHERE correlationKey IS NOT NULL");
      expect((incidentRows as Array<{ c: number }>)[0].c).toBe(1);
    } finally {
      await conn.end();
    }
  });

  it("fires a threshold rule only once the count is reached", async () => {
    await db.createIdsRule({
      ruleId: nanoid(),
      ruleName: "Repeated auth failure",
      detectionLogic: {
        eventTypes: ["authentication_failed"],
        threshold: { count: 3, windowMinutes: 5, field: "sourceIp" },
      },
      severity: "high",
      confidenceWeight: 40,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const from = (n: number) => `Failed password for admin from 10.20.30.${n} port 22 ssh2`;
    // Three events from a DISTINCT source IP not used elsewhere in this suite.
    const r1 = await ingestAndDetect({ sourceType: "syslog", payload: from(40) });
    const r2 = await ingestAndDetect({ sourceType: "syslog", payload: from(40) });
    const r3 = await ingestAndDetect({ sourceType: "syslog", payload: from(40) });

    const named = (r: typeof r1) => r.detections.some((d) => d.ruleName === "Repeated auth failure");
    // Below threshold: no detection from this rule.
    expect(named(r1)).toBe(false);
    expect(named(r2)).toBe(false);
    // At the threshold (3rd event, counted against committed rows): it fires.
    expect(named(r3)).toBe(true);
  });
});
