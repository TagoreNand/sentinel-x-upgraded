import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nanoid } from "nanoid";
import { integrationDbAvailable, setupIntegrationDb, type IntegrationDb } from "../../test/integration/harness";
import * as db from "../db";
import { ingestAndDetect } from "./pipeline";
import { translateSigmaRules } from "./sigma";

/**
 * Proves the Sigma import path is not just a translator but produces rules the
 * pipeline genuinely executes: import a Sigma rule, then ingest a matching
 * event and assert the detection fires. This closes the loop the unit tests
 * cannot — that the translated detectionLogic survives persistence and
 * evaluation against a real normalized event.
 */
describe.skipIf(!integrationDbAvailable())("Sigma import → pipeline (integration)", () => {
  let ctx: IntegrationDb;

  beforeAll(async () => {
    ctx = await setupIntegrationDb();
  });

  afterAll(async () => {
    await ctx?.teardown();
  });

  it("imports a Sigma rule that then fires on a matching event", async () => {
    const translations = translateSigmaRules(`
title: Imported SSH auth failure
description: Sigma-imported detection
logsource:
  category: authentication
detection:
  selection:
    eventType: authentication_failed
  condition: selection
level: high
tags:
  - attack.t1110
  - attack.credential_access
`);
    const t = translations[0];
    expect(t.imported).toBe(true);
    if (!t.imported) return;

    await db.createIdsRule({
      ruleId: nanoid(),
      ruleName: t.rule.ruleName,
      description: t.rule.description,
      ruleType: t.rule.ruleType,
      dataSource: t.rule.dataSource,
      detectionLogic: t.rule.detectionLogic,
      severity: t.rule.severity,
      attackTechnique: t.rule.attackTechnique,
      attackTactic: t.rule.attackTactic,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await ingestAndDetect({
      sourceType: "syslog",
      payload: "Apr 10 12:00:01 web-02 sshd[220]: Failed password for admin from 203.0.113.9 port 22 ssh2",
    });

    const detection = result.detections.find((d) => d.ruleName === "Imported SSH auth failure");
    expect(detection).toBeDefined();
    expect(detection?.mitreTechnique).toBe("T1110");
  });
});
