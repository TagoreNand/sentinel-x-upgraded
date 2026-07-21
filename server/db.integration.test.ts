import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nanoid } from "nanoid";
import { integrationDbAvailable, setupIntegrationDb, type IntegrationDb } from "../test/integration/harness";
import * as db from "./db";

/**
 * Data-layer integration tests against a real, migrated MySQL. These lock in
 * the driver-semantics behaviors that unit tests structurally cannot reach:
 * $returningId primary keys, the login-vs-role update split, and the atomic
 * ingest-job claim.
 */
describe.skipIf(!integrationDbAvailable())("db layer (integration)", () => {
  let ctx: IntegrationDb;

  beforeAll(async () => {
    ctx = await setupIntegrationDb();
  });

  afterAll(async () => {
    await ctx?.teardown();
  });

  it("createIncident returns the real numeric PK (not the raw insertId tuple)", async () => {
    const pk = await db.createIncident({
      incidentId: nanoid(),
      title: "Integration incident",
      severity: "high",
      status: "open",
      detectedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(typeof pk).toBe("number");
    expect(pk).toBeGreaterThan(0);
    const fetched = await db.getIncidentById(pk);
    expect(fetched?.title).toBe("Integration incident");
  });

  it("assigns the configured default role to a new non-owner user", async () => {
    await db.upsertUser({ openId: "u-new", name: "New Analyst", lastSignedIn: new Date() });
    const user = await db.getUserByOpenId("u-new");
    expect(user?.role).toBe("analyst");
  });

  it("preserves a promoted role across subsequent logins", async () => {
    await db.upsertUser({ openId: "u-promote", name: "Future Lead", lastSignedIn: new Date() });
    const created = await db.getUserByOpenId("u-promote");
    expect(created?.role).toBe("analyst");

    await db.updateUserRole(created!.id, "lead");
    // Simulate a re-login: upsert with no explicit role. The promotion must
    // survive — role is deliberately absent from the update set.
    await db.upsertUser({ openId: "u-promote", lastSignedIn: new Date() });
    const afterLogin = await db.getUserByOpenId("u-promote");
    expect(afterLogin?.role).toBe("lead");
  });

  it("anchors the platform owner to admin on every login", async () => {
    await db.upsertUser({ openId: "integration-owner", name: "Owner", lastSignedIn: new Date() });
    const owner = await db.getUserByOpenId("integration-owner");
    expect(owner?.role).toBe("admin");
  });

  it("getUsers and getUserById round-trip the directory", async () => {
    const users = await db.getUsers(50);
    expect(users.length).toBeGreaterThan(0);
    const byId = await db.getUserById(users[0].id);
    expect(byId?.openId).toBe(users[0].openId);
  });

  it("claims an ingest job exactly once (atomic UPDATE-where-status)", async () => {
    const ingestId = nanoid();
    await db.createIngestJob({
      ingestId,
      sourceType: "syslog",
      payload: "raw log line",
      status: "queued",
      attempts: 0,
      queuedAt: new Date(),
    });

    const first = await db.claimIngestJob(ingestId);
    expect(first?.status).toBe("processing");
    expect(first?.attempts).toBe(1);

    // A duplicate delivery loses the claim race and gets nothing.
    const second = await db.claimIngestJob(ingestId);
    expect(second).toBeUndefined();
  });

  it("findIOCsByValues matches only active indicators, exactly", async () => {
    await db.createIOC({
      iocId: nanoid(),
      iocType: "ip",
      iocValue: "203.0.113.7",
      threatLevel: "high",
      status: "active",
      confidence: 80,
      firstSeen: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const hits = await db.findIOCsByValues(["203.0.113.7", "198.51.100.1"]);
    expect(hits).toHaveLength(1);
    expect(hits[0].iocValue).toBe("203.0.113.7");
  });

  it("countRecentEventsByField counts within the window via the composite index", async () => {
    const ip = "5.5.5.5";
    for (let i = 0; i < 3; i++) {
      await db.createSecurityEvent({
        eventId: nanoid(),
        eventType: "authentication_failed",
        sourceIp: ip,
        severity: "medium",
        status: "new",
        timestamp: new Date(),
        createdAt: new Date(),
      });
    }
    const recent = await db.countRecentEventsByField("sourceIp", ip, new Date(Date.now() - 60_000));
    expect(recent).toBe(3);
    // A window that predates the events excludes them.
    const none = await db.countRecentEventsByField("sourceIp", ip, new Date(Date.now() + 60_000));
    expect(none).toBe(0);
  });
});
