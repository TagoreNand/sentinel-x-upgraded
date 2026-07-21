import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Connection } from "mysql2/promise";
import { integrationDbAvailable, runMigrations, setupIntegrationDb, type IntegrationDb } from "./harness";

/**
 * Validates the 0005 role-enum migration on rows that PREDATE it — the exact
 * scenario a direct narrowing ALTER would corrupt (coercing every out-of-range
 * value to ''). We migrate up to 0004 (old enum: 'user'|'admin'), seed legacy
 * rows, then apply 0005 and assert the three-phase remap preserved intent.
 */
describe.skipIf(!integrationDbAvailable())("0005 role enum migration (integration)", () => {
  let ctx: IntegrationDb;
  let conn: Connection;

  beforeAll(async () => {
    ctx = await setupIntegrationDb({ migrateUpTo: "0004_ingest_queue" });
    conn = await ctx.connect();
    // Seed rows under the OLD enum ('user','admin').
    await conn.query(
      "INSERT INTO users (openId, role) VALUES ('legacy-user', 'user'), ('legacy-admin', 'admin'), ('legacy-user-2', 'user')",
    );
    // Apply the remaining migration(s), i.e. 0005.
    await runMigrations(ctx.url, { afterTag: "0004_ingest_queue" });
  });

  afterAll(async () => {
    await conn?.end();
    await ctx?.teardown();
  });

  it("remaps every legacy 'user' to 'analyst'", async () => {
    const [rows] = await conn.query("SELECT openId, role FROM users WHERE openId LIKE 'legacy-user%'");
    for (const row of rows as Array<{ openId: string; role: string }>) {
      expect(row.role).toBe("analyst");
    }
  });

  it("preserves existing admins", async () => {
    const [rows] = await conn.query("SELECT role FROM users WHERE openId = 'legacy-admin'");
    expect((rows as Array<{ role: string }>)[0].role).toBe("admin");
  });

  it("accepts the new tiers and rejects the retired 'user' value", async () => {
    await conn.query("INSERT INTO users (openId, role) VALUES ('new-viewer', 'viewer'), ('new-lead', 'lead')");
    const [rows] = await conn.query("SELECT role FROM users WHERE openId IN ('new-viewer', 'new-lead') ORDER BY openId");
    expect((rows as Array<{ role: string }>).map((r) => r.role).sort()).toEqual(["lead", "viewer"]);

    // The old value is no longer a member of the enum.
    await expect(conn.query("INSERT INTO users (openId, role) VALUES ('should-fail', 'user')")).rejects.toBeTruthy();
  });

  it("defaults the column to the least-privilege tier", async () => {
    await conn.query("INSERT INTO users (openId) VALUES ('no-role-specified')");
    const [rows] = await conn.query("SELECT role FROM users WHERE openId = 'no-role-specified'");
    expect((rows as Array<{ role: string }>)[0].role).toBe("viewer");
  });
});
