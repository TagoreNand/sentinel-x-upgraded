import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nanoid } from "nanoid";
import { integrationDbAvailable, setupIntegrationDb, type IntegrationDb } from "../../test/integration/harness";
import * as db from "../db";
import { pollFeed } from "./intel";
import type { IntelFeed } from "../../drizzle/schema";

/**
 * Feed ingestion end-to-end against real MySQL. The HTTP fetch is injected
 * (canned STIX / MISP payloads) so the test is deterministic; everything after
 * the fetch — parse, dedup against existing IOCs, bulk insert, feed status
 * update — runs for real.
 */
describe.skipIf(!integrationDbAvailable())("intel feed polling (integration)", () => {
  let ctx: IntegrationDb;

  beforeAll(async () => {
    ctx = await setupIntegrationDb();
  });

  afterAll(async () => {
    await ctx?.teardown();
  });

  async function makeFeed(type: "stix" | "misp", name: string): Promise<IntelFeed> {
    const feedId = nanoid();
    const id = await db.createIntelFeed({
      feedId,
      name,
      type,
      url: "https://feed.example/collection",
      defaultThreatLevel: "high",
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    return (await db.getIntelFeedById(id))!;
  }

  it("ingests a STIX bundle, creating deduped IOCs and recording feed status", async () => {
    const feed = await makeFeed("stix", "STIX test feed");
    const bundle = {
      type: "bundle",
      objects: [
        { type: "indicator", pattern: "[ipv4-addr:value = '198.51.100.23']" },
        { type: "indicator", pattern: "[domain-name:value = 'malware.test']" },
        { type: "identity", name: "Vendor" },
        { type: "indicator", pattern: "[ipv4-addr:value = '198.51.100.23']" }, // dup within feed
      ],
    };

    const result = await pollFeed(feed, { fetcher: async () => bundle, timeoutMs: 1000 });
    expect(result.created).toBe(2); // in-feed dedup collapsed the repeat
    expect(result.error).toBeUndefined();

    const hits = await db.findIOCsByValues(["198.51.100.23", "malware.test"]);
    expect(hits.map((h) => h.iocValue).sort()).toEqual(["198.51.100.23", "malware.test"]);
    expect(hits.every((h) => h.source === "feed:STIX test feed")).toBe(true);
    expect(hits.every((h) => h.threatLevel === "high")).toBe(true);

    const updated = await db.getIntelFeedById(feed.id);
    expect(updated?.lastStatus).toBe("success");
    expect(updated?.lastIocCount).toBe(2);

    // Re-poll: everything already exists → nothing new.
    const second = await pollFeed(feed, { fetcher: async () => bundle, timeoutMs: 1000 });
    expect(second.created).toBe(0);
  });

  it("ingests MISP attributes, honoring to_ids and skipping unsupported types", async () => {
    const feed = await makeFeed("misp", "MISP test feed");
    const response = {
      response: {
        Attribute: [
          { type: "ip-dst", value: "203.0.113.55", to_ids: true },
          { type: "btc", value: "1abc" }, // unsupported → skipped
          { type: "sha256", value: "cafebabecafebabe", to_ids: false }, // to_ids false → skipped
          { type: "domain", value: "phish.test" },
        ],
      },
    };

    const result = await pollFeed(feed, { fetcher: async () => response, timeoutMs: 1000 });
    expect(result.created).toBe(2); // ip + domain
    expect(result.skipped).toBe(2); // btc + to_ids:false

    const hits = await db.findIOCsByValues(["203.0.113.55", "phish.test"]);
    expect(hits).toHaveLength(2);
  });

  it("records an error status when the fetch fails, without throwing", async () => {
    const feed = await makeFeed("stix", "Broken feed");
    const result = await pollFeed(feed, {
      fetcher: async () => {
        throw new Error("connection refused");
      },
      timeoutMs: 1000,
    });
    expect(result.error).toMatch(/connection refused/);
    expect(result.created).toBe(0);

    const updated = await db.getIntelFeedById(feed.id);
    expect(updated?.lastStatus).toBe("error");
    expect(updated?.lastError).toMatch(/connection refused/);
  });
});
