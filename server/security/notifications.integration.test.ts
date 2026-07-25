import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nanoid } from "nanoid";
import { integrationDbAvailable, setupIntegrationDb, type IntegrationDb } from "../../test/integration/harness";
import * as db from "../db";
import { notifyIncidentCreated } from "./notifications";

/**
 * End-to-end notification path against real MySQL and a real HTTP sink:
 * create a webhook channel, fan an incident out, and assert both that the
 * sink received the payload and that a 'sent' delivery row was recorded.
 */
describe.skipIf(!integrationDbAvailable())("notification dispatch (integration)", () => {
  let ctx: IntegrationDb;
  let server: Server;
  let received: unknown[] = [];
  let port = 0;

  beforeAll(async () => {
    ctx = await setupIntegrationDb();
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          received.push(JSON.parse(body));
        } catch {
          received.push(body);
        }
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    port = typeof addr === "object" && addr ? addr.port : 0;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await ctx?.teardown();
  });

  it("delivers to an enabled webhook channel and records the delivery", async () => {
    received = [];
    await db.createNotificationChannel({
      channelId: nanoid(),
      name: "Local sink",
      type: "webhook",
      target: `http://127.0.0.1:${port}/hook`,
      minSeverity: "high",
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await notifyIncidentCreated({
      incidentPk: 999,
      incidentId: "inc-notif-test",
      title: "Integration incident",
      severity: "critical",
      source: "test",
    });

    expect(received).toHaveLength(1);
    expect((received[0] as { event: string }).event).toBe("incident.created");

    const deliveries = await db.getNotificationDeliveries(10);
    const delivery = deliveries.find((d) => d.incidentId === 999);
    expect(delivery?.status).toBe("sent");
    expect(delivery?.statusCode).toBe(200);
  });

  it("does not deliver to a channel below the severity floor", async () => {
    received = [];
    await db.createNotificationChannel({
      channelId: nanoid(),
      name: "Critical-only sink",
      type: "webhook",
      target: `http://127.0.0.1:${port}/hook`,
      minSeverity: "critical",
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // A 'medium' incident is below both channels' floors (high + critical).
    await notifyIncidentCreated({
      incidentPk: 1000,
      incidentId: "inc-low",
      title: "Low severity",
      severity: "medium",
      source: "test",
    });

    expect(received).toHaveLength(0);
  });
});
