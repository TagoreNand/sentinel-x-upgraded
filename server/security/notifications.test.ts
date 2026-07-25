import { describe, expect, it, vi } from "vitest";
import type { InsertNotificationDelivery, NotificationChannel } from "../../drizzle/schema";
import {
  CircuitBreaker,
  buildEmailMessage,
  buildSlackPayload,
  buildWebhookPayload,
  dispatchToChannel,
  escapeSlackMrkdwn,
  meetsSeverity,
  type IncidentNotification,
  type NotifyDeps,
} from "./notifications";

function channel(overrides: Partial<NotificationChannel> = {}): NotificationChannel {
  return {
    id: 1,
    channelId: "chan-1",
    name: "Test channel",
    type: "webhook",
    target: "https://example.test/hook",
    minSeverity: "high",
    enabled: true,
    createdBy: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

function incident(overrides: Partial<IncidentNotification> = {}): IncidentNotification {
  return {
    incidentPk: 42,
    incidentId: "inc-42",
    title: "Test incident",
    severity: "critical",
    source: "test",
    ...overrides,
  };
}

function makeDeps(overrides: Partial<NotifyDeps> = {}): { deps: NotifyDeps; deliveries: InsertNotificationDelivery[]; postJson: ReturnType<typeof vi.fn>; sendEmail: ReturnType<typeof vi.fn> } {
  const deliveries: InsertNotificationDelivery[] = [];
  const postJson = vi.fn(async () => ({ status: 200 }));
  const sendEmail = vi.fn(async () => {});
  const deps: NotifyDeps = {
    transport: { postJson, sendEmail },
    emailConfigured: () => true,
    recordDelivery: async (d) => {
      deliveries.push(d);
    },
    now: () => 1_000,
    breaker: new CircuitBreaker(3, 60_000),
    retryDelayMs: 0,
    timeoutMs: 1_000,
    maxAttempts: 2,
    ...overrides,
  };
  return { deps, deliveries, postJson, sendEmail };
}

describe("meetsSeverity", () => {
  it("notifies at or above the channel floor", () => {
    expect(meetsSeverity("high", "critical")).toBe(true);
    expect(meetsSeverity("high", "high")).toBe(true);
    expect(meetsSeverity("high", "medium")).toBe(false);
    expect(meetsSeverity("low", "low")).toBe(true);
    expect(meetsSeverity("critical", "high")).toBe(false);
  });
});

describe("payload builders", () => {
  it("slack payload carries severity and title", () => {
    const p = buildSlackPayload(incident({ severity: "critical", title: "Boom" }));
    expect(String(p.text)).toContain("CRITICAL");
    expect(String(p.text)).toContain("Boom");
    expect(Array.isArray(p.blocks)).toBe(true);
  });

  it("webhook payload is a structured incident.created event", () => {
    const p = buildWebhookPayload(incident({ incidentPk: 7 }));
    expect(p.event).toBe("incident.created");
    expect((p.incident as { id: number }).id).toBe(7);
  });

  it("email message escapes HTML in the title", () => {
    const m = buildEmailMessage(incident({ title: "<script>alert(1)</script>" }));
    expect(m.html).toContain("&lt;script&gt;");
    expect(m.html).not.toContain("<script>alert");
  });

  it("escapeSlackMrkdwn neutralizes Slack's control characters", () => {
    expect(escapeSlackMrkdwn("<!channel>")).toBe("&lt;!channel&gt;");
    expect(escapeSlackMrkdwn("a & b")).toBe("a &amp; b");
    expect(escapeSlackMrkdwn("plain text")).toBe("plain text");
  });

  it("slack payload neutralizes mrkdwn injection in mrkdwn sinks", () => {
    const p = buildSlackPayload(
      incident({
        title: "<!channel> everyone look",
        description: "click <http://evil.example|the console>",
      }),
    );
    // Top-level text is rendered as mrkdwn — the broadcast must be defanged.
    expect(String(p.text)).not.toContain("<!channel>");
    expect(String(p.text)).toContain("&lt;!channel&gt;");
    // The description section is an explicit mrkdwn block — link syntax dead.
    const serialized = JSON.stringify(p.blocks);
    expect(serialized).not.toContain("<http://evil.example|");
    expect(serialized).toContain("&lt;http://evil.example");
  });
});

describe("CircuitBreaker", () => {
  it("opens after the failure threshold and closes on success", () => {
    const b = new CircuitBreaker(2, 1_000);
    expect(b.isOpen(1, 0)).toBe(false);
    b.recordFailure(1, 0);
    expect(b.isOpen(1, 0)).toBe(false); // 1 < threshold
    b.recordFailure(1, 0);
    expect(b.isOpen(1, 500)).toBe(true); // opened for cooldown
    expect(b.isOpen(1, 1_500)).toBe(false); // cooldown elapsed
    b.recordFailure(1, 2_000);
    b.recordFailure(1, 2_000);
    expect(b.isOpen(1, 2_100)).toBe(true);
    b.recordSuccess(1);
    expect(b.isOpen(1, 2_100)).toBe(false); // success resets
  });

  it("isolates channels", () => {
    const b = new CircuitBreaker(1, 1_000);
    b.recordFailure(1, 0);
    expect(b.isOpen(1, 100)).toBe(true);
    expect(b.isOpen(2, 100)).toBe(false);
  });
});

describe("dispatchToChannel", () => {
  it("delivers a webhook and records 'sent'", async () => {
    const { deps, deliveries, postJson } = makeDeps();
    await dispatchToChannel(channel({ type: "webhook" }), incident(), deps);
    expect(postJson).toHaveBeenCalledTimes(1);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].status).toBe("sent");
    expect(deliveries[0].statusCode).toBe(200);
  });

  it("skips silently below the severity floor (no ledger noise)", async () => {
    const { deps, deliveries, postJson } = makeDeps();
    await dispatchToChannel(channel({ minSeverity: "critical" }), incident({ severity: "low" }), deps);
    expect(postJson).not.toHaveBeenCalled();
    expect(deliveries).toHaveLength(0);
  });

  it("records 'skipped' when the breaker is open", async () => {
    const breaker = new CircuitBreaker(1, 60_000);
    breaker.recordFailure(1, 500); // opens (threshold 1)
    const { deps, deliveries, postJson } = makeDeps({ breaker, now: () => 1_000 });
    await dispatchToChannel(channel(), incident(), deps);
    expect(postJson).not.toHaveBeenCalled();
    expect(deliveries[0].status).toBe("skipped");
    expect(deliveries[0].error).toMatch(/circuit breaker/i);
  });

  it("records 'skipped' for an email channel when SMTP is unconfigured", async () => {
    const { deps, deliveries, sendEmail } = makeDeps({ emailConfigured: () => false });
    await dispatchToChannel(channel({ type: "email", target: "soc@corp.test" }), incident(), deps);
    expect(sendEmail).not.toHaveBeenCalled();
    expect(deliveries[0].status).toBe("skipped");
    expect(deliveries[0].error).toMatch(/not configured/i);
  });

  it("retries then records 'failed', and opens the breaker on repeated failure", async () => {
    const postJson = vi.fn(async () => ({ status: 500 }));
    const breaker = new CircuitBreaker(1, 60_000);
    const { deps, deliveries } = makeDeps({ transport: { postJson, sendEmail: vi.fn() }, maxAttempts: 2, breaker });
    await dispatchToChannel(channel(), incident(), deps);
    expect(postJson).toHaveBeenCalledTimes(2); // one retry
    expect(deliveries[0].status).toBe("failed");
    expect(deliveries[0].attempts).toBe(2);
    // threshold 1 → breaker now open for this channel
    expect(breaker.isOpen(1, deps.now())).toBe(true);
  });

  it("does not carry a stale statusCode from an earlier attempt into a network failure", async () => {
    let call = 0;
    const postJson = vi.fn(async () => {
      call += 1;
      if (call === 1) return { status: 500 }; // HTTP error on attempt 1
      throw new Error("socket hang up"); // network error on attempt 2
    });
    const { deps, deliveries } = makeDeps({ transport: { postJson, sendEmail: vi.fn() }, maxAttempts: 2 });
    await dispatchToChannel(channel(), incident(), deps);
    expect(deliveries[0].status).toBe("failed");
    expect(deliveries[0].error).toMatch(/socket hang up/);
    // The failing attempt never received an HTTP response — no status to report.
    expect(deliveries[0].statusCode).toBeUndefined();
  });

  it("bounds a hung transport with the per-attempt timeout", async () => {
    // A transport that never settles — the email path had no ceiling before.
    const sendEmail = vi.fn(() => new Promise<void>(() => {}));
    const { deps, deliveries } = makeDeps({
      transport: { postJson: vi.fn(), sendEmail },
      maxAttempts: 1,
      timeoutMs: 30,
    });
    const started = Date.now();
    await dispatchToChannel(channel({ type: "email", target: "soc@corp.test" }), incident(), deps);
    expect(Date.now() - started).toBeLessThan(2_000); // did not hang
    expect(deliveries[0].status).toBe("failed");
    expect(deliveries[0].error).toMatch(/timed out/i);
  });

  it("delivers email via the transport when configured", async () => {
    const { deps, deliveries, sendEmail } = makeDeps();
    await dispatchToChannel(channel({ type: "email", target: "soc@corp.test" }), incident(), deps);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(sendEmail.mock.calls[0][0]).toMatchObject({ to: "soc@corp.test" });
    expect(deliveries[0].status).toBe("sent");
  });
});
