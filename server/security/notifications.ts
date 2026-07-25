/**
 * SOC notification dispatch — fan an incident out to Slack, generic webhooks,
 * and email when it is created.
 *
 * Design principles carried from the rest of the platform:
 * - BEST-EFFORT, NEVER FATAL. A notification failure must never fail or roll
 *   back incident creation (same stance as the audit log and side-channel
 *   detection). Every dispatch path catches internally; the caller fires and
 *   forgets.
 * - OBSERVABLE. Every attempt writes a notification_deliveries row (sent /
 *   failed / skipped with a reason), so a missed page is diagnosable instead
 *   of invisible.
 * - RESILIENT. Per-attempt timeout, one bounded retry, and a per-channel
 *   circuit breaker so a flapping webhook does not stall every incident or get
 *   hammered while it is down.
 * - TESTABLE. The transport (HTTP/email) and the delivery recorder are
 *   injected, so dispatch logic is unit-tested without a network or SMTP.
 */
import axios from "axios";
import nodemailer from "nodemailer";
import { nanoid } from "nanoid";
import type { InsertNotificationDelivery, NotificationChannel } from "../../drizzle/schema";
import * as db from "../db";
import { envNumber } from "../_core/env";
import { logger } from "../_core/logger";

const log = logger.child({ component: "notifications" });

export type Severity = "critical" | "high" | "medium" | "low";

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

export type IncidentNotification = {
  incidentPk: number;
  incidentId?: string;
  title: string;
  severity: Severity;
  description?: string;
  classification?: string;
  source: string;
};

/** True when an incident is severe enough to notify a channel. */
export function meetsSeverity(channelMin: Severity, incidentSeverity: Severity): boolean {
  return SEVERITY_RANK[incidentSeverity] >= SEVERITY_RANK[channelMin];
}

// ---- payload builders (pure) ----------------------------------------------

/**
 * Neutralize Slack mrkdwn control characters.
 *
 * Incident titles/descriptions are attacker-influencable (an analyst — or a
 * detection rule fed by hostile log content — controls them) and land in a
 * channel responders trust. Unescaped, `<!channel>` forces a broadcast ping
 * and `<http://evil|Open console>` renders as a legitimate-looking link.
 * Slack's documented escaping for mrkdwn sinks is exactly &, <, > — note this
 * is NOT applied to plain_text blocks, which Slack renders literally and where
 * escaping would leak visible entities.
 */
export function escapeSlackMrkdwn(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function buildSlackPayload(incident: IncidentNotification): Record<string, unknown> {
  const emoji = incident.severity === "critical" ? "🔴" : incident.severity === "high" ? "🟠" : incident.severity === "medium" ? "🟡" : "🔵";
  const esc = escapeSlackMrkdwn;
  return {
    // Top-level `text` is rendered as mrkdwn in notifications → must escape.
    text: `${emoji} [${incident.severity.toUpperCase()}] ${esc(incident.title)}`,
    blocks: [
      // plain_text is rendered literally by Slack — no mrkdwn parsing, so no
      // injection and no escaping (escaping here would show raw entities).
      { type: "header", text: { type: "plain_text", text: `${emoji} Incident: ${incident.title}`.slice(0, 150) } },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Severity:*\n${esc(incident.severity)}` },
          { type: "mrkdwn", text: `*Source:*\n${esc(incident.source)}` },
          ...(incident.classification ? [{ type: "mrkdwn", text: `*Classification:*\n${esc(incident.classification)}` }] : []),
          ...(incident.incidentId ? [{ type: "mrkdwn", text: `*ID:*\n${esc(incident.incidentId)}` }] : []),
        ],
      },
      ...(incident.description ? [{ type: "section", text: { type: "mrkdwn", text: esc(incident.description).slice(0, 2900) } }] : []),
    ],
  };
}

export function buildWebhookPayload(incident: IncidentNotification): Record<string, unknown> {
  return {
    event: "incident.created",
    incident: {
      id: incident.incidentPk,
      incidentId: incident.incidentId,
      title: incident.title,
      severity: incident.severity,
      classification: incident.classification,
      description: incident.description,
      source: incident.source,
    },
  };
}

export function buildEmailMessage(incident: IncidentNotification): { subject: string; text: string; html: string } {
  const subject = `[Sentinel-X][${incident.severity.toUpperCase()}] ${incident.title}`.slice(0, 200);
  const lines = [
    `A new security incident was created.`,
    ``,
    `Title:          ${incident.title}`,
    `Severity:       ${incident.severity}`,
    `Source:         ${incident.source}`,
    ...(incident.classification ? [`Classification: ${incident.classification}`] : []),
    ...(incident.incidentId ? [`Incident ID:    ${incident.incidentId}`] : []),
    ...(incident.description ? [``, incident.description] : []),
  ];
  const text = lines.join("\n");
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const html = `<h2>Security incident: ${esc(incident.title)}</h2><ul>${[
    `<li><b>Severity:</b> ${esc(incident.severity)}</li>`,
    `<li><b>Source:</b> ${esc(incident.source)}</li>`,
    incident.classification ? `<li><b>Classification:</b> ${esc(incident.classification)}</li>` : "",
    incident.incidentId ? `<li><b>Incident ID:</b> ${esc(incident.incidentId)}</li>` : "",
  ].join("")}</ul>${incident.description ? `<p>${esc(incident.description)}</p>` : ""}`;
  return { subject, text, html };
}

// ---- circuit breaker -------------------------------------------------------

/**
 * Per-channel breaker: after `threshold` consecutive failures a channel is
 * skipped for `cooldownMs` so a dead endpoint does not add latency and retries
 * to every incident. A single success closes it.
 */
export class CircuitBreaker {
  private readonly state = new Map<number, { failures: number; openUntil: number }>();

  constructor(private readonly threshold = 3, private readonly cooldownMs = 60_000) {}

  isOpen(channelId: number, now: number): boolean {
    const entry = this.state.get(channelId);
    return entry !== undefined && entry.openUntil > now;
  }

  recordSuccess(channelId: number): void {
    this.state.delete(channelId);
  }

  recordFailure(channelId: number, now: number): void {
    const entry = this.state.get(channelId) ?? { failures: 0, openUntil: 0 };
    entry.failures += 1;
    if (entry.failures >= this.threshold) {
      entry.openUntil = now + this.cooldownMs;
      entry.failures = 0;
    }
    this.state.set(channelId, entry);
  }
}

// ---- transport (injectable) ------------------------------------------------

export type EmailMessage = { from: string; to: string; subject: string; text: string; html: string };

export type NotifyTransport = {
  postJson(url: string, body: unknown, timeoutMs: number): Promise<{ status: number }>;
  sendEmail(msg: EmailMessage): Promise<void>;
};

function emailConfigured(): boolean {
  return Boolean(process.env.SMTP_HOST && process.env.EMAIL_FROM);
}

let cachedTransporter: nodemailer.Transporter | null = null;
function getTransporter(): nodemailer.Transporter {
  if (!cachedTransporter) {
    // nodemailer's defaults are generous (greeting 30s, connection 2min,
    // socket 10min) — far beyond our per-attempt budget. Bound them at the
    // socket level so a black-holing relay actually releases the connection,
    // rather than only being abandoned by the caller's race.
    const budget = envNumber("NOTIFY_TIMEOUT_MS", 5000);
    cachedTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: envNumber("SMTP_PORT", 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
      connectionTimeout: budget,
      greetingTimeout: budget,
      socketTimeout: budget,
    });
  }
  return cachedTransporter;
}

const defaultTransport: NotifyTransport = {
  async postJson(url, body, timeoutMs) {
    const response = await axios.post(url, body, {
      timeout: timeoutMs,
      // We classify status ourselves so a 4xx/5xx is a controlled failure, not a throw.
      validateStatus: () => true,
      headers: { "content-type": "application/json" },
    });
    return { status: response.status };
  },
  async sendEmail(msg) {
    await getTransporter().sendMail(msg);
  },
};

export type NotifyDeps = {
  transport: NotifyTransport;
  emailConfigured: () => boolean;
  recordDelivery: (delivery: InsertNotificationDelivery) => Promise<void>;
  now: () => number;
  breaker: CircuitBreaker;
  retryDelayMs: number;
  timeoutMs: number;
  maxAttempts: number;
};

const sharedBreaker = new CircuitBreaker();

function defaultDeps(): NotifyDeps {
  return {
    transport: defaultTransport,
    emailConfigured,
    recordDelivery: db.createNotificationDelivery,
    now: () => Date.now(),
    breaker: sharedBreaker,
    retryDelayMs: envNumber("NOTIFY_RETRY_DELAY_MS", 400),
    timeoutMs: envNumber("NOTIFY_TIMEOUT_MS", 5000),
    maxAttempts: envNumber("NOTIFY_MAX_ATTEMPTS", 2),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    t.unref?.();
  });
}

/**
 * Enforce the per-attempt budget on ANY transport, not just HTTP.
 *
 * axios bounds its own request, but the email path had no ceiling at all —
 * and since fan-out is sequential, one stalled SMTP relay delayed the Slack
 * page for the SAME incident. Racing here makes the guarantee transport-
 * agnostic (and covers a future/custom transport that forgets its own
 * timeout). The underlying promise cannot be cancelled, so the socket-level
 * timeouts above are what actually free the connection; this bounds the
 * dispatch loop.
 */
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`attempt timed out after ${timeoutMs}ms`)), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function record(
  deps: NotifyDeps,
  channelId: number,
  incident: IncidentNotification,
  status: "sent" | "failed" | "skipped",
  statusCode: number | undefined,
  error: string | undefined,
  attempts: number,
): Promise<void> {
  try {
    await deps.recordDelivery({
      deliveryId: nanoid(),
      channelId,
      incidentId: incident.incidentPk,
      status,
      statusCode,
      error: error?.slice(0, 2000),
      attempts,
      createdAt: new Date(),
    });
  } catch (err) {
    // The delivery ledger is itself best-effort; never let recording a failure
    // become a thrown error that escapes the notifier.
    log.error("failed to record notification delivery", err, { channelId, status });
  }
}

/**
 * Deliver one incident to one channel. Never throws. Returns nothing; the
 * outcome is captured in the delivery ledger.
 */
export async function dispatchToChannel(
  channel: NotificationChannel,
  incident: IncidentNotification,
  deps: NotifyDeps = defaultDeps(),
): Promise<void> {
  if (!meetsSeverity(channel.minSeverity, incident.severity)) {
    return; // below the channel's threshold — intentionally no ledger noise
  }
  if (deps.breaker.isOpen(channel.id, deps.now())) {
    await record(deps, channel.id, incident, "skipped", undefined, "circuit breaker open", 0);
    return;
  }
  if (channel.type === "email" && !deps.emailConfigured()) {
    await record(deps, channel.id, incident, "skipped", undefined, "email transport not configured (SMTP_HOST/EMAIL_FROM)", 0);
    return;
  }

  let attempts = 0;
  let statusCode: number | undefined;
  let lastError: string | undefined;

  while (attempts < deps.maxAttempts) {
    attempts += 1;
    // Reset per attempt: a stale status from an earlier attempt must not be
    // recorded against a later one that never received an HTTP response
    // (e.g. HTTP 500 then ECONNRESET would otherwise log status 500 next to
    // a "socket hang up" error).
    statusCode = undefined;
    try {
      if (channel.type === "email") {
        const message = { from: process.env.EMAIL_FROM ?? "sentinel-x@localhost", to: channel.target, ...buildEmailMessage(incident) };
        await withTimeout(deps.transport.sendEmail(message), deps.timeoutMs);
      } else {
        const payload = channel.type === "slack" ? buildSlackPayload(incident) : buildWebhookPayload(incident);
        const result = await withTimeout(deps.transport.postJson(channel.target, payload, deps.timeoutMs), deps.timeoutMs);
        statusCode = result.status;
        if (result.status >= 400) throw new Error(`HTTP ${result.status}`);
      }
      deps.breaker.recordSuccess(channel.id);
      await record(deps, channel.id, incident, "sent", statusCode, undefined, attempts);
      return;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      if (attempts < deps.maxAttempts) await sleep(deps.retryDelayMs);
    }
  }

  deps.breaker.recordFailure(channel.id, deps.now());
  await record(deps, channel.id, incident, "failed", statusCode, lastError, attempts);
  log.warn("notification delivery failed", { channelId: channel.id, type: channel.type, incidentId: incident.incidentPk, error: lastError });
}

/**
 * Fan an incident out to every enabled channel. Best-effort and non-throwing:
 * safe to call (and forget) from any post-commit incident-creation path.
 */
export async function notifyIncidentCreated(incident: IncidentNotification, deps: NotifyDeps = defaultDeps()): Promise<void> {
  try {
    const channels = await db.getActiveNotificationChannels();
    for (const channel of channels) {
      await dispatchToChannel(channel, incident, deps);
    }
  } catch (error) {
    log.error("notification fan-out failed", error, { incidentId: incident.incidentPk });
  }
}
