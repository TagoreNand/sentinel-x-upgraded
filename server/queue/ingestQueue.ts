/**
 * Asynchronous ingestion queue.
 *
 * Architecture: the API path VALIDATES and RECORDS (a durable ingest_jobs
 * row), then returns immediately — the caller never waits on enrichment,
 * rule evaluation, or the persist transaction. A worker drains jobs through
 * the existing ingestAndDetect pipeline. This decouples ingestion latency
 * from detection cost, which was the last synchronous bottleneck in the
 * request path.
 *
 * Invariants:
 * - THE LEDGER IS TRUTH. Redis (or the in-memory channel) is delivery-only.
 *   Any job state decision — claimed, completed, retry budget — is made
 *   against ingest_jobs with atomic UPDATEs. Duplicate deliveries (BullMQ
 *   stalled-job recovery, reaper re-issues) lose the claim race and no-op.
 * - REPLAYS ARE SAFE. The worker passes a deterministic eventId derived from
 *   the job id into the pipeline; the securityEvents UNIQUE constraint turns
 *   a crash-after-commit retry into ER_DUP_ENTRY, which we acknowledge as
 *   success instead of double-ingesting (see isDuplicateEntryError).
 * - CRASHES SELF-HEAL. A reaper periodically re-dispatches jobs stuck in
 *   'queued' (dispatch lost) or 'processing' (worker died) past a staleness
 *   deadline, and terminally fails jobs that exhausted their attempt budget.
 *
 * Transport selection: REDIS_URL set → BullMQ (durable, multi-replica).
 * Unset → bounded in-process channel (dev / single node; delivery is lost on
 * restart but the ledger + reaper recover it).
 */
import { Queue, Worker, type Job } from "bullmq";
import { nanoid } from "nanoid";
import { AppError } from "../_core/errors";
import { envNumber } from "../_core/env";
import { logger } from "../_core/logger";
import * as db from "../db";
import { ingestAndDetect, isDuplicateEntryError, type IngestSourceType } from "../security/pipeline";
import { MemoryChannel } from "./memoryChannel";

const log = logger.child({ component: "ingest-queue" });

const QUEUE_NAME = "sentinel-ingest";

type BullJobData = { ingestId: string };

let bullQueue: Queue<BullJobData> | null = null;
let bullWorker: Worker<BullJobData> | null = null;
let memoryChannel: MemoryChannel | null = null;
let reaperTimer: NodeJS.Timeout | null = null;
let reaping = false;
let initialized = false;

function config() {
  return {
    redisUrl: process.env.REDIS_URL ?? "",
    workerEnabled: (process.env.INGEST_WORKER_ENABLED ?? "true") !== "false",
    concurrency: envNumber("INGEST_QUEUE_CONCURRENCY", 4),
    maxAttempts: envNumber("INGEST_MAX_ATTEMPTS", 3),
    memoryCapacity: envNumber("INGEST_QUEUE_CAPACITY", 1_000),
    staleAfterMs: envNumber("INGEST_STALE_AFTER_SECONDS", 300) * 1_000,
    reaperIntervalMs: envNumber("INGEST_REAPER_INTERVAL_SECONDS", 60) * 1_000,
    retryDelayMs: envNumber("INGEST_RETRY_DELAY_SECONDS", 5) * 1_000,
  };
}

export type EnqueueIngestInput = {
  sourceType: IngestSourceType;
  payload: unknown;
  assetId?: number;
  userId?: number;
};

/**
 * Accept an event for asynchronous processing. Returns the ingestId the
 * caller polls via siem.getIngestJob. The job row is durable BEFORE dispatch
 * is attempted; a dispatch failure (Redis blip, channel saturation) is
 * logged and left for the reaper — acceptance never depends on the
 * transport being healthy, only on the database.
 */
export async function enqueueIngest(input: EnqueueIngestInput): Promise<string> {
  const ingestId = nanoid();
  await db.createIngestJob({
    ingestId,
    sourceType: input.sourceType,
    payload: input.payload,
    assetId: input.assetId,
    requestedBy: input.userId,
    status: "queued",
    attempts: 0,
    queuedAt: new Date(),
  });

  try {
    await dispatch(ingestId);
  } catch (error) {
    log.error("dispatch failed; job remains queued for the reaper", error, { ingestId });
  }
  return ingestId;
}

async function dispatch(ingestId: string, dedupeSuffix = ""): Promise<void> {
  if (bullQueue) {
    // jobId dedupes the common path (enqueue + a racing reaper); the reaper
    // passes a suffix because BullMQ silently ignores an add() whose jobId
    // still exists — correctness does not depend on this, the claim does.
    await bullQueue.add(
      "ingest",
      { ingestId },
      {
        jobId: `${ingestId}${dedupeSuffix}`,
        attempts: config().maxAttempts,
        backoff: { type: "exponential", delay: 2_000 },
        removeOnComplete: { age: 3_600, count: 1_000 },
        removeOnFail: { age: 24 * 3_600 },
      },
    );
    return;
  }
  if (memoryChannel) {
    if (!memoryChannel.push(ingestId)) {
      log.warn("memory channel saturated; job left for reaper", { ingestId, depth: memoryChannel.depth });
    }
    return;
  }
  // Queue not initialized (e.g. a script imported the router without booting
  // the server). The row is durable; a running instance's reaper picks it up.
  log.warn("ingest queue not initialized; job persisted without dispatch", { ingestId });
}

type ProcessOutcome = "completed" | "retry" | "failed" | "skipped";

/**
 * One delivery attempt. All state transitions go through the ledger; the
 * return value only tells the TRANSPORT whether to schedule a redelivery.
 */
async function processIngestJob(ingestId: string): Promise<ProcessOutcome> {
  const claimed = await db.claimIngestJob(ingestId);
  if (!claimed) {
    // Lost the claim race or the job is terminal — a duplicate delivery
    // doing exactly what duplicate deliveries should do: nothing.
    return "skipped";
  }

  const jlog = log.child({ ingestId, attempt: claimed.attempts });
  const timer = jlog.startTimer();
  try {
    const result = await ingestAndDetect({
      sourceType: claimed.sourceType as IngestSourceType,
      payload: claimed.payload,
      assetId: claimed.assetId ?? undefined,
      userId: claimed.requestedBy ?? undefined,
      eventId: `evt_${ingestId}`,
    });
    await db.completeIngestJob(ingestId, {
      eventId: result.eventId,
      alertCount: result.alerts.length,
      detectionCount: result.detections.length,
      incidentIds: result.incidentIds,
      detections: result.detections,
    });
    timer("ingest job completed", { detections: result.detections.length, incidents: result.incidentIds.length });
    return "completed";
  } catch (error) {
    if (isDuplicateEntryError(error)) {
      // A previous attempt committed the whole outcome; this delivery is a
      // replay. Success, not failure.
      await db.completeIngestJob(ingestId, { replayed: true });
      jlog.info("replay of committed work acknowledged");
      return "completed";
    }
    const terminal = claimed.attempts >= config().maxAttempts;
    // The ledger's error column is client-visible via siem.getIngestJob —
    // store the sanitized message; full diagnostics go to the log stream.
    const storedMessage = error instanceof AppError ? `${error.code}: ${error.safeMessage}` : "Unexpected processing error";
    jlog.error("ingest job attempt failed", error, { terminal });
    await db.markIngestJobFailure(ingestId, storedMessage, terminal);
    return terminal ? "failed" : "retry";
  }
}

/** Memory-mode processor wrapper: never rejects; schedules its own retries. */
async function processForMemoryChannel(ingestId: string): Promise<void> {
  try {
    const outcome = await processIngestJob(ingestId);
    if (outcome === "retry") {
      const timer = setTimeout(() => {
        memoryChannel?.push(ingestId);
      }, config().retryDelayMs);
      timer.unref();
    }
  } catch (error) {
    // processIngestJob handles its own failures; reaching here means the
    // LEDGER was unreachable. The reaper retries once the DB is back.
    log.error("ingest job processing crashed outside the ledger", error, { ingestId });
  }
}

/**
 * Re-dispatch jobs whose delivery was lost (enqueue crash, channel loss on
 * restart) or whose worker died mid-claim. Runs in every instance; the
 * atomic claim makes overlapping reapers across replicas harmless.
 */
async function reapStaleJobs(): Promise<void> {
  if (reaping) return;
  reaping = true;
  try {
    const { staleAfterMs, maxAttempts } = config();
    const stale = await db.findStaleIngestJobs(new Date(Date.now() - staleAfterMs));
    for (const job of stale) {
      // Per-job isolation: one undispatchable job must not abort the sweep
      // and starve every other stale job behind it.
      try {
        if (job.attempts >= maxAttempts) {
          // markIngestJobFailure only touches non-terminal rows, so if the
          // "stale" worker was merely slow and completed between our SELECT
          // and this UPDATE, the completed outcome wins — the reaper never
          // stamps committed work as failed.
          await db.markIngestJobFailure(job.ingestId, "Exceeded attempt budget (reaped)", true);
          log.warn("stale job terminally failed by reaper", { ingestId: job.ingestId, attempts: job.attempts });
          continue;
        }
        if (job.status === "processing") {
          await db.requeueIngestJob(job.ingestId);
        }
        await dispatch(job.ingestId, `:r${job.attempts}:${nanoid(6)}`);
        log.info("stale job re-dispatched", { ingestId: job.ingestId, previousStatus: job.status });
      } catch (error) {
        log.error("failed to re-dispatch stale job", error, { ingestId: job.ingestId });
      }
    }
  } catch (error) {
    log.error("reaper sweep failed", error);
  } finally {
    reaping = false;
  }
}

/**
 * Boot-time wiring. Never blocks startup on Redis: BullMQ connects lazily
 * and retries in the background, and readiness is governed by the DB probe —
 * a Redis blip degrades ingestion throughput, it does not take the API down.
 */
export function initIngestQueue(): void {
  if (initialized) return;
  initialized = true;
  const cfg = config();

  if (cfg.redisUrl) {
    // Producer and worker need OPPOSITE failure semantics. The producer must
    // FAIL FAST: with ioredis's offline queue enabled and unlimited retries,
    // an add() during a Redis outage never settles — the ingest request
    // hangs and the reaper's `reaping` guard is never released (its finally
    // block never runs), wedging recovery permanently. The worker's blocking
    // connection is the one place BullMQ requires maxRetriesPerRequest: null,
    // and it SHOULD wait out an outage and resume.
    const producerConnection = { url: cfg.redisUrl, maxRetriesPerRequest: 3, enableOfflineQueue: false };
    const workerConnection = { url: cfg.redisUrl, maxRetriesPerRequest: null };
    bullQueue = new Queue<BullJobData>(QUEUE_NAME, { connection: producerConnection });
    bullQueue.on("error", (error) => log.error("bull queue error", error));

    if (cfg.workerEnabled) {
      bullWorker = new Worker<BullJobData>(
        QUEUE_NAME,
        async (job: Job<BullJobData>) => {
          const outcome = await processIngestJob(job.data.ingestId);
          if (outcome === "retry") {
            // Throwing hands scheduling back to BullMQ's exponential backoff;
            // the ledger already holds the real state.
            throw new Error(`ingest job ${job.data.ingestId} scheduled for retry`);
          }
        },
        { connection: workerConnection, concurrency: cfg.concurrency },
      );
      bullWorker.on("error", (error) => log.error("bull worker error", error));
      log.info("ingest queue initialized", { mode: "redis", concurrency: cfg.concurrency });
    } else {
      log.info("ingest queue initialized (API-only pod, worker disabled)", { mode: "redis" });
    }
  } else {
    if (!cfg.workerEnabled) {
      log.warn("INGEST_WORKER_ENABLED=false ignored: memory mode has no external worker; enabling in-process worker");
    }
    memoryChannel = new MemoryChannel({
      concurrency: cfg.concurrency,
      capacity: cfg.memoryCapacity,
      process: processForMemoryChannel,
      onProcessorError: (id, error) => log.error("memory channel processor rejected", error, { ingestId: id }),
    });
    log.warn("ingest queue initialized in single-node memory mode — set REDIS_URL for durable, multi-replica delivery", {
      mode: "memory",
      concurrency: cfg.concurrency,
      capacity: cfg.memoryCapacity,
    });
  }

  reaperTimer = setInterval(() => void reapStaleJobs(), cfg.reaperIntervalMs);
  reaperTimer.unref();
  // Early sweep shortly after boot to recover work stranded by the previous
  // process (memory-mode restarts, crashed workers).
  const bootSweep = setTimeout(() => void reapStaleJobs(), 5_000);
  bootSweep.unref();
}

/** Graceful-shutdown hook: stop deliveries, drain in-flight, close sockets. */
export async function closeIngestQueue(): Promise<void> {
  if (reaperTimer) {
    clearInterval(reaperTimer);
    reaperTimer = null;
  }
  if (bullWorker) {
    await bullWorker.close();
    bullWorker = null;
  }
  if (bullQueue) {
    await bullQueue.close();
    bullQueue = null;
  }
  if (memoryChannel) {
    await memoryChannel.close(5_000);
    memoryChannel = null;
  }
  initialized = false;
  log.info("ingest queue closed");
}
