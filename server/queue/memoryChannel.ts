/**
 * Bounded, concurrency-limited in-process task channel.
 *
 * This is the ingestion queue's fallback transport for single-node and dev
 * deployments without Redis. It is deliberately dumb: FIFO delivery of ids
 * to an injected processor, a hard capacity bound, and a drain-on-close.
 * Everything stateful about a job (attempts, status, results, retry policy)
 * lives in the ingest_jobs table — so losing this channel's contents on a
 * crash loses only *delivery*, which the DB reaper re-issues. Durability is
 * the ledger's job, never the transport's.
 *
 * NOT safe across replicas: two pods each get their own channel. Multi-pod
 * deployments must configure REDIS_URL (enforced by a boot-time warning in
 * ingestQueue.ts, since we cannot see the replica count from here).
 */

export type MemoryChannelOptions = {
  /** Max tasks processed simultaneously. */
  concurrency: number;
  /** Max tasks waiting; push() returns false beyond this (backpressure). */
  capacity: number;
  /** Processor. MUST NOT reject — wrap your handler; rejections are logged and dropped. */
  process: (id: string) => Promise<void>;
  /** Called if the processor rejects anyway (a bug in the wrapper, not the job). */
  onProcessorError?: (id: string, error: unknown) => void;
};

export class MemoryChannel {
  private readonly waiting: string[] = [];
  private inFlight = 0;
  private closed = false;

  constructor(private readonly options: MemoryChannelOptions) {
    if (
      !Number.isFinite(options.concurrency) ||
      options.concurrency < 1 ||
      !Number.isFinite(options.capacity) ||
      options.capacity < 1
    ) {
      throw new Error("MemoryChannel requires finite concurrency >= 1 and capacity >= 1");
    }
  }

  /** Enqueue a task id. Returns false when full or closed — caller decides what backpressure means. */
  push(id: string): boolean {
    if (this.closed || this.waiting.length >= this.options.capacity) return false;
    this.waiting.push(id);
    this.pump();
    return true;
  }

  get depth(): number {
    return this.waiting.length;
  }

  get active(): number {
    return this.inFlight;
  }

  /**
   * Stop accepting work and wait for in-flight tasks to finish, up to the
   * deadline. Tasks still WAITING are abandoned deliberately — their ledger
   * rows stay 'queued' and the reaper re-delivers after restart.
   */
  async close(drainTimeoutMs = 5_000): Promise<void> {
    this.closed = true;
    const deadline = Date.now() + drainTimeoutMs;
    while (this.inFlight > 0 && Date.now() < deadline) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 25);
        timer.unref();
      });
    }
  }

  private pump(): void {
    // The closed check is what makes close()'s "waiting tasks are abandoned"
    // contract true: without it, every finishing task re-pumps fresh work
    // from the backlog during shutdown, racing the DB pool teardown.
    while (!this.closed && this.inFlight < this.options.concurrency && this.waiting.length > 0) {
      const id = this.waiting.shift();
      if (id === undefined) return;
      this.inFlight += 1;
      this.options
        .process(id)
        .catch((error) => this.options.onProcessorError?.(id, error))
        .finally(() => {
          this.inFlight -= 1;
          this.pump();
        });
    }
  }
}
