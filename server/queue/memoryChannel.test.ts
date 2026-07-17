import { describe, expect, it } from "vitest";
import { MemoryChannel } from "./memoryChannel";

async function waitFor(condition: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("MemoryChannel", () => {
  it("processes every pushed task", async () => {
    const processed: string[] = [];
    const channel = new MemoryChannel({
      concurrency: 3,
      capacity: 100,
      process: async (id) => {
        processed.push(id);
      },
    });
    for (let i = 0; i < 10; i++) expect(channel.push(`job-${i}`)).toBe(true);
    await waitFor(() => processed.length === 10);
    expect(new Set(processed).size).toBe(10);
  });

  it("never exceeds the concurrency bound", async () => {
    let current = 0;
    let peak = 0;
    let done = 0;
    const channel = new MemoryChannel({
      concurrency: 2,
      capacity: 100,
      process: async () => {
        current += 1;
        peak = Math.max(peak, current);
        await new Promise((resolve) => setTimeout(resolve, 10));
        current -= 1;
        done += 1;
      },
    });
    for (let i = 0; i < 8; i++) channel.push(`job-${i}`);
    await waitFor(() => done === 8);
    expect(peak).toBe(2);
  });

  it("applies backpressure at capacity", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const channel = new MemoryChannel({
      concurrency: 1,
      capacity: 2,
      process: async () => {
        await gate;
      },
    });
    expect(channel.push("a")).toBe(true); // immediately claimed by the worker
    await waitFor(() => channel.active === 1);
    expect(channel.push("b")).toBe(true); // waiting: 1
    expect(channel.push("c")).toBe(true); // waiting: 2 = capacity
    expect(channel.push("d")).toBe(false); // overflow → caller's problem, by design
    release();
  });

  it("survives a rejecting processor and reports it", async () => {
    const failures: string[] = [];
    let done = 0;
    const channel = new MemoryChannel({
      concurrency: 1,
      capacity: 10,
      process: async (id) => {
        done += 1;
        if (id === "bad") throw new Error("boom");
      },
      onProcessorError: (id) => failures.push(id),
    });
    channel.push("bad");
    channel.push("good");
    await waitFor(() => done === 2);
    expect(failures).toEqual(["bad"]);
  });

  it("refuses new work after close but drains in-flight tasks", async () => {
    let finished = false;
    const channel = new MemoryChannel({
      concurrency: 1,
      capacity: 10,
      process: async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        finished = true;
      },
    });
    channel.push("only");
    await waitFor(() => channel.active === 1);
    await channel.close(1_000);
    expect(finished).toBe(true);
    expect(channel.push("late")).toBe(false);
  });

  it("abandons waiting tasks on close instead of pumping them mid-shutdown", async () => {
    const processed: string[] = [];
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const channel = new MemoryChannel({
      concurrency: 1,
      capacity: 10,
      process: async (id) => {
        processed.push(id);
        if (id === "first") await gate;
      },
    });
    channel.push("first"); // claimed immediately, blocks on the gate
    await waitFor(() => channel.active === 1);
    channel.push("second"); // waiting when close() begins
    const closing = channel.close(1_000);
    release();
    await closing;
    // "second" must stay in the backlog for the ledger reaper — starting it
    // during shutdown would race the DB pool teardown.
    expect(processed).toEqual(["first"]);
    expect(channel.depth).toBe(1);
  });

  it("rejects non-finite configuration (no fail-open)", () => {
    expect(() => new MemoryChannel({ concurrency: NaN, capacity: 10, process: async () => {} })).toThrow();
    expect(() => new MemoryChannel({ concurrency: 1, capacity: NaN, process: async () => {} })).toThrow();
  });
});
