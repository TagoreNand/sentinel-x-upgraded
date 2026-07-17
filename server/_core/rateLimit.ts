/**
 * In-process token-bucket rate limiter.
 *
 * Scope decision: this protects a single pod from a single noisy caller
 * (runaway log shipper, scripted ingestion loop) saturating the synchronous
 * pipeline. It is intentionally per-process — cross-replica fairness needs a
 * shared store (Redis INCR/EXPIRE or a gateway limiter), and pretending an
 * in-memory map is cluster-wide would be worse than saying so. Callers pick
 * the key (user id preferred, IP as fallback).
 */

export type TokenBucketOptions = {
  /** Maximum burst size. */
  capacity: number;
  /** Sustained refill rate, tokens per second. */
  refillPerSecond: number;
};

type Bucket = { tokens: number; lastSeenMs: number };

export class TokenBucketLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly options: TokenBucketOptions) {
    // NaN comparisons are false in BOTH directions, so `capacity < 1` alone
    // waves NaN through — and a NaN bucket never blocks anything (NaN < 1 is
    // false in tryConsume too). A rate limiter that fails open on a config
    // typo is worse than none: it reports protection that isn't there.
    if (
      !Number.isFinite(options.capacity) ||
      options.capacity < 1 ||
      !Number.isFinite(options.refillPerSecond) ||
      options.refillPerSecond <= 0
    ) {
      throw new Error("TokenBucketLimiter requires finite capacity >= 1 and refillPerSecond > 0");
    }
  }

  /** Returns true and consumes one token if the caller is within budget. */
  tryConsume(key: string, nowMs: number = Date.now()): boolean {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: this.options.capacity, lastSeenMs: nowMs };
      this.buckets.set(key, bucket);
    }
    const elapsedSeconds = Math.max(0, nowMs - bucket.lastSeenMs) / 1000;
    bucket.tokens = Math.min(this.options.capacity, bucket.tokens + elapsedSeconds * this.options.refillPerSecond);
    bucket.lastSeenMs = nowMs;
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  }

  /**
   * Drop buckets idle longer than `idleMs`. Without this, every distinct key
   * ever seen stays resident — a slow memory leak wearing a security feature.
   */
  sweep(nowMs: number = Date.now(), idleMs = 10 * 60_000): void {
    this.buckets.forEach((bucket, key) => {
      if (nowMs - bucket.lastSeenMs > idleMs) this.buckets.delete(key);
    });
  }

  get size(): number {
    return this.buckets.size;
  }
}
