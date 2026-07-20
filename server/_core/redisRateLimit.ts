/**
 * Redis-backed token bucket — the fleet-wide rate limiter.
 *
 * Why this exists: the in-process TokenBucketLimiter multiplies the intended
 * budget by the replica count (each pod has its own buckets). This limiter
 * keeps one bucket per key in Redis, shared by every replica, evaluated
 * atomically in a single Lua script so two pods cannot both spend the last
 * token.
 *
 * Failure posture: the connection is configured to FAIL FAST (no offline
 * queue, bounded retries) so a Redis outage surfaces as a rejected promise
 * in ~milliseconds — which ResilientRateLimiter converts into per-pod
 * degradation. A hanging limiter would be worse than no limiter: it would
 * stall every ingest request behind Redis reconnection attempts.
 */
import Redis from "ioredis";
import type { AsyncRateLimiter } from "./rateLimit";
import { logger } from "./logger";

const log = logger.child({ component: "redis-rate-limit" });

/**
 * Atomic check-and-consume. State per key: tokens + last-refill timestamp,
 * refilled lazily on access. The caller supplies now-ms (small cross-pod
 * clock skew only distorts refill by the skew amount, bounded and
 * self-correcting; using client time keeps the script deterministic for
 * Redis script replication). PEXPIRE makes idle buckets self-cleaning —
 * the distributed equivalent of the local limiter's sweep().
 */
const TOKEN_BUCKET_LUA = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(bucket[1])
local ts = tonumber(bucket[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now_ms
end

local elapsed = now_ms - ts
if elapsed < 0 then elapsed = 0 end
tokens = tokens + elapsed * refill_per_ms
if tokens > capacity then tokens = capacity end

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now_ms)
redis.call('PEXPIRE', key, ttl_ms)
return allowed
`;

type RedisWithTokenBucket = Redis & {
  tokenBucket(key: string, capacity: number, refillPerMs: number, nowMs: number, ttlMs: number): Promise<number>;
};

export type RedisTokenBucketOptions = {
  redisUrl: string;
  capacity: number;
  refillPerSecond: number;
  /** Key namespace, e.g. "srl:ingest:" — one namespace per protected surface. */
  prefix: string;
};

export class RedisTokenBucketLimiter implements AsyncRateLimiter {
  private readonly client: RedisWithTokenBucket;
  private readonly ttlMs: number;

  constructor(private readonly options: RedisTokenBucketOptions) {
    if (
      !Number.isFinite(options.capacity) ||
      options.capacity < 1 ||
      !Number.isFinite(options.refillPerSecond) ||
      options.refillPerSecond <= 0
    ) {
      throw new Error("RedisTokenBucketLimiter requires finite capacity >= 1 and refillPerSecond > 0");
    }
    this.client = new Redis(options.redisUrl, {
      maxRetriesPerRequest: 2,
      enableOfflineQueue: false,
      // Hard per-command deadline. This is the guard connection-state
      // tracking cannot provide: in a black-hole partition (no FIN/RST —
      // node loss, silent firewall drop) the socket stays "ready", so
      // enableOfflineQueue never rejects and a command would otherwise wait
      // out the OS TCP-retransmission timeout (minutes) while every ingest
      // request hangs behind it. The timeout rejects instead, which
      // ResilientRateLimiter converts into per-pod degradation.
      commandTimeout: 1_000,
      // Short connect attempts so commands in flight at a DETECTED
      // disconnect flush after ~1.5s of reconnect probing, not after
      // multiple 10s default connect timeouts.
      connectTimeout: 2_000,
      // Reconnect quietly in the background; commands fail fast meanwhile.
      retryStrategy: (times) => Math.min(times * 500, 5_000),
    }) as RedisWithTokenBucket;
    // ioredis emits 'error' events; without a listener they become uncaught
    // exceptions and kill the process. Per-command failures already reject
    // and are handled by ResilientRateLimiter, so the event is log-only.
    this.client.on("error", (error) => log.debug("redis connection error (degrading to local limiter)", { message: error.message }));
    this.client.defineCommand("tokenBucket", { numberOfKeys: 1, lua: TOKEN_BUCKET_LUA });
    // TTL: time for an idle bucket to refill completely, plus margin. After
    // that the stored state is indistinguishable from a fresh full bucket.
    this.ttlMs = Math.ceil((options.capacity / options.refillPerSecond) * 1_000) + 60_000;
  }

  async tryConsume(key: string): Promise<boolean> {
    const allowed = await this.client.tokenBucket(
      `${this.options.prefix}${key}`,
      this.options.capacity,
      this.options.refillPerSecond / 1_000,
      Date.now(),
      this.ttlMs,
    );
    return allowed === 1;
  }

  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }
}
