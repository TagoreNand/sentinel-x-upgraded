import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from '@shared/const';
import { roleAtLeast, type Role } from '@shared/roles';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import { AppError } from "./errors";
import { ENV, envNumber } from "./env";
import { logger } from "./logger";
import { ResilientRateLimiter, TokenBucketLimiter, type AsyncRateLimiter } from "./rateLimit";
import { RedisTokenBucketLimiter } from "./redisRateLimit";

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
  /**
   * Client-facing error hygiene: unexpected server errors (anything that is
   * not a deliberate TRPCError) must never leak internals — SQL fragments,
   * file paths, or stack frames are reconnaissance gifts on a security
   * product. AppError subclasses carry an explicit `safeMessage`; everything
   * else collapses to a generic message in production. Full diagnostics are
   * logged server-side by the adapter's onError hook.
   */
  errorFormatter({ shape, error }) {
    if (ENV.isProduction && error.code === "INTERNAL_SERVER_ERROR") {
      const safeMessage = error.cause instanceof AppError ? error.cause.safeMessage : "An internal error occurred.";
      return {
        ...shape,
        message: safeMessage,
        data: { ...shape.data, stack: undefined },
      };
    }
    return shape;
  },
});

export const router = t.router;
export const publicProcedure = t.procedure;

const requireUser = t.middleware(async opts => {
  const { ctx, next } = opts;

  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
    },
  });
});

/** Any authenticated user (viewer and above). Use for read-only queries. */
export const protectedProcedure = t.procedure.use(requireUser);

/**
 * Minimum-tier gate over the total role ordering. Because the hierarchy is
 * totally ordered, a single rank comparison enforces "this tier or higher" —
 * `admin` satisfies `requireRole('analyst')` for free, and there is no way to
 * grant a capability to a lower tier without also granting it to every tier
 * above. The user is re-narrowed into ctx so downstream resolvers see a
 * non-null `user`.
 */
function requireRole(minRole: Role) {
  return t.middleware(async ({ ctx, next }) => {
    if (!ctx.user) {
      throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
    }
    if (!roleAtLeast(ctx.user.role, minRole)) {
      throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }
    return next({ ctx: { ...ctx, user: ctx.user } });
  });
}

/** Investigative mutations: ingest, incidents, evidence, IOCs, scans. */
export const analystProcedure = t.procedure.use(requireRole("analyst"));
/** Privileged: IDS rule authoring (pipeline-executed) and SOAR orchestration. */
export const leadProcedure = t.procedure.use(requireRole("lead"));
/** Platform governance: user role management, audit logs, seed/destructive ops. */
export const adminProcedure = t.procedure.use(requireRole("admin"));

/**
 * Rate-limited procedure for ingestion endpoints.
 *
 * The detection pipeline does real work per event (enrichment queries, rule
 * evaluation, transactional writes). Unthrottled, one misconfigured log
 * shipper can saturate the pool for every analyst on the platform. Budget is
 * per authenticated user (fallback: source IP), tuned via env so ops can
 * raise it without a deploy. TOO_MANY_REQUESTS maps to HTTP 429 — a signal
 * well-behaved shippers already understand as "back off and retry".
 */
const rlLog = logger.child({ component: "ingest-rate-limit" });
const bucketConfig = {
  capacity: envNumber("INGEST_RATE_BURST", 20),
  refillPerSecond: envNumber("INGEST_RATE_PER_SECOND", 5),
};

const localLimiter = new TokenBucketLimiter(bucketConfig);
// unref() so the sweep timer never holds the process open during shutdown.
setInterval(() => localLimiter.sweep(), 60_000).unref();

// Redis makes the budget fleet-wide (one bucket per caller across every
// replica); without it the budget silently multiplies by replica count —
// fine for dev/single-node, warned about by boot validation in production.
// On Redis failure, ResilientRateLimiter degrades to the per-pod bucket and
// this throttled warning is the operator's signal.
let degradedWarnAt = 0;
let redisLimiter: RedisTokenBucketLimiter | null = null;
let ingestLimiter: AsyncRateLimiter;
if (process.env.REDIS_URL) {
  redisLimiter = new RedisTokenBucketLimiter({
    redisUrl: process.env.REDIS_URL,
    ...bucketConfig,
    prefix: "srl:ingest:",
  });
  ingestLimiter = new ResilientRateLimiter(redisLimiter, localLimiter, (error) => {
    const now = Date.now();
    if (now - degradedWarnAt > 30_000) {
      degradedWarnAt = now;
      rlLog.warn("redis rate limiter unreachable — degraded to per-pod limiting", {
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  });
} else {
  ingestLimiter = { tryConsume: async (key) => localLimiter.tryConsume(key) };
}

/** Shutdown hook: closes the limiter's Redis connection, if one exists. */
export async function closeIngestRateLimiter(): Promise<void> {
  await redisLimiter?.close();
}

// Ingestion is an analyst-tier mutation (it creates events, detections, and
// incidents) AND rate-limited — so it composes the analyst gate with the
// throttle. A viewer is rejected with FORBIDDEN before a token is spent.
export const ingestProcedure = analystProcedure.use(
  t.middleware(async ({ ctx, next }) => {
    const key = ctx.user ? `user:${ctx.user.id}` : `ip:${ctx.req.ip ?? "unknown"}`;
    if (!(await ingestLimiter.tryConsume(key))) {
      throw new TRPCError({
        code: "TOO_MANY_REQUESTS",
        message: "Ingestion rate limit exceeded. Batch events or reduce request rate.",
      });
    }
    return next();
  }),
);
