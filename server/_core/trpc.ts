import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from '@shared/const';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import { AppError } from "./errors";
import { ENV, envNumber } from "./env";
import { TokenBucketLimiter } from "./rateLimit";

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

export const protectedProcedure = t.procedure.use(requireUser);

export const adminProcedure = t.procedure.use(
  t.middleware(async opts => {
    const { ctx, next } = opts;

    if (!ctx.user || ctx.user.role !== 'admin') {
      throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }

    return next({
      ctx: {
        ...ctx,
        user: ctx.user,
      },
    });
  }),
);

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
const ingestLimiter = new TokenBucketLimiter({
  capacity: envNumber("INGEST_RATE_BURST", 20),
  refillPerSecond: envNumber("INGEST_RATE_PER_SECOND", 5),
});
// unref() so the sweep timer never holds the process open during shutdown.
setInterval(() => ingestLimiter.sweep(), 60_000).unref();

export const ingestProcedure = protectedProcedure.use(
  t.middleware(async ({ ctx, next }) => {
    const key = ctx.user ? `user:${ctx.user.id}` : `ip:${ctx.req.ip ?? "unknown"}`;
    if (!ingestLimiter.tryConsume(key)) {
      throw new TRPCError({
        code: "TOO_MANY_REQUESTS",
        message: "Ingestion rate limit exceeded. Batch events or reduce request rate.",
      });
    }
    return next();
  }),
);
