import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { closeDb, pingDb } from "../db";
import { closeIngestQueue, initIngestQueue } from "../queue/ingestQueue";
import { validateEnv } from "./env";
import { closeIngestRateLimiter } from "./trpc";
import { logger } from "./logger";

const log = logger.child({ component: "server" });

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

async function startServer() {
  // Config contract check before anything binds or connects. A production
  // pod with a missing/placeholder secret must CrashLoopBackOff with a named
  // reason — not come up Ready and mint unsigned sessions.
  const envIssues = validateEnv();
  for (const issue of envIssues) {
    if (issue.level === "fatal") log.error(`config: ${issue.message}`);
    else log.warn(`config: ${issue.message}`);
  }
  if (envIssues.some((issue) => issue.level === "fatal")) {
    log.error("fatal configuration errors — refusing to start");
    process.exit(1);
  }

  const app = express();
  const server = createServer(app);
  // Configure body parser with larger size limit for file uploads
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));

  /**
   * Kubernetes probe endpoints — registered before everything else so a
   * wedged Vite middleware or slow static handler can never shadow them.
   *
   * - /healthz (liveness): "the event loop is alive". Deliberately does NOT
   *   check the database — restarting a pod does not fix a down database,
   *   and coupling liveness to dependencies turns a DB blip into a
   *   fleet-wide crash loop.
   * - /readyz (readiness): "safe to route traffic to me". DOES check the
   *   database with a bounded ping; while it fails, the pod is pulled from
   *   the Service and traffic goes to healthy replicas.
   */
  app.get("/healthz", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });
  app.get("/readyz", async (_req, res) => {
    try {
      await pingDb(2000);
      res.status(200).json({ status: "ready" });
    } catch (error) {
      log.warn("readiness check failed", { reason: error instanceof Error ? error.message : String(error) });
      res.status(503).json({ status: "unavailable" });
    }
  });

  // OAuth callback under /api/oauth/callback
  registerOAuthRoutes(app);
  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
      // Server-side error visibility: the errorFormatter sanitizes what the
      // client sees, so this hook is where the full failure (path, user,
      // stack) lands in the structured log stream.
      onError({ error, path, type, ctx }) {
        log.error("trpc request failed", error, {
          path,
          type,
          code: error.code,
          userId: ctx?.user?.id,
        });
      },
    })
  );
  // development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const preferredPort = parseInt(process.env.PORT || "3000");

  /**
   * Port policy differs by environment on purpose:
   * - development: hunting for a free port is a convenience.
   * - production: the container contract says "listen on $PORT". Silently
   *   binding elsewhere means the Service/probes point at a port nobody is
   *   listening on — the pod looks Running and serves nothing. Fail fast and
   *   let the orchestrator surface a CrashLoopBackOff instead.
   */
  let port = preferredPort;
  if (process.env.NODE_ENV === "development") {
    port = await findAvailablePort(preferredPort);
    if (port !== preferredPort) {
      log.warn("preferred port busy, using fallback", { preferredPort, port });
    }
  }

  server.on("error", (error) => {
    log.error("http server error", error);
    process.exit(1);
  });

  // Non-blocking: Redis (if configured) connects in the background; a queue
  // transport outage degrades ingestion throughput, not API availability.
  initIngestQueue();

  server.listen(port, () => {
    log.info("server listening", { port, env: process.env.NODE_ENV ?? "unknown" });
  });

  /**
   * Graceful shutdown: on SIGTERM (the normal K8s pod-termination signal),
   * stop accepting new connections, let in-flight requests finish, then
   * close the DB pool. The hard deadline guarantees we never hang past the
   * pod's terminationGracePeriod and get SIGKILLed mid-write.
   */
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info("shutdown initiated", { signal });

    const forceExit = setTimeout(() => {
      log.error("graceful shutdown deadline exceeded, forcing exit");
      process.exit(1);
    }, 10_000);
    forceExit.unref();

    server.close(async () => {
      try {
        // Queue first (drains in-flight jobs that still need the DB), then
        // the pool. Reversed order would strand mid-job workers without a
        // database.
        await closeIngestQueue();
        await closeIngestRateLimiter();
        await closeDb();
        log.info("shutdown complete");
        process.exit(0);
      } catch (error) {
        log.error("error during shutdown", error);
        process.exit(1);
      }
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  /**
   * Last-resort handlers. An unhandled rejection means unknown state — log
   * it loudly. We do not exit on unhandledRejection (Node's default in
   * recent versions is to crash; for a SOC dashboard, degraded-but-observed
   * beats a crash loop), but uncaughtException leaves the process
   * unrecoverable and must exit so the orchestrator replaces the pod.
   */
  process.on("unhandledRejection", (reason) => {
    log.error("unhandled promise rejection", reason);
  });
  process.on("uncaughtException", (error) => {
    log.error("uncaught exception, exiting", error);
    process.exit(1);
  });
}

startServer().catch((error) => {
  log.error("server failed to start", error);
  process.exit(1);
});
