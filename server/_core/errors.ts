/**
 * Typed server-side error taxonomy.
 *
 * Two rules enforced here:
 * 1. Every operational failure carries a stable machine-readable `code` so
 *    alerting can key on error classes, not string-matching log messages.
 * 2. Every error separates `message` (internal, may contain identifiers and
 *    diagnostic context — logs only) from `safeMessage` (what a client is
 *    allowed to see). The tRPC error formatter relies on this split; nothing
 *    internal ever reaches the wire.
 */

export type AppErrorCode =
  | "DB_UNAVAILABLE"
  | "PIPELINE_FAILURE"
  | "RULE_INVALID"
  | "RATE_LIMITED";

export class AppError extends Error {
  public readonly code: AppErrorCode;
  public readonly safeMessage: string;
  public readonly context: Record<string, unknown>;

  constructor(
    code: AppErrorCode,
    message: string,
    options?: { safeMessage?: string; context?: Record<string, unknown>; cause?: unknown },
  ) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.code = code;
    this.safeMessage = options?.safeMessage ?? "An internal error occurred.";
    this.context = options?.context ?? {};
  }
}

/**
 * The database is not reachable/configured. Deliberately maps to "temporarily
 * unavailable" semantics: readiness probes flip, the pod is pulled from the
 * Service, and callers get a retryable signal — never a silent no-op write.
 */
export class DatabaseUnavailableError extends AppError {
  constructor(message = "Database is not available", context?: Record<string, unknown>) {
    super("DB_UNAVAILABLE", message, {
      safeMessage: "Service temporarily unavailable. Please retry.",
      context,
    });
  }
}

/** A failure inside the ingestion/detection pipeline, tagged with the stage. */
export class PipelineError extends AppError {
  public readonly stage: string;

  constructor(stage: string, message: string, options?: { cause?: unknown; context?: Record<string, unknown> }) {
    super("PIPELINE_FAILURE", message, {
      safeMessage: "Event ingestion failed. The event was not recorded.",
      context: { stage, ...options?.context },
      cause: options?.cause,
    });
    this.stage = stage;
  }
}
