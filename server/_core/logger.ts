/**
 * Structured JSON logger for Sentinel-X.
 *
 * Design decisions:
 * - Single-line JSON to stdout, per Twelve-Factor: the process never manages
 *   log files or transports; the platform (Docker/K8s/CloudWatch/Loki) owns
 *   aggregation. Every line is machine-parseable so a 3 AM incident query is
 *   `{app="sentinel-x"} | json | level="error"` instead of regex archaeology.
 * - Zero dependencies. This keeps the security surface of the logging path
 *   empty and the module usable from any entrypoint (server, scripts, tests).
 *   If throughput ever makes JSON.stringify a measurable cost, swap the sink
 *   for pino — the call-site API below is deliberately pino-shaped so that
 *   migration is mechanical.
 * - Child loggers carry bound context (component, requestId, eventId) so the
 *   pipeline can emit correlated lines without threading strings by hand.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export type LogFields = Record<string, unknown>;

function resolveMinLevel(): number {
  const configured = (process.env.LOG_LEVEL ?? "info").toLowerCase() as LogLevel;
  return LEVEL_WEIGHT[configured] ?? LEVEL_WEIGHT.info;
}

/**
 * Errors do not JSON.stringify (message/stack are non-enumerable), so they are
 * serialized explicitly. Stack traces stay in server logs only — they must
 * never ride an error object into a client-facing response.
 */
function serializeError(error: unknown): LogFields {
  if (error instanceof Error) {
    return {
      errorName: error.name,
      errorMessage: error.message,
      stack: error.stack,
      ...(error.cause ? { cause: String(error.cause) } : {}),
    };
  }
  return { errorMessage: String(error) };
}

export class Logger {
  private readonly context: LogFields;
  private readonly minLevel: number;

  constructor(context: LogFields = {}, minLevel: number = resolveMinLevel()) {
    this.context = context;
    this.minLevel = minLevel;
  }

  /** Returns a logger that stamps every line with the given bound fields. */
  child(context: LogFields): Logger {
    return new Logger({ ...this.context, ...context }, this.minLevel);
  }

  debug(msg: string, fields?: LogFields): void {
    this.write("debug", msg, fields);
  }

  info(msg: string, fields?: LogFields): void {
    this.write("info", msg, fields);
  }

  warn(msg: string, fields?: LogFields): void {
    this.write("warn", msg, fields);
  }

  error(msg: string, error?: unknown, fields?: LogFields): void {
    this.write("error", msg, {
      ...(error !== undefined ? serializeError(error) : {}),
      ...fields,
    });
  }

  /**
   * Stage-timing helper: `const done = log.startTimer(); ...; done("db.insert")`
   * emits a duration line. Durations are what turn "the pipeline is slow" into
   * "IOC lookup p99 regressed 40ms after Tuesday's deploy".
   */
  startTimer(): (msg: string, fields?: LogFields) => void {
    const startedAt = process.hrtime.bigint();
    return (msg, fields) => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      this.info(msg, { durationMs: Math.round(durationMs * 100) / 100, ...fields });
    };
  }

  private write(level: LogLevel, msg: string, fields?: LogFields): void {
    if (LEVEL_WEIGHT[level] < this.minLevel) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      msg,
      service: "sentinel-x",
      ...this.context,
      ...fields,
    });
    // stdout for the event stream; stderr is reserved for the runtime itself.
    process.stdout.write(line + "\n");
  }
}

export const logger = new Logger();
