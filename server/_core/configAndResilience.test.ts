import { afterEach, describe, expect, it } from "vitest";
import { resolveDefaultRole, validateEnv } from "./env";
import { ResilientRateLimiter, TokenBucketLimiter, type AsyncRateLimiter } from "./rateLimit";

const GOOD_SECRET = "a-perfectly-reasonable-session-secret-with-length";

describe("validateEnv", () => {
  it("fails production boot on missing or weak JWT_SECRET", () => {
    const missing = validateEnv({ NODE_ENV: "production", DATABASE_URL: "mysql://u:p@h/db" });
    expect(missing.some((i) => i.level === "fatal" && i.message.includes("JWT_SECRET"))).toBe(true);

    const short = validateEnv({ NODE_ENV: "production", JWT_SECRET: "short", DATABASE_URL: "mysql://u:p@h/db" });
    expect(short.some((i) => i.level === "fatal" && i.message.includes("32"))).toBe(true);
  });

  it("rejects placeholder secrets in every environment", () => {
    const issues = validateEnv({ NODE_ENV: "development", JWT_SECRET: "changeme" });
    expect(issues.some((i) => i.level === "fatal" && i.message.includes("placeholder"))).toBe(true);
  });

  it("downgrades missing config to warnings outside production", () => {
    const issues = validateEnv({ NODE_ENV: "development" });
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.every((i) => i.level === "warn")).toBe(true);
  });

  it("accepts a fully-provisioned production environment with only advisory warnings", () => {
    const issues = validateEnv({
      NODE_ENV: "production",
      JWT_SECRET: GOOD_SECRET,
      DATABASE_URL: "mysql://svc_user:8charM1n@db.internal:3306/sentinelx",
      REDIS_URL: "redis://redis:6379",
      OAUTH_SERVER_URL: "https://auth.example.com",
    });
    expect(issues.filter((i) => i.level === "fatal")).toEqual([]);
  });

  it("flags default database credentials in production as a warning", () => {
    const issues = validateEnv({
      NODE_ENV: "production",
      JWT_SECRET: GOOD_SECRET,
      DATABASE_URL: "mysql://root:password@db:3306/sentinelx",
      REDIS_URL: "redis://redis:6379",
      OAUTH_SERVER_URL: "https://auth.example.com",
    });
    expect(issues.some((i) => i.level === "warn" && i.message.includes("default credential"))).toBe(true);
    expect(issues.filter((i) => i.level === "fatal")).toEqual([]);
  });
});

describe("resolveDefaultRole", () => {
  afterEach(() => {
    delete process.env.DEFAULT_NEW_USER_ROLE;
  });

  it("defaults to analyst when unset", () => {
    delete process.env.DEFAULT_NEW_USER_ROLE;
    expect(resolveDefaultRole()).toBe("analyst");
  });

  it("honors a valid configured role", () => {
    process.env.DEFAULT_NEW_USER_ROLE = "viewer";
    expect(resolveDefaultRole()).toBe("viewer");
  });

  it("degrades a garbage value to analyst rather than a higher tier", () => {
    process.env.DEFAULT_NEW_USER_ROLE = "superadmin";
    expect(resolveDefaultRole()).toBe("analyst");
  });
});

describe("ResilientRateLimiter", () => {
  const failingPrimary: AsyncRateLimiter = {
    tryConsume: async () => {
      throw new Error("redis unreachable");
    },
  };

  it("uses the primary verdict when it is healthy", async () => {
    const primary: AsyncRateLimiter = { tryConsume: async () => false };
    const fallback = new TokenBucketLimiter({ capacity: 10, refillPerSecond: 1 });
    const limiter = new ResilientRateLimiter(primary, fallback);
    // Primary says throttled; the (full) fallback bucket must NOT override it.
    expect(await limiter.tryConsume("k")).toBe(false);
  });

  it("degrades to the local bucket when the primary throws, and reports it", async () => {
    const fallback = new TokenBucketLimiter({ capacity: 2, refillPerSecond: 1 });
    const reported: unknown[] = [];
    const limiter = new ResilientRateLimiter(failingPrimary, fallback, (e) => reported.push(e));

    expect(await limiter.tryConsume("k")).toBe(true);
    expect(await limiter.tryConsume("k")).toBe(true);
    expect(await limiter.tryConsume("k")).toBe(false); // local budget enforced
    expect(reported).toHaveLength(3); // every degraded call reported (caller throttles logging)
  });
});
