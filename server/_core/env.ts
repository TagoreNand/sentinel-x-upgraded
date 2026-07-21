export const ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
};

import { isRole, type Role } from "@shared/roles";

/**
 * Role assigned to a brand-new authenticated user on first login. Defaults to
 * `analyst` (can investigate immediately) rather than `viewer`, so onboarding
 * is not a locked-out experience; a stricter deployment can set
 * DEFAULT_NEW_USER_ROLE=viewer and have an admin promote explicitly. A typo'd
 * value degrades to the safe default with a warning — never to an unintended
 * higher tier.
 */
export function resolveDefaultRole(): Role {
  const raw = process.env.DEFAULT_NEW_USER_ROLE;
  if (raw === undefined || raw === "") return "analyst";
  if (isRole(raw)) return raw;
  console.warn(`[env] DEFAULT_NEW_USER_ROLE="${raw}" is not a valid role; using default 'analyst'`);
  return "analyst";
}

export type EnvIssue = { level: "fatal" | "warn"; message: string };

const PLACEHOLDER_SECRET = /^(changeme|change-me|secret|password|example|placeholder|test|xxx+|todo)$/i;

/**
 * Boot-time configuration validation. The contract with the secret store
 * (Vault / AWS Secrets Manager / ExternalSecrets → k8s Secret → env) is that
 * secrets ARRIVE as environment variables — which means a broken secret
 * mount looks exactly like a typo'd .env. In production that must be a
 * refused boot with a named reason, not a pod that comes up Ready and mints
 * unsigned sessions. Pure function over an env snapshot so it is testable.
 */
export function validateEnv(env: NodeJS.ProcessEnv = process.env): EnvIssue[] {
  const issues: EnvIssue[] = [];
  const isProd = env.NODE_ENV === "production";
  const prodFatal = isProd ? "fatal" : "warn";

  const jwtSecret = env.JWT_SECRET ?? "";
  if (!jwtSecret) {
    issues.push({ level: prodFatal, message: "JWT_SECRET is not set — sessions cannot be signed; provision it from the secret store" });
  } else if (PLACEHOLDER_SECRET.test(jwtSecret)) {
    issues.push({ level: "fatal", message: "JWT_SECRET is a placeholder value — generate a real secret (e.g. openssl rand -base64 48)" });
  } else if (jwtSecret.length < 32) {
    issues.push({ level: prodFatal, message: "JWT_SECRET is shorter than 32 characters — too weak for HMAC session signing" });
  }

  if (!env.DATABASE_URL) {
    issues.push({ level: prodFatal, message: "DATABASE_URL is not set — persistence and readiness will fail" });
  } else if (isProd && /:(password|root|changeme|secret)@/i.test(env.DATABASE_URL)) {
    issues.push({ level: "warn", message: "DATABASE_URL appears to use a default credential — rotate it and source it from the secret store" });
  }

  if (isProd && !env.REDIS_URL) {
    issues.push({ level: "warn", message: "REDIS_URL is not set — ingestion queue and rate limiting degrade to per-pod in-memory mode" });
  }
  if (isProd && !env.OAUTH_SERVER_URL) {
    issues.push({ level: "warn", message: "OAUTH_SERVER_URL is not set — interactive login is unavailable" });
  }

  return issues;
}

/**
 * Parse a positive numeric env var, falling back on absence OR garbage.
 * `Number("abc")` is NaN and NaN slips through every `<`/`<=` guard, so raw
 * `Number(process.env.X ?? default)` turns a config typo into undefined
 * behavior (a disabled rate limiter, a NaN-sized connection pool). A typo
 * degrades to the safe default and a loud log line — not to silence.
 */
export function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    // console over logger: env.ts sits at the bottom of the import graph and
    // must stay dependency-free to prevent cycles.
    console.warn(`[env] ${name}="${raw}" is not a positive number; using default ${fallback}`);
    return fallback;
  }
  return parsed;
}
