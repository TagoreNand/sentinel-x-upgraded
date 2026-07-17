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
