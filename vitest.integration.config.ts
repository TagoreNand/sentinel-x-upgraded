import { defineConfig } from "vitest/config";
import path from "path";

const templateRoot = path.resolve(import.meta.dirname);

/**
 * Integration tests run separately from the fast unit suite: they need a real
 * MySQL (testcontainers or INTEGRATION_DATABASE_URL), so they carry a long
 * timeout and run single-threaded to avoid contending for the container on
 * spin-up. `pnpm test` never loads this config.
 */
export default defineConfig({
  root: templateRoot,
  resolve: {
    alias: {
      "@": path.resolve(templateRoot, "client", "src"),
      "@shared": path.resolve(templateRoot, "shared"),
      "@assets": path.resolve(templateRoot, "attached_assets"),
    },
  },
  test: {
    environment: "node",
    include: ["**/*.integration.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 180_000,
    fileParallelism: false,
    // Captured by server/_core/env.ts (ENV) at import time, so it must be set
    // before the worker loads any server module — vitest applies test.env
    // before test files are collected.
    env: {
      OWNER_OPEN_ID: "integration-owner",
      DEFAULT_NEW_USER_ROLE: "analyst",
      LOG_LEVEL: "error",
    },
  },
});
