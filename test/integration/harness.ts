/**
 * Integration-test harness: a real MySQL, real migrations, real driver.
 *
 * Unit tests prove pure logic; they cannot catch the class of bug that has
 * dominated this project's reviews — driver return shapes ($returningId vs
 * the raw insertId tuple), CLIENT_FOUND_ROWS affecting affectedRows, and enum
 * coercion during migration. Those only surface against a live server. This
 * harness stands one up.
 *
 * Two backends, chosen automatically:
 * - INTEGRATION_DATABASE_URL set → connect to it (CI service container).
 * - otherwise → testcontainers spins up mysql:8 (local dev).
 * When neither Docker nor a URL is available the suites skip (see
 * integrationDbAvailable) so `pnpm test` never depends on Docker.
 */
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import mysql from "mysql2/promise";
import { closeDb } from "../../server/db";

const MIGRATIONS_DIR = path.resolve(process.cwd(), "drizzle");

/** Synchronous availability probe, so `describe.skipIf` can use it at collect time. */
export function integrationDbAvailable(): boolean {
  if (process.env.INTEGRATION_DATABASE_URL) return true;
  try {
    execSync("docker info", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

type JournalEntry = { idx: number; tag: string };

function migrationTags(): string[] {
  const journal = JSON.parse(readFileSync(path.join(MIGRATIONS_DIR, "meta", "_journal.json"), "utf8")) as {
    entries: JournalEntry[];
  };
  return [...journal.entries].sort((a, b) => a.idx - b.idx).map((e) => e.tag);
}

/**
 * Apply migration SQL files in journal order, splitting each on drizzle's
 * `--> statement-breakpoint` marker.
 * - upToTag (inclusive): stop after this migration.
 * - afterTag (exclusive): skip everything up to and including this migration,
 *   so a test can apply the base schema, seed legacy data, then apply the
 *   remaining migrations — used to exercise the 0005 role-enum remap on rows
 *   that predate it.
 */
export async function runMigrations(url: string, opts: { upToTag?: string; afterTag?: string } = {}): Promise<void> {
  const conn = await mysql.createConnection({ uri: url, multipleStatements: false });
  try {
    let applying = opts.afterTag === undefined;
    for (const tag of migrationTags()) {
      if (!applying) {
        if (tag === opts.afterTag) applying = true;
        continue;
      }
      const sql = readFileSync(path.join(MIGRATIONS_DIR, `${tag}.sql`), "utf8");
      const statements = sql
        .split("--> statement-breakpoint")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      for (const statement of statements) {
        await conn.query(statement);
      }
      if (tag === opts.upToTag) break;
    }
  } finally {
    await conn.end();
  }
}

export type IntegrationDb = {
  url: string;
  /** Fresh mysql2 connection for arranging fixtures / asserting raw rows. */
  connect: () => Promise<mysql.Connection>;
  teardown: () => Promise<void>;
};

/**
 * Boot a migrated database and point the app's db layer (process.env
 * DATABASE_URL) at it. Returns a teardown that closes the app pool and stops
 * the container. `migrateUpTo` defers the final migrations for tests that
 * need to seed pre-migration state.
 */
export async function setupIntegrationDb(options: { migrateUpTo?: string } = {}): Promise<IntegrationDb> {
  let url = process.env.INTEGRATION_DATABASE_URL;
  let stopContainer = async () => {};

  if (!url) {
    const { MySqlContainer } = await import("@testcontainers/mysql");
    const container = await new MySqlContainer("mysql:8.0").withDatabase("sentinelx").start();
    url = container.getConnectionUri();
    stopContainer = async () => {
      await container.stop();
    };
  }

  // Isolate this run's data on a fresh schema so repeated CI runs against a
  // persistent service container never see each other's rows.
  const admin = await mysql.createConnection({ uri: url });
  const schema = `sx_it_${Date.now().toString(36)}`;
  await admin.query(`CREATE DATABASE IF NOT EXISTS \`${schema}\``);
  await admin.end();
  const runUrl = withDatabase(url, schema);

  await runMigrations(runUrl, { upToTag: options.migrateUpTo });

  process.env.DATABASE_URL = runUrl;

  return {
    url: runUrl,
    connect: () => mysql.createConnection({ uri: runUrl }),
    teardown: async () => {
      await closeDb();
      const drop = await mysql.createConnection({ uri: url! });
      await drop.query(`DROP DATABASE IF EXISTS \`${schema}\``);
      await drop.end();
      await stopContainer();
    },
  };
}

/** Swap (or append) the database segment of a mysql:// URL. */
function withDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}
