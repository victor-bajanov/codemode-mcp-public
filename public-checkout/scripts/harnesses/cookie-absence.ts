/**
 * I4 cookie-absence harness.
 *
 * Boots `wrangler dev` from `apps/gmail/` with no COOKIE_ENCRYPTION_KEY in
 * scope, hits the worker root, and asserts:
 *
 *   1. status is 500 (the assertSecrets() throw propagates as a 500).
 *   2. the response body contains "COOKIE_ENCRYPTION_KEY" and
 *      "wrangler secret put" — the actionable remedy.
 *
 * Stripping the secret without permanently mutating the operator's
 * environment: if `apps/gmail/.dev.vars` exists, move it aside to
 * `/tmp/codemode-harness-<pid>/.dev.vars.backup` and write a copy with the
 * `COOKIE_ENCRYPTION_KEY=` line removed. Restore on cleanup (try/finally,
 * plus SIGINT/SIGTERM handlers). If `.dev.vars` doesn't exist there's
 * nothing to back up — we just spawn wrangler dev with an env that doesn't
 * have COOKIE_ENCRYPTION_KEY set.
 *
 * The harness reports the backup path in its output so the operator can
 * manually restore if a crash beats the cleanup.
 */
import {
  copyFile,
  mkdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { spawnWrangler, type SpawnedWrangler } from "./lib/spawn-wrangler.js";
import { dumpTail, printAssertions, summary, type Assertion } from "./lib/report.js";

interface Args {
  port: number;
}

const USAGE = `Usage: pnpm harness:cookie [options]

Options:
  --port=<n>   Port for wrangler dev. Default 8787
  --help       Print this help and exit.
`;

function parseArgs(argv: readonly string[]): Args {
  let port = 8787;
  for (const raw of argv) {
    if (raw === "--help" || raw === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    }
    // Skip a standalone "--" separator (pnpm 9 forwards it; `op run … --`
    // doesn't strip its own). Either way it's just a delimiter.
    if (raw === "--") {
      continue;
    }
    const eq = raw.indexOf("=");
    if (eq < 0) {
      throw new Error(`Unrecognised argument: ${raw}\n${USAGE}`);
    }
    const key = raw.slice(0, eq);
    const value = raw.slice(eq + 1);
    if (key === "--port") {
      const n = Number.parseInt(value, 10);
      if (!Number.isFinite(n) || n <= 0 || n > 65535) {
        throw new Error(`Invalid --port: ${value}`);
      }
      port = n;
    } else {
      throw new Error(`Unrecognised argument: ${raw}\n${USAGE}`);
    }
  }
  return { port };
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");
const GMAIL_APP_CWD = path.join(REPO_ROOT, "apps", "gmail");
const DEV_VARS_PATH = path.join(GMAIL_APP_CWD, ".dev.vars");
const BACKUP_DIR = path.join(tmpdir(), `codemode-harness-${process.pid}`);
const BACKUP_PATH = path.join(BACKUP_DIR, ".dev.vars.backup");

/**
 * Filter the lines of a `.dev.vars` file to drop COOKIE_ENCRYPTION_KEY=...
 * entries while preserving everything else (GOOGLE_CLIENT_ID etc).
 * `.dev.vars` is a dotenv-style KEY=VALUE list; comments start with `#`.
 */
function stripCookieKey(contents: string): string {
  const out: string[] = [];
  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.replace(/^\s+/, "");
    if (trimmed.startsWith("COOKIE_ENCRYPTION_KEY=") || trimmed.startsWith("COOKIE_ENCRYPTION_KEY ")) {
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}

interface PreparedState {
  backedUp: boolean;
}

async function stageNoSecretEnv(): Promise<PreparedState> {
  await mkdir(BACKUP_DIR, { recursive: true });
  let backedUp = false;
  if (existsSync(DEV_VARS_PATH)) {
    // Use copyFile + then overwrite so the original inode is preserved.
    await copyFile(DEV_VARS_PATH, BACKUP_PATH);
    backedUp = true;
    const original = await readFile(DEV_VARS_PATH, "utf8");
    const stripped = stripCookieKey(original);
    await writeFile(DEV_VARS_PATH, stripped, "utf8");
  }
  return { backedUp };
}

async function restoreSecretEnv(state: PreparedState): Promise<void> {
  if (state.backedUp) {
    try {
      // copyFile + unlink-backup so a partial-restore failure leaves the
      // backup intact for manual recovery.
      await copyFile(BACKUP_PATH, DEV_VARS_PATH);
      await rm(BACKUP_PATH, { force: true });
    } catch (err) {
      process.stderr.write(
        `[harness:cookie] RESTORE FAILED — original .dev.vars is at ${BACKUP_PATH}\n` +
          `  cp "${BACKUP_PATH}" "${DEV_VARS_PATH}"\n` +
          `  error: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      return;
    }
  }
  // Best-effort cleanup of the backup dir itself.
  try {
    await rm(BACKUP_DIR, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}

interface ProbeResult {
  status: number;
  body: string;
}

async function probeRoot(url: string): Promise<ProbeResult> {
  const res = await fetch(url, { method: "GET" });
  const body = await res.text();
  return { status: res.status, body };
}

function buildAssertions(probe: ProbeResult): Assertion[] {
  return [
    {
      ok: probe.status === 500,
      label: "GET / returns HTTP 500",
      detail: `status=${probe.status}`,
    },
    {
      ok: probe.body.includes("COOKIE_ENCRYPTION_KEY"),
      label: "response body mentions COOKIE_ENCRYPTION_KEY",
      detail: probe.body.includes("COOKIE_ENCRYPTION_KEY")
        ? undefined
        : `body=${probe.body.slice(0, 300)}`,
    },
    {
      ok: probe.body.includes("wrangler secret put"),
      label: "response body cites the `wrangler secret put` remedy",
      detail: probe.body.includes("wrangler secret put")
        ? undefined
        : `body=${probe.body.slice(0, 300)}`,
    },
  ];
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // Check the gmail app exists.
  try {
    await stat(GMAIL_APP_CWD);
  } catch {
    process.stderr.write(`[harness:cookie] missing apps/gmail at ${GMAIL_APP_CWD}\n`);
    process.exit(2);
  }

  const state = await stageNoSecretEnv();
  process.stderr.write(
    `[harness:cookie] staged no-secret env (backup at ${BACKUP_PATH}, backedUp=${state.backedUp})\n`,
  );

  // Signal handlers — restore on Ctrl-C / kill.
  let cleaningUp = false;
  let wrangler: SpawnedWrangler | undefined;
  const cleanup = async (signal: NodeJS.Signals | undefined): Promise<void> => {
    if (cleaningUp) return;
    cleaningUp = true;
    if (wrangler) {
      await wrangler.kill();
    }
    await restoreSecretEnv(state);
    if (signal) process.exit(130);
  };
  process.on("SIGINT", () => {
    void cleanup("SIGINT");
  });
  process.on("SIGTERM", () => {
    void cleanup("SIGTERM");
  });

  let exitCode = 0;
  try {
    // Spawn with COOKIE_ENCRYPTION_KEY explicitly stripped from the
    // inherited env too — defence in depth in case the operator has it
    // exported in their shell.
    wrangler = spawnWrangler({
      cwd: GMAIL_APP_CWD,
      port: args.port,
      env: { COOKIE_ENCRYPTION_KEY: undefined },
    });

    let target: string;
    try {
      target = await wrangler.ready;
    } catch (err) {
      // Wrangler may refuse to start without the secret. That's an
      // acceptable alternative-PASS path: the operator-visible message
      // still names COOKIE_ENCRYPTION_KEY somewhere in the log.
      const lines = wrangler.getCapturedLines();
      const joined = lines.join("\n");
      const ok =
        joined.includes("COOKIE_ENCRYPTION_KEY") &&
        joined.includes("wrangler secret put");
      const assertions: Assertion[] = [
        {
          ok,
          label: "wrangler-dev startup failure log carries the actionable message",
          detail: ok
            ? undefined
            : `last error: ${err instanceof Error ? err.message : String(err)}`,
        },
      ];
      const allOk = printAssertions(assertions);
      summary("COOKIE-ABSENCE (startup-fail path)", allOk);
      exitCode = allOk ? 0 : 1;
      return;
    }

    const probe = await probeRoot(`${target}/`);
    process.stderr.write(
      `[harness:cookie] probe: status=${probe.status} body=${probe.body.slice(0, 200)}\n`,
    );
    const assertions = buildAssertions(probe);
    const allOk = printAssertions(assertions);
    summary("COOKIE-ABSENCE", allOk);
    if (!allOk) {
      dumpTail("wrangler log", wrangler.getCapturedLines());
    }
    exitCode = allOk ? 0 : 1;
  } catch (err) {
    process.stderr.write(
      `[harness:cookie] error: ${err instanceof Error ? err.stack : String(err)}\n`,
    );
    if (wrangler) dumpTail("wrangler log", wrangler.getCapturedLines());
    summary("COOKIE-ABSENCE", false);
    exitCode = 2;
  } finally {
    if (wrangler) await wrangler.kill();
    await restoreSecretEnv(state);
  }

  process.exit(exitCode);
}

main().catch((err: unknown) => {
  process.stderr.write(`[harness:cookie] fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
