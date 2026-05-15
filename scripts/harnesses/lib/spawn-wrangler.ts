/**
 * Shared helper for the harnesses: spawn `pnpm wrangler dev` from a given
 * working directory, capture stdout/stderr line-by-line, expose a promise
 * that resolves when wrangler prints its "Ready on <url>" line.
 *
 * Two consumers: `mcp-client.ts` (PKCE + audit modes) and `cookie-absence.ts`
 * (I4). The cookie-absence harness needs to detect *failure* on startup too,
 * so the spawn keeps a rolling buffer of lines that the caller can inspect
 * via `getCapturedLines()`.
 */
import { type ChildProcess, spawn } from "node:child_process";

export interface SpawnedWrangler {
  child: ChildProcess;
  /** Resolves to the ready URL (e.g. "http://localhost:8787"). */
  ready: Promise<string>;
  /** Snapshot of all captured stdout+stderr lines (oldest first). */
  getCapturedLines: () => readonly string[];
  /** Subscribe to every new line as it arrives. Returns an unsubscribe fn. */
  onLine: (cb: (line: string, stream: "stdout" | "stderr") => void) => () => void;
  /** Kill the child and wait for exit. Safe to call multiple times. */
  kill: () => Promise<void>;
}

export interface SpawnWranglerOptions {
  /** Absolute path to the wrangler-dev cwd (e.g. apps/gmail). */
  cwd: string;
  /** Port to bind. Default 8787. */
  port?: number;
  /** Extra `--var KEY:VALUE` pairs appended after the base flags. */
  vars?: Record<string, string>;
  /** Environment overrides for the child process. Merged onto process.env. */
  env?: Record<string, string | undefined>;
  /** ms to wait for "Ready on". Default 60_000. */
  readyTimeoutMs?: number;
  /** Mirror wrangler output to the harness's stderr. Default true. */
  mirrorToStderr?: boolean;
}

const READY_RX = /Ready on\s+(https?:\/\/[^\s]+)/i;

export function spawnWrangler(opts: SpawnWranglerOptions): SpawnedWrangler {
  const port = opts.port ?? 8787;
  const readyTimeoutMs = opts.readyTimeoutMs ?? 60_000;
  const mirrorToStderr = opts.mirrorToStderr ?? true;

  const args = ["wrangler", "dev", "--port", String(port)];
  if (opts.vars) {
    for (const [k, v] of Object.entries(opts.vars)) {
      args.push("--var", `${k}:${v}`);
    }
  }

  const childEnv: NodeJS.ProcessEnv = { ...process.env, FORCE_COLOR: "0" };
  if (opts.env) {
    for (const [k, v] of Object.entries(opts.env)) {
      if (v === undefined) {
        delete childEnv[k];
      } else {
        childEnv[k] = v;
      }
    }
  }

  const child = spawn("pnpm", args, {
    cwd: opts.cwd,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const captured: string[] = [];
  const subscribers = new Set<(line: string, stream: "stdout" | "stderr") => void>();
  const buffers: Record<"stdout" | "stderr", string> = { stdout: "", stderr: "" };

  const flushLine = (stream: "stdout" | "stderr", line: string): void => {
    captured.push(line);
    if (mirrorToStderr) {
      process.stderr.write(`[wrangler:${stream}] ${line}\n`);
    }
    for (const cb of subscribers) {
      try {
        cb(line, stream);
      } catch {
        // never let a subscriber's error escape into the spawn loop
      }
    }
  };

  const onChunk = (stream: "stdout" | "stderr") => (chunk: Buffer): void => {
    buffers[stream] += chunk.toString("utf8");
    let idx = buffers[stream].indexOf("\n");
    while (idx >= 0) {
      const line = buffers[stream].slice(0, idx).replace(/\r$/, "");
      buffers[stream] = buffers[stream].slice(idx + 1);
      flushLine(stream, line);
      idx = buffers[stream].indexOf("\n");
    }
  };

  // stdio:["ignore","pipe","pipe"] guarantees stdout/stderr are non-null
  // Readable streams; the explicit null checks satisfy strict typing.
  if (!child.stdout || !child.stderr) {
    throw new Error("spawn returned a child without piped stdout/stderr");
  }
  child.stdout.on("data", onChunk("stdout"));
  child.stderr.on("data", onChunk("stderr"));

  const ready = new Promise<string>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(
        new Error(
          `Timed out (${readyTimeoutMs} ms) waiting for "Ready on" from wrangler dev. ` +
            `Last captured lines:\n${captured.slice(-20).join("\n")}`,
        ),
      );
    }, readyTimeoutMs);

    const unsub = onLine((line) => {
      const m = line.match(READY_RX);
      if (m && m[1] && !settled) {
        settled = true;
        clearTimeout(timer);
        unsub();
        resolve(m[1].replace(/\/$/, ""));
      }
    });

    child.on("exit", (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      unsub();
      reject(
        new Error(
          `wrangler dev exited (code=${code} signal=${signal}) before becoming ready. ` +
            `Last captured lines:\n${captured.slice(-20).join("\n")}`,
        ),
      );
    });
  });

  function onLine(cb: (line: string, stream: "stdout" | "stderr") => void): () => void {
    subscribers.add(cb);
    return () => subscribers.delete(cb);
  }

  let killed = false;
  async function kill(): Promise<void> {
    if (killed) return;
    killed = true;
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      const done = (): void => resolve();
      child.once("exit", done);
      try {
        child.kill("SIGTERM");
      } catch {
        resolve();
        return;
      }
      // Force-kill if the child ignores SIGTERM after 5s.
      const force = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
      }, 5_000);
      child.once("exit", () => clearTimeout(force));
    });
  }

  return {
    child,
    ready,
    getCapturedLines: () => captured.slice(),
    onLine,
    kill,
  };
}
