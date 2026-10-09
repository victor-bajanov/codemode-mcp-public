// Host-side limits for one codemode sandbox run (F-12, 2026-10-07 security
// review). codemode's own 70 s timeout is a `Promise.race` INSIDE the sandbox,
// so LLM code can neuter it (`setTimeout = () => 0`) or spin the CPU while the
// host awaits forever. These two knobs are enforced by the host instead — see
// createGuardedExecutor in mcp-agent-factory.ts:
//
//   • EXECUTE_HOST_TIMEOUT_MS — the host stops waiting after this long and
//     refuses every later upstream call from that run. Default 75 000 ms:
//     codemode's in-sandbox 70 s plus a margin, so the cooperative timeout
//     still fires first whenever the sandbox lets it.
//   • EXECUTE_MAX_UPSTREAM_CALLS — upstream requests one run may make
//     (`codemode.request` plus `__stagingHost.stageFromUpstreamJson` /
//     `stageFromAttachment`). Default 1 000. Sized to sit below Cloudflare's
//     paid-plan subrequest limit (10 000 per invocation since 2026-02-11) so
//     an ambitious run stops with this budget's clear error rather than the
//     platform's "Too many subrequests": a budgeted call costs at most ~4
//     subrequests (broker RPC + upstream fetch, plus R2 put and D1 insert
//     when staging), so 1 000 calls stay under 4 000. The deadline usually
//     binds first for sequential loops. Raise both together if the Worker
//     sets a higher `limits.subrequests`.

export const DEFAULT_EXECUTE_HOST_TIMEOUT_MS = 75_000;
export const DEFAULT_EXECUTE_MAX_UPSTREAM_CALLS = 1_000;

export interface ExecutionLimits {
  hostTimeoutMs: number;
  maxUpstreamCalls: number;
}

/** Positive-integer env var, falling back when unset/empty. Deliberately a
 *  local copy of config.ts's parser (same contract, same error text) so this
 *  module has no dependency on the OAuth/staging config surface. */
function parsePositiveIntVar(
  env: Record<string, unknown>,
  name: string,
  fallback: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
    throw new Error(`${name}: must be a positive integer, got ${String(raw)}`);
  }
  return n;
}

/** Reads EXECUTE_HOST_TIMEOUT_MS / EXECUTE_MAX_UPSTREAM_CALLS; unset or "" →
 *  default; anything that is not a positive integer throws (same contract as
 *  config.ts's positive-integer vars). */
export function readExecutionLimits(env: Record<string, unknown>): ExecutionLimits {
  return {
    hostTimeoutMs: parsePositiveIntVar(env, "EXECUTE_HOST_TIMEOUT_MS", DEFAULT_EXECUTE_HOST_TIMEOUT_MS),
    maxUpstreamCalls: parsePositiveIntVar(
      env,
      "EXECUTE_MAX_UPSTREAM_CALLS",
      DEFAULT_EXECUTE_MAX_UPSTREAM_CALLS,
    ),
  };
}
