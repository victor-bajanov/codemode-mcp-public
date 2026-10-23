// Structural view of the request path's TransferGate (compose/gate.ts, D8),
// so staging capabilities can take the gate without importing it.
//
// The `__stagingHost` capabilities are built once per session, while the gate
// is keyed per execute run; `currentRun` supplies the live run's key and
// deadline signal. Without it each call is its own run (isolate-level cap
// only) with a signal that never aborts.

export interface TransferGateLike {
  acquire(runKey: object, signal: AbortSignal): Promise<() => void>;
}

export interface RunContext {
  runKey: object;
  signal: AbortSignal;
}

/** Neither, or both: a gate is keyed by run, so it never comes without the
 *  run context (the type makes `transferGate` alone a compile error). */
export type TransferGateDeps =
  | { transferGate?: undefined; currentRun?: undefined }
  | { transferGate: TransferGateLike; currentRun: () => RunContext | undefined };

export type GateResult<T> = { ok: true; value: T } | { ok: false; status: 429; message: string };

/**
 * Run `fn` holding a gate slot when a gate is supplied; release in `finally`.
 * A refused acquisition (per-run cap, full queue, aborted run) becomes a 429
 * carrying the gate's own message, which never contains a token or handle.
 */
export async function withTransferGate<T>(deps: TransferGateDeps, fn: () => Promise<T>): Promise<GateResult<T>> {
  if (!deps.transferGate) return { ok: true, value: await fn() };
  const run = deps.currentRun?.() ?? { runKey: {}, signal: new AbortController().signal };
  let release: () => void;
  try {
    release = await deps.transferGate.acquire(run.runKey, run.signal);
  } catch (err) {
    const message = err instanceof Error ? err.message : "staged transfer refused; retry shortly";
    return { ok: false, status: 429, message };
  }
  try {
    return { ok: true, value: await fn() };
  } finally {
    release();
  }
}

/**
 * A gate slot taken later, by someone else. `stageFromUpstreamJson` must not
 * hold a slot while its inner request may block on elicitation (D7), so it
 * hands this lease to the request handler, which acquires it only after the
 * request is approved and the token minted; the capability releases it in its
 * own `finally`, after the store.
 */
export interface TransferLease {
  /** Idempotent; resolves once a slot is held (no-op without a gate). Rejects
   *  with the gate's own error on refusal. */
  acquire(): Promise<void>;
  /** Idempotent; a no-op if never acquired. */
  release(): void;
}

export function createTransferLease(deps: TransferGateDeps): TransferLease & { refusal(): Error | null } {
  let pending: Promise<void> | null = null;
  let releaseFn: (() => void) | null = null;
  let released = false;
  let refused: Error | null = null;
  return {
    acquire() {
      pending ??= (async () => {
        if (!deps.transferGate) return;
        const run = deps.currentRun?.() ?? { runKey: {}, signal: new AbortController().signal };
        try {
          const r = await deps.transferGate.acquire(run.runKey, run.signal);
          if (released) r(); // released while waiting
          else releaseFn = r;
        } catch (err) {
          refused = err instanceof Error ? err : new Error("staged transfer refused; retry shortly");
          throw refused;
        }
      })();
      return pending;
    },
    release() {
      released = true;
      const r = releaseFn;
      releaseFn = null;
      r?.();
    },
    refusal: () => refused,
  };
}
