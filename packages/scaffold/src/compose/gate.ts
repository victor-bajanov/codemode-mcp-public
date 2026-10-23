// Two-level transfer gate (D8).
//
// Level 1, per execution run: at most one file-sized transfer in flight and
// one waiting; a third concurrent request from the same run is refused
// outright. Level 2, per isolate: a semaphore of `maxConcurrent` slots with a
// FIFO queue of at most `maxWaiting` waiters; beyond that the request is
// refused with a "retry shortly". The 128 MB budget is per isolate and shared
// with every other live session of the deployment, so one session must never
// be able to hold the whole queue: the per-run cap bounds any single run to
// two slots.
//
// Every file-sized capability acquires the gate and releases it in `finally`.

import { ToolError } from "../elicit";

export const PER_RUN_MESSAGE =
  "one staged transfer at a time per execution; await each before starting the next";
export const RETRY_MESSAGE =
  "too many staged transfers are in progress on this server; retry shortly";

export interface TransferGateOptions {
  maxConcurrent: number;
  maxWaiting: number;
  perRunInFlight: 1;
  perRunWaiting: 1;
}

interface RunState {
  active: number;
  waiting: number;
}

interface Waiter {
  run: RunState;
  grant: () => void;
}

export class TransferGate {
  private readonly maxConcurrent: number;
  private readonly maxWaiting: number;
  private readonly perRunTotal: number;
  private readonly perRunInFlight: number;
  private inFlight = 0;
  private readonly queue: Waiter[] = [];
  private readonly runs = new WeakMap<object, RunState>();

  constructor(opts: TransferGateOptions) {
    this.maxConcurrent = Math.max(1, opts.maxConcurrent);
    this.maxWaiting = Math.max(0, opts.maxWaiting);
    this.perRunInFlight = opts.perRunInFlight;
    this.perRunTotal = opts.perRunInFlight + opts.perRunWaiting;
  }

  /**
   * Resolve with an idempotent release function once a slot is held. Rejects
   * with a ToolError when the run already has a transfer in flight and one
   * waiting, or when the isolate queue is full; rejects when `signal` aborts
   * while waiting (the queue slot is freed).
   */
  acquire(runKey: object, signal: AbortSignal): Promise<() => void> {
    if (signal.aborted) return Promise.reject(abortError(signal));
    let run = this.runs.get(runKey);
    if (!run) {
      run = { active: 0, waiting: 0 };
      this.runs.set(runKey, run);
    }
    if (run.active + run.waiting >= this.perRunTotal) {
      return Promise.reject(new ToolError(PER_RUN_MESSAGE));
    }
    const state = run;
    if (state.active < this.perRunInFlight && this.inFlight < this.maxConcurrent && !this.hasEligibleWaiter()) {
      return Promise.resolve(this.take(state));
    }
    if (this.queue.length >= this.maxWaiting) {
      return Promise.reject(new ToolError(RETRY_MESSAGE));
    }
    return new Promise<() => void>((resolve, reject) => {
      const onAbort = (): void => {
        const i = this.queue.indexOf(waiter);
        if (i < 0) return;
        this.queue.splice(i, 1);
        state.waiting--;
        reject(abortError(signal));
        this.pump();
      };
      const waiter: Waiter = {
        run: state,
        grant: () => {
          signal.removeEventListener("abort", onAbort);
          state.waiting--;
          resolve(this.take(state));
        },
      };
      state.waiting++;
      this.queue.push(waiter);
      signal.addEventListener("abort", onAbort, { once: true });
    });
  }

  /** FIFO fairness: a newcomer may not overtake a queued waiter that could
   *  run now. Waiters held back only by their own run do not block others. */
  private hasEligibleWaiter(): boolean {
    return this.queue.some((w) => w.run.active < this.perRunInFlight);
  }

  private take(run: RunState): () => void {
    run.active++;
    this.inFlight++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      run.active--;
      this.inFlight--;
      this.pump();
    };
  }

  /** Admit waiters in FIFO order, skipping any whose run already has a
   *  transfer in flight (it waits for its own run, not for the isolate). */
  private pump(): void {
    let i = 0;
    while (this.inFlight < this.maxConcurrent && i < this.queue.length) {
      const w = this.queue[i]!;
      if (w.run.active >= this.perRunInFlight) {
        i++;
        continue;
      }
      this.queue.splice(i, 1);
      w.grant();
    }
  }
}

function abortError(signal: AbortSignal): Error {
  const r: unknown = signal.reason;
  return r instanceof Error ? r : new ToolError("staged transfer cancelled: the execution was aborted");
}
