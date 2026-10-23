// Writer/fetch coupling for host-assembled sends (D3a).
//
// One controller per transfer, aborted by the run's host deadline, by a
// per-transfer absolute timeout, or by the other side failing. The writer
// loop and `fetch` run concurrently but are never `Promise.all`ed: if fetch
// settles first (an upstream answering 413 after 4 KB and no longer reading),
// the writer is aborted and its rejection swallowed; if the writer fails
// first (R2 read, corrupt block), fetch is aborted and the writer's error
// surfaces. An aborted transfer leaves the upstream with a body shorter than
// its Content-Length, so no send can complete after the run was told it
// failed.
//
// One exception to "the writer's error surfaces": a write the sink's platform
// stream refuses (SinkTransportError) means the upstream closed the
// connection mid-body, typically just before answering (Xero's edge sends 413
// for an oversized body after ~30 s). Then fetch gets a short grace to settle:
// its response, if any, is the answer; otherwise the error names the close
// and how many bytes got through, never a staged-file read failure.

import { ToolError } from "../elicit";
import { createFixedLengthSink, SinkTransportError } from "../staging/sinks";
import { StagedFileReadError, type OpenStagedFile } from "../staging/staged-file";
import { writeAssembled } from "./assemble";
import type { Segment } from "./validate";

/** How long fetch may take to settle after the upstream closed the body
 *  stream, before the close itself is reported. Also bounded by the
 *  transfer controller (host deadline, transfer timeout). */
export const UPSTREAM_CLOSE_GRACE_MS = 5_000;

export interface TransferController {
  readonly signal: AbortSignal;
  abort(reason: unknown): void;
  dispose(): void;
}

/** A controller aborted by `runSignal` (the host deadline) or after
 *  `timeoutMs`, whichever comes first; reasons are ToolErrors. */
export function transferController(runSignal: AbortSignal | undefined, timeoutMs: number): TransferController {
  const ctl = new AbortController();
  const onRun = (): void =>
    ctl.abort(new ToolError("staged transfer aborted: this execution passed its host-side deadline"));
  if (runSignal?.aborted) onRun();
  else runSignal?.addEventListener("abort", onRun, { once: true });
  const timer = setTimeout(
    () => ctl.abort(new ToolError(`staged transfer timed out after ${timeoutMs} ms and was aborted`)),
    timeoutMs,
  );
  return {
    signal: ctl.signal,
    abort: (reason) => ctl.abort(reason),
    dispose: () => {
      clearTimeout(timer);
      runSignal?.removeEventListener("abort", onRun);
    },
  };
}

function reasonOf(signal: AbortSignal): ToolError {
  const r: unknown = signal.reason;
  return r instanceof ToolError ? r : new ToolError("staged transfer aborted");
}

/** `p`'s response if it resolves within `ms` and before `signal` aborts;
 *  otherwise undefined. Never rejects. */
async function settleWithin(p: Promise<Response>, ms: number, signal: AbortSignal): Promise<Response | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  try {
    return await Promise.race([
      p.then(
        (res) => res,
        () => undefined,
      ),
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), ms);
        onAbort = () => resolve(undefined);
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
      }),
    ]);
  } finally {
    clearTimeout(timer);
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

/** Caller-safe description of a writer failure: never a token, handle or
 *  file content. */
function writerMessage(err: unknown): string {
  if (err instanceof ToolError) return err.message;
  if (err instanceof StagedFileReadError) return err.message;
  return "a staged file could not be read";
}

export interface AssembledBody {
  segments: readonly Segment[];
  files: readonly OpenStagedFile[];
  length: number;
}

/** True when the platform supplies `FixedLengthStream` (workerd), whose
 *  readable already carries the length, so `Content-Length` must not be set
 *  by hand. Under Node the header is set explicitly. */
export function platformSuppliesContentLength(): boolean {
  return typeof (globalThis as { FixedLengthStream?: unknown }).FixedLengthStream === "function";
}

/** The upstream's answer to an assembled send, and how much of the body the
 *  connection accepted before it answered (for the audit line). */
export interface AssembledSend {
  response: Response;
  bodyBytesSent: number;
  /** Every byte of the declared length was accepted. False when the
   *  upstream answered (any status) after reading only part of the body. */
  bodyComplete: boolean;
}

/**
 * `fetch(url, init)` with `body` written block by block into a fixed-length
 * sink of `body.length` bytes, under the caller's transfer controller `tc`
 * (host deadline + per-transfer timeout). The caller keeps `tc` alive while
 * it reads the response and disposes it afterwards. Resolves with the
 * upstream response (any status) and the bytes sent; rejects with a
 * ToolError on a writer failure, a fetch failure, the host deadline or the
 * transfer timeout.
 */
export async function sendAssembled(
  url: string,
  init: RequestInit,
  body: AssembledBody,
  tc: TransferController,
): Promise<AssembledSend> {
  const writerCtl = new AbortController();
  const stopWriter = (): void => writerCtl.abort(tc.signal.reason);
  tc.signal.addEventListener("abort", stopWriter, { once: true });
  try {
    if (tc.signal.aborted) throw reasonOf(tc.signal);
    const sink = createFixedLengthSink(body.length);
    let writerDone = false;
    const writer = writeAssembled(body.segments, body.files, sink, writerCtl.signal).then(() => {
      writerDone = true;
    });
    writer.catch(() => {});
    let fetched: Promise<Response>;
    try {
      fetched = fetch(url, { ...init, body: sink.readable, signal: tc.signal });
    } catch (err) {
      fetched = Promise.reject(err);
    }
    fetched.catch(() => {});
    const answered = (response: Response): AssembledSend => ({
      response,
      bodyBytesSent: sink.sent,
      bodyComplete: sink.sent === body.length,
    });

    type First = { from: "fetch"; res: Response } | { from: "fetch-error"; err: unknown } | { from: "writer"; err: unknown };
    const first = await Promise.race<First>([
      fetched.then(
        (res) => ({ from: "fetch", res }),
        (err: unknown) => ({ from: "fetch-error", err }),
      ),
      // A writer that finishes never settles the race: only its rejection does.
      writer.then(
        () => new Promise<never>(() => {}),
        (err: unknown) => ({ from: "writer", err }),
      ),
    ]);
    if (first.from === "writer") {
      if (tc.signal.aborted) throw reasonOf(tc.signal);
      if (first.err instanceof SinkTransportError) {
        // The writer has already aborted the sink; only fetch is outstanding.
        const res = await settleWithin(fetched, UPSTREAM_CLOSE_GRACE_MS, tc.signal);
        if (res) return answered(res);
        if (tc.signal.aborted) throw reasonOf(tc.signal);
        const failure = new ToolError(
          `staged transfer failed: upstream closed the connection after ${sink.sent} of ${body.length} bytes were sent; the upstream request was aborted`,
        );
        tc.abort(failure);
        throw failure;
      }
      // Abort with the caller-facing error itself, so the handler's
      // transferFailure() reports this reason, not a generic abort.
      const failure = new ToolError(
        `staged transfer failed: ${writerMessage(first.err)}; the upstream request was aborted`,
      );
      tc.abort(failure);
      throw failure;
    }
    if (first.from === "fetch-error") {
      if (tc.signal.aborted) throw reasonOf(tc.signal);
      writerCtl.abort(first.err);
      const msg = first.err instanceof Error ? first.err.message : String(first.err);
      throw new ToolError(`upstream request failed: ${msg.slice(0, 200)}`);
    }
    // The upstream answered before reading the whole body: stop writing so the
    // writer cannot stay blocked on backpressure.
    if (!writerDone) writerCtl.abort(new ToolError("upstream answered before the body was fully sent"));
    return answered(first.res);
  } finally {
    tc.signal.removeEventListener("abort", stopWriter);
  }
}

/** The transfer's own abort reason when `tc` fired, else `err` unchanged. */
export function transferFailure(tc: TransferController, err: unknown): unknown {
  return tc.signal.aborted ? reasonOf(tc.signal) : err;
}
