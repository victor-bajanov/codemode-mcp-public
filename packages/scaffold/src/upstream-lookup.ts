// Host-side upstream read for `SurfaceReviewEntry.inspectUpstream` (F1-2b).
//
// The only power the hook gets is a GET of a plain-allow read, sent through
// the same request handler as any sandbox request (path guards, query
// policy, audit line, no redirects), at most MAX_UPSTREAM_LOOKUPS times per
// outer request. Every refusal throws before any fetch, and any throw marks
// the session failed: the request handler then denies the write whatever the
// hook returned (fail closed).

import type { UpstreamLookup, UpstreamLookupResult } from "@local/shared";
import { matchOperation } from "./path-matcher";
import { ToolError } from "./elicit";
import type { HandleArgs } from "./request-handler";

export const MAX_UPSTREAM_LOOKUPS = 4;

/** An error the session raised itself: fixed, host-authored text with no
 *  lookup path, query or upstream content in it, so the request handler may
 *  name it to the caller. Every other error is reported without its text. */
export class UpstreamLookupError extends ToolError {
  constructor(message: string) {
    super(message);
    this.name = "UpstreamLookupError";
  }
}

export interface UpstreamLookupSession {
  /** What the hook receives. */
  lookup: UpstreamLookup;
  /** True once any lookup threw (refused, failed, aborted). */
  failed(): boolean;
  /** Refuse every later lookup (called once the hook has settled). */
  close(): void;
  /** Resolves once every lookup started so far has settled (a hook may
   *  fire one without awaiting it); check `failed()` after this. */
  settled(): Promise<void>;
}

type Handle = <P extends Record<string, unknown>>(args: HandleArgs<P>) => Promise<unknown>;

/** One session per outer request. `handle` is `handleUpstreamRequest`
 *  (passed in to keep this module free of an import cycle). */
export function createUpstreamLookup<P extends Record<string, unknown>>(
  args: HandleArgs<P>,
  handle: Handle,
): UpstreamLookupSession {
  let count = 0;
  let failed = false;
  let closed = false;
  const pending = new Set<Promise<unknown>>();

  const refuse = (message: string): never => {
    throw new UpstreamLookupError(message);
  };

  const run = async (path: string, query?: Record<string, string>): Promise<UpstreamLookupResult> => {
    try {
      if (closed) refuse("upstream lookup refused: the inspection that owned it has finished");
      if (typeof path !== "string") refuse("upstream lookup needs a string path");
      count += 1;
      if (count > MAX_UPSTREAM_LOOKUPS) {
        refuse(`upstream lookup refused: at most ${MAX_UPSTREAM_LOOKUPS} reads per request`);
      }
      if (args.signal?.aborted) refuse("upstream lookup refused: this execution passed its host-side deadline");
      const match = matchOperation(args.spec, "GET", path);
      const entry = match ? args.surfaceReview[match.op.operationId] : undefined;
      if (
        !match ||
        !entry ||
        entry.decision !== "allow" ||
        entry.inspect !== undefined ||
        entry.inspectUpstream !== undefined
      ) {
        refuse("upstream lookup refused: the path is not a plain-allow read");
      }
      // The nested request is a bare GET: no staging, no gate (it is small
      // and never returned to the sandbox), the caller's signal and creds.
      const {
        ctx: _ctx,
        transferGate: _gate,
        gateLease: _lease,
        stagingStore: _store,
        openStaged: _open,
        ...inner
      } = args;
      const res = (await handle({
        ...inner,
        ctx: { method: "GET", path, ...(query !== undefined ? { query } : {}), bypassTruncate: true },
      })) as { status: number; result: unknown };
      return { status: res.status, body: res.result };
    } catch (err) {
      failed = true;
      // The nested transfer controller words its abort for staged files.
      if (err instanceof ToolError && !(err instanceof UpstreamLookupError)) {
        if (err.message.startsWith("staged transfer timed out")) refuse("upstream lookup timed out");
        if (err.message.startsWith("staged transfer aborted")) {
          refuse("upstream lookup aborted: this execution passed its host-side deadline");
        }
      }
      throw err;
    }
  };

  const get = (path: string, query?: Record<string, string>): Promise<UpstreamLookupResult> => {
    const p = run(path, query);
    // Tracked so the handler can wait for a lookup the hook did not await;
    // the no-op catch keeps such a dropped promise from being unhandled
    // (an awaiting hook still sees the rejection).
    pending.add(p);
    p.catch(() => {}).finally(() => pending.delete(p));
    return p;
  };

  return {
    lookup: Object.freeze({ get }),
    failed: () => failed,
    close: () => {
      closed = true;
    },
    settled: async () => {
      while (pending.size > 0) await Promise.allSettled([...pending]);
    },
  };
}
