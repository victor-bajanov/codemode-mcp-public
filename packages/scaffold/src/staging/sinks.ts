// Fixed-length sinks: the only way file-sized bytes leave a block loop.
//
// workerd copies every Uint8Array body handed to `fetch`, `new Response` or
// `R2.put`, so a preassembled buffer would double peak memory. Instead the
// block loop writes into a stream of precomputed length that the consumer
// reads as it goes. In workerd that is a `FixedLengthStream` (which still
// sends `Content-Length`); under Node/Vitest an identity `TransformStream`.
//
// The wrapper owns the invariants rather than trusting platform behaviour
// (workerd's handling of a short `close()` is unverified): it counts bytes,
// rejects an over-write before touching the platform stream, and turns a
// short `close()` into an abort. Any failure after the first byte aborts the
// stream, so a consumer sees an error, never a clean end of a truncated body.
//
// A write or close the platform stream itself refuses (its consumer, the
// upstream connection, went away) throws a SinkTransportError, so callers can
// tell a broken transport from a failure of their own.

/** The platform stream refused a write or close: its consumer is gone. */
export class SinkTransportError extends Error {
  constructor(cause: unknown) {
    super("sink: the stream's consumer closed it", { cause });
    this.name = "SinkTransportError";
  }
}

export interface FixedLengthSink {
  readable: ReadableStream<Uint8Array>;
  /** Bytes the platform stream has accepted. */
  readonly sent: number;
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason: unknown): Promise<void>;
}

type FixedLengthStreamCtor = new (length: number) => {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
};

export function createFixedLengthSink(length: number): FixedLengthSink {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError("createFixedLengthSink: length must be a non-negative integer");
  }
  const Fls = (globalThis as { FixedLengthStream?: unknown }).FixedLengthStream;
  const pair =
    typeof Fls === "function"
      ? new (Fls as FixedLengthStreamCtor)(length)
      : new TransformStream<Uint8Array, Uint8Array>();
  const writer = pair.writable.getWriter();
  let written = 0;
  let sent = 0;
  let state: "open" | "closed" | "aborted" = "open";

  async function abort(reason: unknown): Promise<void> {
    if (state !== "open") return;
    state = "aborted";
    try {
      await writer.abort(reason);
    } catch {
      /* already errored */
    }
  }

  return {
    readable: pair.readable,
    get sent() {
      return sent;
    },
    async write(chunk) {
      if (state !== "open") throw new Error(`sink is ${state}`);
      if (written + chunk.byteLength > length) {
        await abort(new Error("sink: body exceeds its declared length"));
        throw new Error("sink: body exceeds its declared length");
      }
      written += chunk.byteLength;
      if (chunk.byteLength === 0) return;
      try {
        await writer.write(chunk);
      } catch (err) {
        throw new SinkTransportError(err);
      }
      sent += chunk.byteLength;
    },
    async close() {
      if (state !== "open") throw new Error(`sink is ${state}`);
      if (written !== length) {
        const err = new Error("sink: short body, aborted instead of closing");
        await abort(err);
        throw err;
      }
      state = "closed";
      try {
        await writer.close();
      } catch (err) {
        throw new SinkTransportError(err);
      }
    },
    abort,
  };
}
