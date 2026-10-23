import { describe, it, expect, vi, afterEach } from "vitest";
import { createFixedLengthSink, SinkTransportError } from "../sinks";

async function drain(rs: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = rs.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return Buffer.concat(parts);
}

interface StubRecord {
  lengths: number[];
  closed: number;
  aborted: unknown[];
  writes: number;
}

function installStub(): StubRecord {
  const rec: StubRecord = { lengths: [], closed: 0, aborted: [], writes: 0 };
  class FakeFixedLengthStream {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
    constructor(length: number) {
      rec.lengths.push(length);
      const inner = new TransformStream<Uint8Array, Uint8Array>();
      const w = inner.writable.getWriter();
      this.readable = inner.readable;
      this.writable = new WritableStream<Uint8Array>({
        write: (c) => { rec.writes++; return w.write(c); },
        close: () => { rec.closed++; return w.close(); },
        abort: (r) => { rec.aborted.push(r); return w.abort(r); },
      });
    }
  }
  vi.stubGlobal("FixedLengthStream", FakeFixedLengthStream);
  return rec;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe.each([
  ["Node fallback", false],
  ["workerd FixedLengthStream", true],
] as const)("createFixedLengthSink (%s)", (_label, stub) => {
  it("passes through writes summing to length and forwards close()", async () => {
    const rec = stub ? installStub() : null;
    const sink = createFixedLengthSink(6);
    const out = drain(sink.readable);
    await sink.write(new Uint8Array([1, 2, 3]));
    await sink.write(new Uint8Array([4, 5, 6]));
    await sink.close();
    expect(Array.from(await out)).toEqual([1, 2, 3, 4, 5, 6]);
    if (rec) {
      expect(rec.lengths).toEqual([6]);
      expect(rec.closed).toBe(1);
    }
  });

  it("aborts instead of closing on a short body; the readable errors", async () => {
    const rec = stub ? installStub() : null;
    const sink = createFixedLengthSink(10);
    const out = drain(sink.readable);
    await sink.write(new Uint8Array(4));
    await expect(sink.close()).rejects.toThrow(/short/);
    await expect(out).rejects.toThrow();
    if (rec) {
      expect(rec.closed).toBe(0);
      expect(rec.aborted).toHaveLength(1);
    }
  });

  it("rejects an over-write before any platform write, and aborts the sink", async () => {
    const rec = stub ? installStub() : null;
    const sink = createFixedLengthSink(3);
    const out = drain(sink.readable);
    await sink.write(new Uint8Array(2));
    await expect(sink.write(new Uint8Array(2))).rejects.toThrow(/exceeds/);
    await expect(out).rejects.toThrow();
    if (rec) {
      expect(rec.writes).toBe(1);
      expect(rec.closed).toBe(0);
    }
    await expect(sink.write(new Uint8Array(1))).rejects.toThrow();
  });

  it("an over-write is not a transport failure", async () => {
    stub && installStub();
    const sink = createFixedLengthSink(1);
    void drain(sink.readable).catch(() => {});
    const err = await sink.write(new Uint8Array(2)).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(SinkTransportError);
  });

  it("counts the bytes the stream accepted; a consumer cancel mid-body surfaces as SinkTransportError", async () => {
    stub && installStub();
    const sink = createFixedLengthSink(10);
    expect(sink.sent).toBe(0);
    const reader = sink.readable.getReader();
    const w1 = sink.write(new Uint8Array(4));
    await reader.read();
    await w1;
    expect(sink.sent).toBe(4);
    await reader.cancel(new Error("connection closed"));
    const err = await sink.write(new Uint8Array(4)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SinkTransportError);
    expect(sink.sent).toBe(4);
  });

  it("a consumer cancel before close() surfaces as SinkTransportError", async () => {
    stub && installStub();
    const sink = createFixedLengthSink(2);
    const reader = sink.readable.getReader();
    const w1 = sink.write(new Uint8Array(2));
    await reader.read();
    await w1;
    await reader.cancel(new Error("connection closed"));
    const err = await sink.close().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SinkTransportError);
    expect(sink.sent).toBe(2);
  });

  it("abort(reason) propagates to the readable", async () => {
    const rec = stub ? installStub() : null;
    const sink = createFixedLengthSink(3);
    const out = drain(sink.readable);
    await sink.write(new Uint8Array(1));
    await sink.abort(new Error("upstream failed"));
    await expect(out).rejects.toThrow(/upstream failed/);
    if (rec) expect(rec.aborted).toHaveLength(1);
    await expect(sink.close()).rejects.toThrow();
  });

  it("supports a zero-length body", async () => {
    stub && installStub();
    const sink = createFixedLengthSink(0);
    const out = drain(sink.readable);
    await sink.close();
    expect((await out).byteLength).toBe(0);
  });

  it("applies backpressure: write() does not settle until the consumer reads", async () => {
    stub && installStub();
    const sink = createFixedLengthSink(4);
    let settled = false;
    const p = sink.write(new Uint8Array(2)).then(() => { settled = true; });
    const p2 = sink.write(new Uint8Array(2));
    await new Promise((r) => setTimeout(r, 10));
    const reader = sink.readable.getReader();
    await reader.read();
    await reader.read();
    await p;
    await p2;
    expect(settled).toBe(true);
    const c = sink.close();
    expect((await reader.read()).done).toBe(true);
    await c;
  });
});

describe("selection", () => {
  it("uses the global FixedLengthStream when present, constructed with the length", () => {
    const rec = installStub();
    createFixedLengthSink(1234);
    expect(rec.lengths).toEqual([1234]);
  });

  it("rejects a negative or non-integer length", () => {
    expect(() => createFixedLengthSink(-1)).toThrow();
    expect(() => createFixedLengthSink(1.5)).toThrow();
  });
});
