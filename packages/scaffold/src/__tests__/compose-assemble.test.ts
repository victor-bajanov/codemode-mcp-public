// Exact length, inspection view, staged multipart compilation and the
// block-by-block writer for host-assembled bodies (plan B3, D4–D6).

import { describe, it, expect, vi } from "vitest";
import { Buffer } from "node:buffer";
import {
  assembledLength,
  buildInspectionView,
  compileStagedMultipart,
  writeAssembled,
  sanitiseStagedFilename,
  sanitiseRowContentType,
} from "../compose/assemble";
import type { Segment } from "../compose/validate";
import { buildMultipartBody } from "../request-handler";
import { BLOCK_BYTES } from "../staging/block-format";
import { createFixedLengthSink, type FixedLengthSink } from "../staging/sinks";
import type { OpenStagedFile, StagedFileMeta } from "../staging/staged-file";

const REF = { file_handle: "fh_x", token: "stg_y" };
const enc = (s: string) => new TextEncoder().encode(s);

function pattern(n: number, seed = 11): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}

function fileOf(bytes: Uint8Array, contentType = "application/pdf", filename: string | null = "q.pdf") {
  const readBlocks = vi.fn(async (onBlock: (plain: Uint8Array, index: number) => Promise<void>) => {
    let i = 0;
    for (let off = 0; off < bytes.byteLength; off += BLOCK_BYTES) {
      await onBlock(bytes.slice(off, Math.min(bytes.byteLength, off + BLOCK_BYTES)), i++);
    }
  });
  const file: OpenStagedFile = { meta: { byteLength: bytes.byteLength, contentType, filename }, readBlocks };
  return { file, readBlocks };
}

function lines76(b64: string): string {
  let out = "";
  for (let i = 0; i < b64.length; i += 76) out += b64.slice(i, i + 76) + "\r\n";
  return out;
}

async function drain(readable: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const reader = readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

function recordingSink(length: number): { sink: FixedLengthSink; sizes: number[] } {
  const sink = createFixedLengthSink(length);
  const sizes: number[] = [];
  const write = sink.write.bind(sink);
  sink.write = async (c) => {
    sizes.push(c.byteLength);
    return write(c);
  };
  return { sink, sizes };
}

const meta = (n: number, contentType = "application/pdf", filename: string | null = "q.pdf"): StagedFileMeta => ({
  byteLength: n,
  contentType,
  filename,
});

describe("assembledLength", () => {
  it("is exact for text plus each encoding", () => {
    for (const n of [0, 1, 2, 3, 56, 57, 58, 1000, BLOCK_BYTES + 1]) {
      const text: Segment = { kind: "text", bytes: enc("héllo\r\n") };
      const b = Buffer.from(pattern(n)).toString("base64");
      expect(assembledLength([text, { kind: "staged", ref: REF, encoding: "base64", index: 1 }], [meta(n)])).toBe(
        8 + b.length,
      );
      expect(
        assembledLength([text, { kind: "staged", ref: REF, encoding: "base64-lines", index: 1 }], [meta(n)]),
      ).toBe(8 + lines76(b).length);
      expect(assembledLength([{ kind: "staged", ref: REF, encoding: "identity", index: 0 }], [meta(n)])).toBe(n);
    }
  });

  it("counts the same file twice", () => {
    const s: Segment = { kind: "staged", ref: REF, encoding: "identity", index: 0 };
    expect(assembledLength([s, s], [meta(10), meta(10)])).toBe(20);
  });
});

describe("buildInspectionView", () => {
  it("places U+FFFC per staged segment and carries metadata + assembled length", () => {
    const segs: Segment[] = [
      { kind: "text", bytes: enc("To: a@x\r\n\r\n") },
      { kind: "staged", ref: REF, encoding: "base64-lines", index: 1 },
      { kind: "text", bytes: enc("--b--\r\n") },
      { kind: "staged", ref: REF, encoding: "base64", index: 3 },
    ];
    const v = buildInspectionView(segs, [meta(5, "application/pdf", "a.pdf"), meta(7, "image/png", null)]);
    expect(v.rawBody).toBe("To: a@x\r\n\r\n￼--b--\r\n￼");
    expect(v.staged).toEqual([
      { index: 1, byteLength: 5, contentType: "application/pdf", filename: "a.pdf", encoding: "base64-lines" },
      { index: 3, byteLength: 7, contentType: "image/png", filename: null, encoding: "base64" },
    ]);
    expect(v.assembledByteLength).toBe(assembledLength(segs, [meta(5), meta(7)]));
  });

  it("sanitises row-derived filenames (CR/LF/NUL stripped, 255 code points)", () => {
    const v = buildInspectionView(
      [{ kind: "staged", ref: REF, encoding: "identity", index: 0 }],
      [meta(1, "text/plain\r\nX: y", "x\r\nTo: evil@x\0" + "😀".repeat(300))],
    );
    const f = v.staged[0]!.filename!;
    expect(f).not.toMatch(/[\r\n\0]/);
    expect([...f]).toHaveLength(255);
    expect(f.startsWith("xTo: evil@x")).toBe(true);
    expect(v.staged[0]!.contentType).not.toMatch(/[\r\n]/);
  });
});

describe("sanitisers", () => {
  it("sanitiseStagedFilename strips Unicode format characters when asked", () => {
    expect(sanitiseStagedFilename("abc‮fdp.exe", { stripFormat: true })).toBe("abcfdp.exe");
    expect(sanitiseStagedFilename("abc‮fdp.exe")).toBe("abc‮fdp.exe");
    expect(sanitiseStagedFilename(null)).toBeNull();
    expect(sanitiseStagedFilename("\r\n")).toBeNull();
  });

  it("sanitiseRowContentType keeps only a valid media-type essence", () => {
    expect(sanitiseRowContentType("application/pdf")).toBe("application/pdf");
    expect(sanitiseRowContentType("multipart/mixed; boundary=zz")).toBe("multipart/mixed");
    expect(sanitiseRowContentType(' text/plain ; charset="x"')).toBe("text/plain");
    expect(sanitiseRowContentType("text/plain\r\nX-Evil: 1")).toBe("application/octet-stream");
    expect(sanitiseRowContentType('a"b/c')).toBe("application/octet-stream");
    expect(sanitiseRowContentType("")).toBe("application/octet-stream");
  });
});

describe("compileStagedMultipart", () => {
  const BOUNDARY = "----codemode-fixed";

  it("is byte-identical to buildMultipartBody for non-staged parts", async () => {
    const parts = [
      { name: "Name", value: "q.pdf" },
      { name: "bin", filename: "b.bin", bodyBase64: Buffer.from([0, 1, 2, 255]).toString("base64") },
      { name: "t", contentType: "text/csv", value: "a,b\r\n" },
    ];
    const segs = compileStagedMultipart(parts, BOUNDARY, []);
    const { body } = buildMultipartBody(parts, BOUNDARY);
    const sink = createFixedLengthSink(assembledLength(segs, []));
    const [out] = await Promise.all([drain(sink.readable), writeAssembled(segs, [], sink, new AbortController().signal)]);
    expect(Buffer.from(out).equals(Buffer.from(body))).toBe(true);
  });

  it("inserts staged bytes as an identity segment with the row's (sanitised) defaults", async () => {
    const file = pattern(1000);
    const parts = [
      { name: "Name", value: "q.pdf" },
      { name: "file", staged: REF },
    ];
    const metas = [meta(file.byteLength, "application/pdf; boundary=zz", 'q"\r\n.pdf')];
    const segs = compileStagedMultipart(parts, BOUNDARY, metas);
    expect(segs.filter((s) => s.kind === "staged")).toEqual([
      { kind: "staged", ref: REF, encoding: "identity", index: 1 },
    ]);
    const sink = createFixedLengthSink(assembledLength(segs, metas));
    const { file: f } = fileOf(file);
    const [out] = await Promise.all([drain(sink.readable), writeAssembled(segs, [f], sink, new AbortController().signal)]);
    const reference = Buffer.concat([
      Buffer.from(
        `--${BOUNDARY}\r\nContent-Disposition: form-data; name="Name"\r\nContent-Type: text/plain\r\n\r\nq.pdf\r\n` +
          `--${BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="q.pdf"\r\nContent-Type: application/pdf\r\n\r\n`,
      ),
      Buffer.from(file),
      Buffer.from(`\r\n--${BOUNDARY}--\r\n`),
    ]);
    expect(Buffer.from(out).equals(reference)).toBe(true);
  });

  it("sandbox-supplied filename/contentType win over the row's", () => {
    const segs = compileStagedMultipart(
      [{ name: "file", staged: REF, filename: "mine.txt", contentType: "text/plain" }],
      BOUNDARY,
      [meta(3)],
    );
    const head = new TextDecoder().decode((segs[0] as { bytes: Uint8Array }).bytes);
    expect(head).toContain('filename="mine.txt"');
    expect(head).toContain("Content-Type: text/plain\r\n");
  });
});

describe("writeAssembled", () => {
  const SIZES = [0, 1, 57, BLOCK_BYTES, BLOCK_BYTES + 1, 2 * BLOCK_BYTES + 58];

  for (const n of SIZES) {
    it(`Gmail-shaped body equals the Buffer reference for a ${n}-byte file; chunks ≤ 1.5 MiB`, async () => {
      const bytes = pattern(n, n + 3);
      const head = "From: a@x\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\n\r\n";
      const tail = "--b1--\r\n";
      const segs: Segment[] = [
        { kind: "text", bytes: enc(head) },
        { kind: "staged", ref: REF, encoding: "base64-lines", index: 1 },
        { kind: "text", bytes: enc(tail) },
      ];
      const { file, readBlocks } = fileOf(bytes);
      const len = assembledLength(segs, [file.meta]);
      const { sink, sizes } = recordingSink(len);
      const [out] = await Promise.all([
        drain(sink.readable),
        writeAssembled(segs, [file], sink, new AbortController().signal),
      ]);
      const reference = head + lines76(Buffer.from(bytes).toString("base64")) + tail;
      expect(out.byteLength).toBe(len);
      expect(Buffer.from(out).toString("latin1")).toBe(reference);
      expect(Math.max(...sizes)).toBeLessThanOrEqual(1.5 * 1024 * 1024);
      expect(readBlocks).toHaveBeenCalledTimes(1);
    });
  }

  it("plain base64 and identity match their references", async () => {
    const bytes = pattern(BLOCK_BYTES + 2);
    for (const encoding of ["base64", "identity"] as const) {
      const segs: Segment[] = [{ kind: "staged", ref: REF, encoding, index: 0 }];
      const { file } = fileOf(bytes);
      const sink = createFixedLengthSink(assembledLength(segs, [file.meta]));
      const [out] = await Promise.all([drain(sink.readable), writeAssembled(segs, [file], sink, new AbortController().signal)]);
      const ref = encoding === "identity" ? Buffer.from(bytes) : Buffer.from(Buffer.from(bytes).toString("base64"));
      expect(Buffer.from(out).equals(ref)).toBe(true);
    }
  });

  it("splits a large text segment into chunks ≤ 1.5 MiB", async () => {
    const text = new Uint8Array(4 * 1024 * 1024).fill(0x61);
    const { sink, sizes } = recordingSink(text.byteLength);
    await Promise.all([drain(sink.readable), writeAssembled([{ kind: "text", bytes: text }], [], sink, new AbortController().signal)]);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(1.5 * 1024 * 1024);
  });

  it("reads each staged reference independently (same file twice → two reads)", async () => {
    const bytes = pattern(10);
    const a = fileOf(bytes);
    const b = fileOf(bytes);
    const segs: Segment[] = [
      { kind: "staged", ref: REF, encoding: "base64", index: 0 },
      { kind: "staged", ref: REF, encoding: "base64", index: 1 },
    ];
    const sink = createFixedLengthSink(assembledLength(segs, [a.file.meta, b.file.meta]));
    const [out] = await Promise.all([drain(sink.readable), writeAssembled(segs, [a.file, b.file], sink, new AbortController().signal)]);
    const one = Buffer.from(bytes).toString("base64");
    expect(Buffer.from(out).toString()).toBe(one + one);
    expect(a.readBlocks).toHaveBeenCalledTimes(1);
    expect(b.readBlocks).toHaveBeenCalledTimes(1);
  });

  it("a failing block read aborts the sink (consumer sees an error, never EOF) and rejects", async () => {
    const file: OpenStagedFile = {
      meta: meta(2 * BLOCK_BYTES),
      readBlocks: async (onBlock) => {
        await onBlock(new Uint8Array(BLOCK_BYTES), 0);
        throw new Error("stored file is corrupt");
      },
    };
    const segs: Segment[] = [{ kind: "staged", ref: REF, encoding: "identity", index: 0 }];
    const sink = createFixedLengthSink(2 * BLOCK_BYTES);
    const consumer = drain(sink.readable);
    await expect(writeAssembled(segs, [file], sink, new AbortController().signal)).rejects.toThrow(/corrupt/);
    await expect(consumer).rejects.toBeDefined();
  });

  it("an abort while blocked on backpressure rejects promptly and stops reading blocks", async () => {
    const delivered: number[] = [];
    const file: OpenStagedFile = {
      meta: meta(8 * BLOCK_BYTES),
      readBlocks: async (onBlock) => {
        for (let i = 0; i < 8; i++) {
          delivered.push(i);
          await onBlock(new Uint8Array(BLOCK_BYTES), i);
        }
      },
    };
    const segs: Segment[] = [{ kind: "staged", ref: REF, encoding: "identity", index: 0 }];
    const sink = createFixedLengthSink(8 * BLOCK_BYTES);
    const abortSpy = vi.spyOn(sink, "abort");
    const ctl = new AbortController();
    // Nobody reads the readable: the first write blocks on backpressure.
    const w = writeAssembled(segs, [file], sink, ctl.signal);
    await new Promise((r) => setTimeout(r, 10));
    ctl.abort(new Error("upstream answered early"));
    await expect(w).rejects.toThrow(/answered early/);
    expect(abortSpy).toHaveBeenCalled();
    expect(delivered.length).toBeLessThan(8);
  });

  it("an already-aborted signal writes nothing", async () => {
    const { file, readBlocks } = fileOf(pattern(10));
    const sink = createFixedLengthSink(10);
    const ctl = new AbortController();
    ctl.abort(new Error("deadline"));
    await expect(
      writeAssembled([{ kind: "staged", ref: REF, encoding: "identity", index: 0 }], [file], sink, ctl.signal),
    ).rejects.toThrow(/deadline/);
    expect(readBlocks).not.toHaveBeenCalled();
  });
});

describe("BOM-leading text segments (review: D6)", () => {
  it("the view keeps a leading U+FEFF, so view bytes equal the wire bytes", async () => {
    for (const segs of [
      [{ kind: "text", bytes: enc("﻿Subject: x\r\n\r\n") }] as Segment[],
      [
        { kind: "text", bytes: enc("From: me@x\r\nTo: ok@allowed\r\n") },
        { kind: "text", bytes: enc("﻿\r\nBcc: victim@external\r\n\r\nbody") },
      ] as Segment[],
    ]) {
      const v = buildInspectionView(segs, []);
      const sink = createFixedLengthSink(assembledLength(segs, []));
      const [out] = await Promise.all([drain(sink.readable), writeAssembled(segs, [], sink, new AbortController().signal)]);
      expect(Buffer.from(v.rawBody, "utf8").equals(Buffer.from(out))).toBe(true);
      expect(v.assembledByteLength).toBe(out.byteLength);
    }
  });
});
