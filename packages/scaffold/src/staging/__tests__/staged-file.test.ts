import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import {
  StagingBodyLengthMismatch,
  StagingTooLarge,
  blockSourceFromBase64,
  blockSourceFromBytes,
  blockSourceFromStream,
  stageFromBlocks,
  type BlockSource,
} from "../staged-file";
import { BLOCK_BYTES, blockCount, ciphertextLength, decryptBlock } from "../block-format";
import { deriveV2Key, sha256Bearer } from "../crypto";
import { lookupByHash } from "../repo";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
const NOW = 1_700_000_000;
const SIZES = [0, 1, BLOCK_BYTES - 1, BLOCK_BYTES, BLOCK_BYTES + 1, 3 * BLOCK_BYTES + 5];

export function pattern(n: number, seed = 7): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < n; i++) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    a[i] = x & 0xff;
  }
  return a;
}

function makeDeps(config: StagingConfig = CFG) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  return {
    d1, r2,
    deps: {
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config,
      uploadOrigin: "https://x.test",
      now: () => NOW,
    },
  };
}

async function collect(src: BlockSource): Promise<{ blocks: Uint8Array[]; total: number }> {
  const blocks: Uint8Array[] = [];
  const total = await src.read(async (b) => { blocks.push(b.slice()); });
  return { blocks, total };
}

function streamOf(chunks: Uint8Array[]): { stream: ReadableStream<Uint8Array>; cancelled: () => boolean; pulled: () => number } {
  let i = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (i < chunks.length) c.enqueue(chunks[i++]!);
      else c.close();
    },
    cancel() { cancelled = true; },
  });
  return { stream, cancelled: () => cancelled, pulled: () => i };
}

function split(bytes: Uint8Array, size: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let o = 0; o < bytes.byteLength; o += size) out.push(bytes.slice(o, Math.min(bytes.byteLength, o + size)));
  return out;
}

async function decryptObject(token: string, handle: string, iv: Uint8Array, obj: Uint8Array, byteLen: number): Promise<Uint8Array> {
  const key = await deriveV2Key(token, handle);
  const n = blockCount(byteLen);
  const out = new Uint8Array(byteLen);
  let off = 0;
  let pos = 0;
  for (let i = 0; i < n; i++) {
    const plainLen = i < n - 1 ? BLOCK_BYTES : byteLen - (n - 1) * BLOCK_BYTES;
    const pt = await decryptBlock(key, iv, handle, i, n, byteLen, obj.subarray(pos, pos + plainLen + 16));
    out.set(pt, off);
    off += pt.byteLength;
    pos += plainLen + 16;
  }
  return out;
}

describe("blockSourceFromBytes", () => {
  it("yields BLOCK_BYTES blocks then the remainder", async () => {
    const x = pattern(2 * BLOCK_BYTES + 10);
    const src = blockSourceFromBytes(x);
    expect(src.byteLength).toBe(x.byteLength);
    const { blocks, total } = await collect(src);
    expect(blocks.map((b) => b.byteLength)).toEqual([BLOCK_BYTES, BLOCK_BYTES, 10]);
    expect(total).toBe(x.byteLength);
    expect(Buffer.concat(blocks).equals(Buffer.from(x))).toBe(true);
  });

  it("yields nothing for an empty input", async () => {
    expect((await collect(blockSourceFromBytes(new Uint8Array(0)))).blocks).toHaveLength(0);
  });
});

describe("stageFromBlocks", () => {
  for (const size of SIZES) {
    it(`stages ${size} bytes as one v2 object of ciphertextLength through a stream put`, async () => {
      const { d1, r2, deps } = makeDeps();
      const x = pattern(size, size + 1);
      const out = await stageFromBlocks(deps, blockSourceFromBytes(x), "application/pdf", "q.pdf");
      expect(out.ok).toBe(true);
      if (!out.ok) return;
      expect(out.byte_length).toBe(size);
      expect(r2.store.size).toBe(1);
      expect(r2.putKinds).toEqual(["stream"]);
      const obj = [...r2.store.values()][0]!;
      expect(obj.byteLength).toBe(ciphertextLength(size));
      const row = await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(out.token));
      expect(row!.enc_version).toBe(2);
      expect(row!.state).toBe("claimed");
      expect(row!.byte_len).toBe(size);
      expect(row!.iv!.byteLength).toBe(8);
      expect(row!.content_type).toBe("application/pdf");
      expect(row!.filename).toBe("q.pdf");
      const plain = await decryptObject(out.token, out.file_handle, row!.iv!, obj, size);
      expect(Buffer.from(plain).equals(Buffer.from(x))).toBe(true);
    });
  }

  it("stages a stream source of unknown length (buffered path) to the identical format", async () => {
    const { d1, r2, deps } = makeDeps();
    const x = pattern(BLOCK_BYTES + 77);
    const { stream } = streamOf(split(x, 65_536));
    const out = await stageFromBlocks(deps, blockSourceFromStream(stream, null, CFG.maxBytes), "text/plain", null);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(r2.putKinds).toEqual(["stream"]);
    const obj = [...r2.store.values()][0]!;
    expect(obj.byteLength).toBe(ciphertextLength(x.byteLength));
    const row = await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(out.token));
    const plain = await decryptObject(out.token, out.file_handle, row!.iv!, obj, x.byteLength);
    expect(Buffer.from(plain).equals(Buffer.from(x))).toBe(true);
  });

  it("returns 413 for a known length over maxBytes without writing", async () => {
    const { r2, d1, deps } = makeDeps({ ...CFG, maxBytes: 10 });
    const out = await stageFromBlocks(deps, blockSourceFromBytes(new Uint8Array(11)), "x/y", null);
    expect(out).toMatchObject({ ok: false, status: 413 });
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });

  it("returns 413 and leaves no object or row when a stream passes maxBytes", async () => {
    const { r2, d1, deps } = makeDeps();
    const { stream } = streamOf([new Uint8Array(8), new Uint8Array(8)]);
    const out = await stageFromBlocks(deps, blockSourceFromStream(stream, null, 10), "x/y", null);
    expect(out).toMatchObject({ ok: false, status: 413 });
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });

  it("returns 400 and leaves nothing behind for bad base64", async () => {
    const { r2, d1, deps } = makeDeps();
    const s = "AAAA!AAA";
    const out = await stageFromBlocks(deps, blockSourceFromBase64(s, 0, s.length, "std"), "x/y", null);
    expect(out).toMatchObject({ ok: false, status: 400 });
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });

  it("returns 500 and no row when R2 put rejects", async () => {
    const { r2, d1, deps } = makeDeps();
    r2.put = async () => { throw new Error("boom"); };
    const out = await stageFromBlocks(deps, blockSourceFromBytes(pattern(BLOCK_BYTES + 3)), "x/y", null);
    expect(out).toMatchObject({ ok: false, status: 500 });
    expect(d1.rows.size).toBe(0);
  });

  it("returns 500 and deletes the object when the D1 insert fails", async () => {
    const { r2, d1, deps } = makeDeps();
    d1.prepare = () => { throw new Error("d1 down"); };
    const out = await stageFromBlocks(deps, blockSourceFromBytes(pattern(5)), "x/y", null);
    expect(out).toMatchObject({ ok: false, status: 500 });
    expect(r2.store.size).toBe(0);
  });
});

describe("blockSourceFromStream", () => {
  it("re-blocks chunks that straddle block boundaries (known length)", async () => {
    const x = pattern(2 * BLOCK_BYTES + 3);
    const { stream } = streamOf(split(x, 300_007));
    const src = blockSourceFromStream(stream, x.byteLength, CFG.maxBytes);
    expect(src.byteLength).toBe(x.byteLength);
    const { blocks, total } = await collect(src);
    expect(blocks.map((b) => b.byteLength)).toEqual([BLOCK_BYTES, BLOCK_BYTES, 3]);
    expect(total).toBe(x.byteLength);
    expect(Buffer.concat(blocks).equals(Buffer.from(x))).toBe(true);
  });

  it("handles a null contentLength", async () => {
    const x = pattern(BLOCK_BYTES + 1);
    const { stream } = streamOf(split(x, BLOCK_BYTES + 1));
    const src = blockSourceFromStream(stream, null, CFG.maxBytes);
    expect(src.byteLength).toBeNull();
    const { blocks, total } = await collect(src);
    expect(blocks.map((b) => b.byteLength)).toEqual([BLOCK_BYTES, 1]);
    expect(total).toBe(x.byteLength);
  });

  it("throws StagingTooLarge at the first byte past maxBytes and cancels the reader", async () => {
    const { stream, cancelled, pulled } = streamOf([new Uint8Array(5), new Uint8Array(5), new Uint8Array(1), new Uint8Array(100)]);
    const src = blockSourceFromStream(stream, null, 10);
    await expect(collect(src)).rejects.toBeInstanceOf(StagingTooLarge);
    expect(cancelled()).toBe(true);
    expect(pulled()).toBeLessThan(4);
  });

  it("throws StagingTooLarge before reading when the declared length is over maxBytes", async () => {
    const { stream, cancelled, pulled } = streamOf([new Uint8Array(5)]);
    const src = blockSourceFromStream(stream, 11, 10);
    await expect(collect(src)).rejects.toBeInstanceOf(StagingTooLarge);
    expect(cancelled()).toBe(true);
    expect(pulled()).toBe(0);
  });

  it("rejects a body that runs past the declared length, cancelling the reader", async () => {
    const { stream, cancelled } = streamOf([new Uint8Array(6), new Uint8Array(6)]);
    const src = blockSourceFromStream(stream, 8, 100);
    await expect(collect(src)).rejects.toBeInstanceOf(StagingBodyLengthMismatch);
    expect(cancelled()).toBe(true);
  });

  it("rejects a body that ends short of the declared length", async () => {
    const { stream } = streamOf([new Uint8Array(6)]);
    const src = blockSourceFromStream(stream, 8, 100);
    await expect(collect(src)).rejects.toBeInstanceOf(StagingBodyLengthMismatch);
  });

  it("is single-use", async () => {
    const { stream } = streamOf([new Uint8Array(1)]);
    const src = blockSourceFromStream(stream, null, 100);
    await collect(src);
    await expect(collect(src)).rejects.toThrow();
  });
});

describe("blockSourceFromBase64", () => {
  const x = pattern(2 * BLOCK_BYTES + 5); // ≡ 1 (mod 3): two padding chars

  it.each([
    ["std padded", Buffer.from(x).toString("base64"), "std"],
    ["std unpadded", Buffer.from(x).toString("base64").replace(/=+$/, ""), "std"],
    ["url unpadded", Buffer.from(x).toString("base64url"), "url"],
    ["url padded", Buffer.from(x).toString("base64url") + "==", "url"],
  ] as const)("decodes %s straight into blocks", async (_l, s, alphabet) => {
    const src = blockSourceFromBase64(s, 0, s.length, alphabet);
    expect(src.byteLength).toBe(x.byteLength);
    const { blocks, total } = await collect(src);
    expect(blocks.map((b) => b.byteLength)).toEqual([BLOCK_BYTES, BLOCK_BYTES, 5]);
    expect(total).toBe(x.byteLength);
    expect(Buffer.concat(blocks).equals(Buffer.from(x))).toBe(true);
  });

  it("round-trips every small length (quantum alignment at block edges)", async () => {
    for (let n = 0; n < 40; n++) {
      const y = pattern(n, n + 11);
      const s = Buffer.from(y).toString("base64");
      const { blocks } = await collect(blockSourceFromBase64(s, 0, s.length, "std"));
      expect(Buffer.concat(blocks).equals(Buffer.from(y))).toBe(true);
    }
  });

  it.each([
    ["a bad character", "AAAA!AAA", "std"],
    ["the wrong alphabet", "AAAA-_AA", "std"],
    ["a length ≡ 1 mod 4", "AAAAA", "std"],
    ["padding mid-string", "AA==AAAA", "std"],
  ] as const)("rejects %s", async (_l, s, alphabet) => {
    await expect((async () => collect(blockSourceFromBase64(s, 0, s.length, alphabet)))()).rejects.toThrow();
  });

  it("rejects a bad character deep in a later block", async () => {
    const s = Buffer.from(pattern(BLOCK_BYTES * 2)).toString("base64");
    const bad = s.slice(0, s.length - 10) + "*" + s.slice(s.length - 9);
    const seen: number[] = [];
    await expect(
      blockSourceFromBase64(bad, 0, bad.length, "std").read(async (b) => { seen.push(b.byteLength); }),
    ).rejects.toThrow();
    expect(seen.length).toBeLessThan(3);
  });
});

describe("unknown-length slot (shared with /staging/upload)", () => {
  function heldStream() {
    let pulls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let sent = false;
    const stream = new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          pulls++;
          await gate;
          if (!sent) { sent = true; c.enqueue(new Uint8Array([1, 2, 3])); return; }
          c.close();
        },
      },
      { highWaterMark: 0 },
    );
    return { stream, release, pulls: () => pulls };
  }

  it("a second concurrent unknown-length stage → 503 without reading its source; known-length unaffected; freed after", async () => {
    const { deps } = makeDeps();
    const first = heldStream();
    const p1 = stageFromBlocks(deps, blockSourceFromStream(first.stream, null, CFG.maxBytes), "x/y", null);
    await new Promise((r) => setTimeout(r, 10));

    const second = heldStream();
    const out2 = await stageFromBlocks(deps, blockSourceFromStream(second.stream, null, CFG.maxBytes), "x/y", null);
    expect(out2).toMatchObject({ ok: false, status: 503 });
    expect(out2.ok ? "" : out2.message).toMatch(/retry shortly, or send Content-Length/);
    expect(second.pulls()).toBe(0);

    const known = await stageFromBlocks(deps, blockSourceFromBytes(pattern(10)), "x/y", null);
    expect(known.ok).toBe(true);

    first.release();
    expect((await p1).ok).toBe(true);
    const third = streamOf([new Uint8Array(4)]);
    expect((await stageFromBlocks(deps, blockSourceFromStream(third.stream, null, CFG.maxBytes), "x/y", null)).ok).toBe(true);
  });

  it("an upload without Content-Length during an in-flight unknown-length stage → 503 + Retry-After", async () => {
    const { handleUpload } = await import("../upload-handler");
    const { insertPending } = await import("../repo");
    const { mintToken, mintFileHandle } = await import("../tokens");
    const { d1, deps } = makeDeps();
    const first = heldStream();
    const p1 = stageFromBlocks(deps, blockSourceFromStream(first.stream, null, CFG.maxBytes), "x/y", null);
    await new Promise((r) => setTimeout(r, 10));

    const token = mintToken();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: await sha256Bearer(token), file_handle: mintFileHandle(), content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: NOW, expires_at: NOW + 300,
    });
    const body = heldStream();
    const res = await handleUpload(
      new Request("https://x.test/staging/upload", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: body.stream,
        duplex: "half",
      } as RequestInit),
      { ...deps, now: () => NOW + 1 },
    );
    expect(res.status).toBe(503);
    expect(res.headers.get("Retry-After")).toBe("1");
    expect(body.pulls()).toBe(0);
    first.release();
    await p1;
  });

  it("a block source that throws mid-read → 502 upstream body read failed", async () => {
    const { deps, r2, d1 } = makeDeps();
    const src: BlockSource = {
      byteLength: 3 * BLOCK_BYTES,
      async read(onBlock) {
        await onBlock(new Uint8Array(BLOCK_BYTES));
        throw new TypeError("network connection lost");
      },
    };
    const out = await stageFromBlocks(deps, src, "x/y", null);
    expect(out).toEqual({ ok: false, status: 502, message: "upstream body read failed" });
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });
});
