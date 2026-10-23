import { describe, it, expect, vi, afterEach } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { seedV1Row } from "./__fixtures__/v1-row";
import {
  StagedFileReadError,
  blockSourceFromBytes,
  createStagedFileOpener,
  isPlausibleStagedRef,
  stageFromBlocks,
  type OpenStagedResult,
  type StagedRef,
} from "../staged-file";
import { BLOCK_BYTES } from "../block-format";
import { insertPending, lookupByHash } from "../repo";
import { sha256Bearer } from "../crypto";
import { mintFileHandle, mintToken } from "../tokens";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = {
  uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024, getFileMaxBytes: 64,
};
const NOW = 1_700_000_000;

function pattern(n: number, seed = 3): Uint8Array {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i++) a[i] = (i * 131 + seed) & 0xff;
  return a;
}

function setup(now = NOW) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const open = createStagedFileOpener({
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    now: () => now,
  });
  const stage = async (bytes: Uint8Array, ct = "application/pdf", filename: string | null = "q.pdf") => {
    const out = await stageFromBlocks(
      {
        STAGING_D1: d1 as unknown as D1Database,
        STAGING_R2: r2 as unknown as R2Bucket,
        config: CFG,
        uploadOrigin: "https://x.test",
        now: () => NOW,
      },
      blockSourceFromBytes(bytes),
      ct,
      filename,
    );
    if (!out.ok) throw new Error("stage failed");
    return { file_handle: out.file_handle, token: out.token };
  };
  return { d1, r2, open, stage };
}

function assertNoSecrets(r: OpenStagedResult | Error, ref: StagedRef) {
  const msg = r instanceof Error ? r.message : r.ok ? "" : r.message;
  expect(msg).not.toContain(ref.token);
  expect(msg).not.toContain(ref.file_handle);
  expect(msg).not.toContain(ref.token.slice(4, 20));
}

async function readAll(r: OpenStagedResult): Promise<{ blocks: Uint8Array[]; indices: number[] }> {
  if (!r.ok) throw new Error("not ok");
  const blocks: Uint8Array[] = [];
  const indices: number[] = [];
  await r.file.readBlocks(async (b, i) => { blocks.push(b.slice()); indices.push(i); });
  return { blocks, indices };
}

afterEach(() => vi.restoreAllMocks());

describe("isPlausibleStagedRef", () => {
  it("accepts minted values", () => {
    expect(isPlausibleStagedRef({ file_handle: mintFileHandle(), token: mintToken() })).toBe(true);
  });
  it.each([
    ["null", null],
    ["a string", "fh_x"],
    ["missing token", { file_handle: mintFileHandle() }],
    ["swapped prefixes", { file_handle: mintToken(), token: mintFileHandle() }],
    ["short handle", { file_handle: "fh_AAAA", token: mintToken() }],
    ["non-string", { file_handle: 1, token: 2 }],
    ["whitespace in token", { file_handle: mintFileHandle(), token: mintToken() + " " }],
  ])("rejects %s", (_l, v) => {
    expect(isPlausibleStagedRef(v)).toBe(false);
  });
});

describe("createStagedFileOpener — resolution (D1 only)", () => {
  it("400 for an implausible ref, with no I/O", async () => {
    const { open, r2 } = setup();
    const r = await open({ file_handle: "fh_x", token: "stg_y" });
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect(r2.getCalls).toBe(0);
  });

  it("403 for a token/handle pair that does not match, with no R2 read", async () => {
    const { open, stage, r2 } = setup();
    const a = await stage(pattern(10));
    const ref = { file_handle: mintFileHandle(), token: a.token };
    const r = await open(ref);
    expect(r).toMatchObject({ ok: false, status: 403 });
    assertNoSecrets(r, ref);
    const r2b = await open({ file_handle: a.file_handle, token: mintToken() });
    expect(r2b).toMatchObject({ ok: false, status: 403 });
    expect(r2.getCalls).toBe(0);
  });

  it("409 for a pending upload", async () => {
    const { open, d1 } = setup();
    const ref = { file_handle: mintFileHandle(), token: mintToken() };
    await insertPending(d1 as unknown as D1Database, {
      token_hash: await sha256Bearer(ref.token), file_handle: ref.file_handle, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: NOW, expires_at: NOW + 300,
    });
    const r = await open(ref);
    expect(r).toMatchObject({ ok: false, status: 409 });
    assertNoSecrets(r, ref);
  });

  it("410 for an expired row", async () => {
    const s = setup();
    const ref = await s.stage(pattern(4));
    const later = createStagedFileOpener({
      STAGING_D1: s.d1 as unknown as D1Database,
      STAGING_R2: s.r2 as unknown as R2Bucket,
      config: CFG,
      now: () => NOW + 3600,
    });
    const r = await later(ref);
    expect(r).toMatchObject({ ok: false, status: 410 });
    assertNoSecrets(r, ref);
  });

  it("410 for a row already marked corrupt", async () => {
    const { open, stage, d1, r2 } = setup();
    const ref = await stage(pattern(4));
    const row = (await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(ref.token)))!;
    d1.rows.get(Buffer.from(row.token_hash).toString("hex"))!.state = "corrupt";
    expect(await open(ref)).toMatchObject({ ok: false, status: 410 });
    expect(r2.getCalls).toBe(0);
  });

  it("does not open R2 until readBlocks is called", async () => {
    const { open, stage, r2 } = setup();
    const ref = await stage(pattern(4));
    const r = await open(ref);
    expect(r.ok).toBe(true);
    expect(r2.getCalls).toBe(0);
  });
});

describe("createStagedFileOpener — v2 reads", () => {
  it("yields BLOCK_BYTES blocks then the remainder, in order, with meta from the row", async () => {
    const { open, stage, r2 } = setup();
    r2.chunkBytes = 300_007; // R2 body chunks straddle block boundaries
    const x = pattern(2 * BLOCK_BYTES + 5);
    const ref = await stage(x, "application/pdf", "q.pdf");
    const r = await open(ref);
    expect(r.ok && r.file.meta).toEqual({ byteLength: x.byteLength, contentType: "application/pdf", filename: "q.pdf" });
    const { blocks, indices } = await readAll(r);
    expect(blocks.map((b) => b.byteLength)).toEqual([BLOCK_BYTES, BLOCK_BYTES, 5]);
    expect(indices).toEqual([0, 1, 2]);
    expect(Buffer.concat(blocks).equals(Buffer.from(x))).toBe(true);
  });

  it("yields one empty block for a zero-byte file", async () => {
    const { open, stage } = setup();
    const ref = await stage(new Uint8Array(0));
    const { blocks } = await readAll(await open(ref));
    expect(blocks.map((b) => b.byteLength)).toEqual([0]);
  });

  it("an object whose size is not ciphertextLength → corrupt + 410, no block delivered", async () => {
    const { open, stage, r2, d1 } = setup();
    const ref = await stage(pattern(100));
    const [k, v] = [...r2.store.entries()][0]!;
    r2.store.set(k, Buffer.concat([v, new Uint8Array(1)]));
    const r = await open(ref);
    const cb = vi.fn(async () => {});
    const err = await (r.ok ? r.file.readBlocks(cb) : Promise.reject(new Error("x"))).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StagedFileReadError);
    expect((err as StagedFileReadError).status).toBe(410);
    assertNoSecrets(err as Error, ref);
    expect(cb).not.toHaveBeenCalled();
    expect((await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(ref.token)))!.state).toBe("corrupt");
  });

  it("a missing object → 500-class read error, no block", async () => {
    const { open, stage, r2 } = setup();
    const ref = await stage(pattern(100));
    r2.store.clear();
    const r = await open(ref);
    const cb = vi.fn(async () => {});
    const err = await (r.ok ? r.file.readBlocks(cb) : Promise.resolve()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StagedFileReadError);
    expect(cb).not.toHaveBeenCalled();
  });

  it("a tampered block stops delivery before it: earlier blocks only, then a generic rejection", async () => {
    const { open, stage, r2, d1 } = setup();
    const ref = await stage(pattern(2 * BLOCK_BYTES + 5));
    const [, v] = [...r2.store.entries()][0]!;
    v[BLOCK_BYTES + 16 + 10] = v[BLOCK_BYTES + 16 + 10]! ^ 0xff; // inside block 1
    const r = await open(ref);
    const seen: number[] = [];
    const err = await (r.ok ? r.file.readBlocks(async (_b, i) => { seen.push(i); }) : Promise.resolve()).catch((e: unknown) => e);
    expect(seen).toEqual([0]);
    expect(err).toBeInstanceOf(StagedFileReadError);
    expect((err as StagedFileReadError).status).toBe(410);
    assertNoSecrets(err as Error, ref);
    expect((await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(ref.token)))!.state).toBe("corrupt");
  });

  it("swapped blocks fail authentication", async () => {
    const { open, stage, r2 } = setup();
    const ref = await stage(pattern(2 * BLOCK_BYTES));
    const [k, v] = [...r2.store.entries()][0]!;
    const a = v.slice(0, BLOCK_BYTES + 16);
    const b = v.slice(BLOCK_BYTES + 16);
    r2.store.set(k, Buffer.concat([b, a]));
    const r = await open(ref);
    const seen: number[] = [];
    await expect(r.ok ? r.file.readBlocks(async (_b, i) => { seen.push(i); }) : Promise.resolve()).rejects.toBeInstanceOf(StagedFileReadError);
    expect(seen).toEqual([]);
  });

  it("a body that ends short after the size check → 500 read error; the row is NOT marked corrupt", async () => {
    const { open, stage, r2, d1 } = setup();
    const ref = await stage(pattern(2 * BLOCK_BYTES + 5));
    const realGet = r2.get.bind(r2);
    r2.get = async (key: string) => {
      const o = await realGet(key);
      if (!o) return o;
      const full = r2.store.get(key)!;
      return {
        ...o,
        size: o.size, // right size …
        get body() {  // … but the stream stops one byte short
          return new ReadableStream<Uint8Array>({
            start(c) { c.enqueue(full.slice(0, full.byteLength - 1)); c.close(); },
          });
        },
      };
    };
    const r = await open(ref);
    const err = await (r.ok ? r.file.readBlocks(async () => {}) : Promise.resolve()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StagedFileReadError);
    expect((err as StagedFileReadError).status).toBe(500);
    expect((await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(ref.token)))!.state).toBe("claimed");
  });

  it("propagates a callback error unchanged and does not mark the row corrupt", async () => {
    const { open, stage, d1 } = setup();
    const ref = await stage(pattern(2 * BLOCK_BYTES));
    const r = await open(ref);
    const boom = new Error("sink closed");
    await expect(r.ok ? r.file.readBlocks(async () => { throw boom; }) : Promise.resolve()).rejects.toBe(boom);
    expect((await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(ref.token)))!.state).toBe("claimed");
  });

  it("readBlocks is single-use", async () => {
    const { open, stage } = setup();
    const r = await open(await stage(pattern(5)));
    await readAll(r);
    await expect(readAll(r)).rejects.toThrow();
  });
});

describe("createStagedFileOpener — legacy rows are refused", () => {
  const LEGACY = { ok: false, status: 410, message: "stored in a legacy format; re-stage the file" };

  it("refuses a v1 row within STAGING_GETFILE_MAX_BYTES with 410 'legacy format', no R2 read, no decrypt, not marked corrupt", async () => {
    const { open, d1, r2 } = setup();
    const seeded = await seedV1Row(d1, r2, pattern(64), { now: NOW });
    const ref = { file_handle: seeded.handle, token: seeded.token };
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    const r = await open(ref);
    expect(r).toEqual(LEGACY);
    assertNoSecrets(r, ref);
    expect(decrypt).not.toHaveBeenCalled();
    expect(r2.getCalls).toBe(0);
    expect((await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(ref.token)))!.state).toBe("claimed");
  });

  it("refuses a v1 row over STAGING_GETFILE_MAX_BYTES with the same message", async () => {
    const { open, d1, r2 } = setup();
    const seeded = await seedV1Row(d1, r2, pattern(65), { now: NOW });
    const r = await open({ file_handle: seeded.handle, token: seeded.token });
    expect(r).toEqual(LEGACY);
    expect(r2.getCalls).toBe(0);
  });

  it("refuses a v1 row with a null iv or r2_key with 410 'legacy format', not 500", async () => {
    const { open, d1, r2 } = setup();
    for (const field of ["iv_hex", "r2_key"] as const) {
      const seeded = await seedV1Row(d1, r2, pattern(10), { now: NOW });
      const ref = { file_handle: seeded.handle, token: seeded.token };
      d1.rows.get(Buffer.from(await sha256Bearer(ref.token)).toString("hex"))![field] = null as never;
      expect(await open(ref)).toEqual(LEGACY);
    }
    expect(r2.getCalls).toBe(0);
  });

  it("refuses a pre-0002 row (enc_version null) with the same message", async () => {
    const { open, d1, r2, stage } = setup();
    const ref = await stage(pattern(10));
    d1.rows.get(Buffer.from(await sha256Bearer(ref.token)).toString("hex"))!.enc_version = null as never;
    const r = await open(ref);
    expect(r).toEqual(LEGACY);
    expect(r2.getCalls).toBe(0);
  });
});
