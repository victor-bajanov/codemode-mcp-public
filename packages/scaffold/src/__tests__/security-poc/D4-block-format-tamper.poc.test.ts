// D4 — Blockwise AES-GCM v2 at-rest format: tamper handling (issue #59, D2, red-team R-5).
//
// Attacker: an R2 writer (object-level access to the staging bucket) and/or a
//   D1 writer (row-level access to the staging table), neither holding the
//   bearer token. Also a legitimate token holder whose object was damaged.
// Precondition: v2 rows written by the real block loop; readers are the real
//   opener, getFile and /staging/fetch.
// Payloads: C1 swap two blocks; C2 drop the last block; C3 append a
//   duplicate block; C4 splice a block (or the whole object) from another
//   file; C5 swap `r2_key` between two rows; C6 `byte_len` ± 1; C7 flip
//   `enc_version` 2→1 and 1→2; C8 nonce-prefix and secret uniqueness over
//   10 000 mints; C9 zero-length and exact-multiple files; C10 corrupt is
//   sticky; C11 a tamper in block 2 served through /staging/fetch.
// Control: nonce = prefix ‖ BE32(index), AAD = handle ‖ version ‖ index ‖
//   count ‖ length; the object size is checked before any decrypt; every
//   block is authenticated before it is handed on; any failure marks the row
//   corrupt (sticky, no further R2 read) and aborts the sink (never a clean
//   EOF); a legacy (enc_version 1) row is refused without a read.
// Invariant asserted everywhere: NO block is emitted unless it
//   authenticated; any failure aborts; corrupt is sticky.
//
// Pre-v2 reasoning: v1 sealed the whole object once (AAD = handle only), so
// position attacks did not exist but one-shot decrypt held 2F; the v2 block
// AAD/nonce construction and the size pre-check are new. Removing the size
// check (verified by mutation) makes C2/C3/C6 reach `crypto.subtle.decrypt`.
//
// FakeD1/FakeR2 only. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { seedV1Row } from "../../staging/__tests__/__fixtures__/v1-row";
import {
  StagedFileReadError,
  blockSourceFromBytes,
  createStagedFileOpener,
  stageFromBlocks,
  type OpenStagedResult,
  type StagedRef,
} from "../../staging/staged-file";
import { blockAad, blockNonce, blockCount, ciphertextLength } from "../../staging/block-format";
import { handleFetch } from "../../staging/fetch-handler";
import { createGetFileCapability } from "../../staging/getfile-capability";
import { lookupByHash } from "../../staging/repo";
import { sha256Bearer } from "../../staging/crypto";
import { BLOCK_BYTES, GCM_TAG_BYTES, type StagingConfig } from "../../staging/types";

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024, getFileMaxBytes: 4 * BLOCK_BYTES };
const TAG = GCM_TAG_BYTES;

function pattern(n: number, seed = 11): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const D1 = d1 as unknown as D1Database;
  const R2 = r2 as unknown as R2Bucket;
  const deps = { STAGING_D1: D1, STAGING_R2: R2, config: CFG, uploadOrigin: "https://x.test", now: () => NOW };
  const open = createStagedFileOpener(deps);
  const stage = async (bytes: Uint8Array, seedless = false): Promise<StagedRef & { r2_key: string }> => {
    const r = await stageFromBlocks(deps, blockSourceFromBytes(bytes), "application/pdf", seedless ? null : "q.pdf");
    if (!r.ok) throw new Error("stage failed");
    const row = (await lookupByHash(D1, await sha256Bearer(r.token)))!;
    return { file_handle: r.file_handle, token: r.token, r2_key: row.r2_key! };
  };
  const rowOf = async (ref: StagedRef) => d1.rows.get(Buffer.from(await sha256Bearer(ref.token)).toString("hex"))!;
  const state = async (ref: StagedRef) => (await rowOf(ref)).state;
  const object = (key: string) => r2.store.get(key)!;
  const setObject = (key: string, v: Uint8Array) => r2.store.set(key, v);
  /** Read every block; resolves with what the callback saw and the error, if any. */
  const read = async (ref: StagedRef) => {
    const r = await open(ref);
    const seen: Array<{ index: number; bytes: Uint8Array }> = [];
    if (!r.ok) return { opened: r, seen, err: null as unknown };
    const err = await r.file.readBlocks(async (b, i) => void seen.push({ index: i, bytes: b.slice() })).then(() => null, (e: unknown) => e);
    return { opened: r, seen, err };
  };
  return { d1, r2, deps, open, stage, rowOf, state, object, setObject, read };
}

/** The n-th sealed block (ct ‖ tag) of an object of `byteLen` plaintext bytes. */
function blockSlice(obj: Uint8Array, byteLen: number, i: number): Uint8Array {
  const n = blockCount(byteLen);
  const start = i * (BLOCK_BYTES + TAG);
  const plainLen = i < n - 1 ? BLOCK_BYTES : byteLen - (n - 1) * BLOCK_BYTES;
  return obj.slice(start, start + plainLen + TAG);
}

function expectCorruptRead(r: { opened: OpenStagedResult; seen: unknown[]; err: unknown }, ref: StagedRef) {
  expect(r.opened.ok).toBe(true);
  expect(r.err).toBeInstanceOf(StagedFileReadError);
  expect((r.err as StagedFileReadError).status).toBe(410);
  const msg = (r.err as Error).message;
  expect(msg).not.toContain(ref.token);
  expect(msg).not.toContain(ref.file_handle);
}

afterEach(() => vi.restoreAllMocks());

describe("D4 — object-level tampers (R2 writer)", () => {
  const LEN = 2 * BLOCK_BYTES + 5;

  it("FIXED (#59): C1 swapped blocks → nothing delivered, 410, row corrupt", async () => {
    const w = world();
    const ref = await w.stage(pattern(LEN));
    const obj = w.object(ref.r2_key);
    const [b0, b1, b2] = [0, 1, 2].map((i) => blockSlice(obj, LEN, i));
    w.setObject(ref.r2_key, Buffer.concat([b1!, b0!, b2!]));
    const r = await w.read(ref);
    expectCorruptRead(r, ref);
    expect(r.seen).toEqual([]);
    expect(await w.state(ref)).toBe("corrupt");
  });

  it("FIXED (#59): C2 last block dropped → size check fails, 410, no decrypt attempted", async () => {
    const w = world();
    const ref = await w.stage(pattern(LEN));
    const obj = w.object(ref.r2_key);
    w.setObject(ref.r2_key, obj.slice(0, obj.byteLength - (5 + TAG)));
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    const r = await w.read(ref);
    expectCorruptRead(r, ref);
    expect(r.seen).toEqual([]);
    expect(decrypt).not.toHaveBeenCalled();
    expect(await w.state(ref)).toBe("corrupt");
  });

  it("FIXED (#59): C3 a duplicate block appended → size check fails, 410, no decrypt attempted", async () => {
    const w = world();
    const ref = await w.stage(pattern(LEN));
    const obj = w.object(ref.r2_key);
    w.setObject(ref.r2_key, Buffer.concat([obj, blockSlice(obj, LEN, 1)]));
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    const r = await w.read(ref);
    expectCorruptRead(r, ref);
    expect(decrypt).not.toHaveBeenCalled();
    expect(r.seen).toEqual([]);
  });

  it("FIXED (#59): C3' the last block replaced by a copy of block 0 (same size) → block 0 delivered, then 410 at the duplicate", async () => {
    const w = world();
    const len = 2 * BLOCK_BYTES;
    const ref = await w.stage(pattern(len));
    const obj = w.object(ref.r2_key);
    w.setObject(ref.r2_key, Buffer.concat([blockSlice(obj, len, 0), blockSlice(obj, len, 0)]));
    const r = await w.read(ref);
    expectCorruptRead(r, ref);
    expect(r.seen.map((s) => s.index)).toEqual([0]); // only the authenticated block reached the consumer
    expect(await w.state(ref)).toBe("corrupt");
  });

  it("FIXED (#59): C4 a block spliced from another file (same position, same size) → earlier blocks only, 410; the whole object swapped → nothing", async () => {
    const w = world();
    const a = await w.stage(pattern(LEN, 1));
    const b = await w.stage(pattern(LEN, 2));
    const objA = w.object(a.r2_key);
    const objB = w.object(b.r2_key);
    w.setObject(a.r2_key, Buffer.concat([blockSlice(objA, LEN, 0), blockSlice(objB, LEN, 1), blockSlice(objA, LEN, 2)]));
    const r = await w.read(a);
    expectCorruptRead(r, a);
    expect(r.seen.map((s) => s.index)).toEqual([0]);
    expect(Buffer.from(r.seen[0]!.bytes).equals(Buffer.from(pattern(LEN, 1).subarray(0, BLOCK_BYTES)))).toBe(true);
    // Whole-object splice: file B's object under file A's row (different handle in the AAD and key).
    const c = await w.stage(pattern(LEN, 3));
    w.setObject(c.r2_key, objB.slice());
    const r2 = await w.read(c);
    expectCorruptRead(r2, c);
    expect(r2.seen).toEqual([]);
  });

  it("REFUTED: a single flipped bit anywhere in a block (ciphertext or tag) stops delivery at that block", async () => {
    const w = world();
    for (const offset of [0, BLOCK_BYTES - 1, BLOCK_BYTES + TAG - 1, BLOCK_BYTES + TAG, 2 * (BLOCK_BYTES + TAG) + 4 + TAG - 1]) {
      const ref = await w.stage(pattern(LEN));
      const obj = w.object(ref.r2_key);
      obj[offset] = obj[offset]! ^ 0x01;
      const r = await w.read(ref);
      expectCorruptRead(r, ref);
      const hitBlock = Math.floor(offset / (BLOCK_BYTES + TAG));
      expect(r.seen.map((s) => s.index), `offset ${offset}`).toEqual(Array.from({ length: hitBlock }, (_, i) => i));
    }
  });
});

describe("D4 — row-level tampers (D1 writer)", () => {
  const LEN = BLOCK_BYTES + 100;

  it("FIXED (#59): C5 r2_key swapped between two rows → both 410 at block 0, no plaintext", async () => {
    const w = world();
    const a = await w.stage(pattern(LEN, 1));
    const b = await w.stage(pattern(LEN, 2));
    const rowA = await w.rowOf(a);
    const rowB = await w.rowOf(b);
    [rowA.r2_key, rowB.r2_key] = [rowB.r2_key, rowA.r2_key];
    for (const ref of [a, b]) {
      const r = await w.read(ref);
      expectCorruptRead(r, ref);
      expect(r.seen).toEqual([]);
    }
  });

  it("FIXED (#59): C6 byte_len ± 1 → size check fails before any decrypt", async () => {
    const w = world();
    for (const delta of [1, -1]) {
      const ref = await w.stage(pattern(LEN));
      (await w.rowOf(ref)).byte_len = LEN + delta;
      const decrypt = vi.spyOn(crypto.subtle, "decrypt");
      const r = await w.read(ref);
      expectCorruptRead(r, ref);
      expect(decrypt).not.toHaveBeenCalled();
      expect(r.seen).toEqual([]);
      decrypt.mockRestore();
    }
  });

  it("FIXED (#59): C6' byte_len shrunk by a whole block (object now 'too long') → 410, no decrypt", async () => {
    const w = world();
    const ref = await w.stage(pattern(2 * BLOCK_BYTES));
    (await w.rowOf(ref)).byte_len = BLOCK_BYTES;
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    const r = await w.read(ref);
    expectCorruptRead(r, ref);
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("FIXED (#59, v1 reader removed): C7 enc_version 2→1 on any row → 410 'stored in a legacy format; re-stage the file', no R2 read, no decrypt, not marked corrupt (R-5)", async () => {
    const w = world();
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    for (const size of [4 * BLOCK_BYTES + 1, 100]) {
      const ref = await w.stage(pattern(size));
      (await w.rowOf(ref)).enc_version = 1;
      const before = w.r2.getCalls;
      const r = await w.open(ref);
      expect(r).toEqual({ ok: false, status: 410, message: "stored in a legacy format; re-stage the file" });
      expect(w.r2.getCalls).toBe(before);
      expect(await w.state(ref)).toBe("claimed");
    }
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("FIXED (#59): C7'' enc_version 1→2 on a v1 row → size check (multi-block) or nonce shape (single block) fails; never plaintext", async () => {
    const w = world();
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    const multi = await seedV1Row(w.d1, w.r2, pattern(2 * BLOCK_BYTES), { now: NOW });
    const refM = { file_handle: multi.handle, token: multi.token };
    (await w.rowOf(refM)).enc_version = 2;
    const rM = await w.read(refM);
    expectCorruptRead(rM, refM);
    expect(decrypt).not.toHaveBeenCalled(); // v1 object is byteLen+16, v2 expects byteLen+32
    const single = await seedV1Row(w.d1, w.r2, pattern(50), { now: NOW });
    const refS = { file_handle: single.handle, token: single.token };
    (await w.rowOf(refS)).enc_version = 2;
    const rS = await w.read(refS);
    expectCorruptRead(rS, refS); // the 12-byte v1 iv is not an 8-byte v2 prefix
    expect(rS.seen).toEqual([]);
  });

  it("REFUTED: an unknown enc_version on the row is refused outright (never read as either format)", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    (await w.rowOf(ref)).enc_version = 3 as never;
    const r = await w.open(ref);
    expect(r).toMatchObject({ ok: false, status: 500 });
    expect(w.r2.getCalls).toBe(0);
  });
});

describe("D4 — construction properties and edge sizes", () => {
  it("REFUTED: C8 10 000 mints → 10 000 distinct nonce prefixes, tokens and handles", async () => {
    const w = world();
    const ivs = new Set<string>();
    const tokens = new Set<string>();
    const handles = new Set<string>();
    const one = new Uint8Array([1]);
    for (let i = 0; i < 10_000; i++) {
      const r = await stageFromBlocks(w.deps, blockSourceFromBytes(one), "text/plain", null);
      if (!r.ok) throw new Error("stage failed");
      tokens.add(r.token);
      handles.add(r.file_handle);
      ivs.add((await w.rowOf(r)).iv_hex!);
    }
    expect(ivs.size).toBe(10_000);
    expect(tokens.size).toBe(10_000);
    expect(handles.size).toBe(10_000);
    // Within a file the counter separates blocks under one prefix; across
    // files the prefix separates them. Equal prefix + index is the only
    // collision, and prefixes are 64 random bits.
    const prefix = new Uint8Array(8);
    const nonces = new Set<string>();
    for (let i = 0; i < 1000; i++) nonces.add(Buffer.from(blockNonce(prefix, i)).toString("hex"));
    expect(nonces.size).toBe(1000);
  }, 120_000);

  it("REFUTED: C8' the AAD binds handle, version, index, count and length — any change yields a different AAD", () => {
    const base = blockAad("fh_a", 1, 3, 2_500_000);
    const variants = [
      blockAad("fh_b", 1, 3, 2_500_000),
      blockAad("fh_a", 0, 3, 2_500_000),
      blockAad("fh_a", 1, 4, 2_500_000),
      blockAad("fh_a", 1, 3, 2_500_001),
    ];
    for (const v of variants) expect(Buffer.from(v).equals(Buffer.from(base))).toBe(false);
    // The handle is length-prefixed: "fh_a" ‖ … cannot alias a longer handle.
    expect(Buffer.from(blockAad("fh_ab", 1, 3, 2_500_000)).byteLength).toBe(base.byteLength + 1);
  });

  it("REFUTED: C9 zero-length and exact-multiple files round-trip, and an appended block on an exact multiple is refused", async () => {
    const w = world();
    for (const len of [0, BLOCK_BYTES, 2 * BLOCK_BYTES]) {
      const bytes = pattern(len);
      const ref = await w.stage(bytes);
      expect(w.object(ref.r2_key).byteLength).toBe(ciphertextLength(len));
      const r = await w.read(ref);
      expect(r.err).toBeNull();
      expect(r.seen.map((s) => s.bytes.byteLength)).toEqual(len === 0 ? [0] : Array(len / BLOCK_BYTES).fill(BLOCK_BYTES));
      expect(Buffer.concat(r.seen.map((s) => s.bytes)).equals(Buffer.from(bytes))).toBe(true);
    }
    const ref = await w.stage(pattern(BLOCK_BYTES));
    const obj = w.object(ref.r2_key);
    w.setObject(ref.r2_key, Buffer.concat([obj, obj]));
    const decrypt = vi.spyOn(crypto.subtle, "decrypt");
    const r = await w.read(ref);
    expectCorruptRead(r, ref);
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("FIXED (#59): C10 corrupt is sticky — a later open costs no R2 read, even after the attacker restores the object", async () => {
    const w = world();
    const ref = await w.stage(pattern(BLOCK_BYTES + 3));
    const pristine = w.object(ref.r2_key).slice();
    const obj = w.object(ref.r2_key);
    obj[5] = obj[5]! ^ 1;
    expectCorruptRead(await w.read(ref), ref);
    const getsAfterDetect = w.r2.getCalls;
    w.setObject(ref.r2_key, pristine); // "fixed" again
    expect(await w.open(ref)).toMatchObject({ ok: false, status: 410, message: "stored file is corrupt" });
    expect(w.r2.getCalls).toBe(getsAfterDetect);
    // getFile sees the same sticky state, with no R2 read.
    const getFile = createGetFileCapability(w.deps);
    expect(await getFile(ref.file_handle, ref.token)).toMatchObject({ ok: false, status: 410 });
    expect(w.r2.getCalls).toBe(getsAfterDetect);
  });

  it("FIXED (#59): C11 a tamper in block 2 served through /staging/fetch → 200 then the stream errors after block 1 (never a clean EOF), Content-Length unmet, row corrupt", async () => {
    const w = world();
    const len = 2 * BLOCK_BYTES + 7;
    const ref = await w.stage(pattern(len));
    const obj = w.object(ref.r2_key);
    obj[BLOCK_BYTES + TAG + 9] = obj[BLOCK_BYTES + TAG + 9]! ^ 0x80;
    const res = await handleFetch(
      new Request(`https://w/staging/fetch/${ref.file_handle}`, { headers: { Authorization: `Bearer ${ref.token}` } }),
      w.deps,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe(String(len));
    const reader = res.body!.getReader();
    let got = 0;
    const outcome = await (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return "clean-eof";
        got += value.byteLength;
      }
    })().catch(() => "errored");
    expect(outcome).toBe("errored");
    expect(got).toBe(BLOCK_BYTES); // exactly the authenticated prefix
    expect(await w.state(ref)).toBe("corrupt");
    // The next fetch is a clean 410 with no R2 read.
    const gets = w.r2.getCalls;
    const again = await handleFetch(
      new Request(`https://w/staging/fetch/${ref.file_handle}`, { headers: { Authorization: `Bearer ${ref.token}` } }),
      w.deps,
    );
    expect(again.status).toBe(410);
    expect(w.r2.getCalls).toBe(gets);
  });

  it("FIXED (#59): C11' a tamper in block 1 (the first) on /staging/fetch → a clean 410, never a 200", async () => {
    const w = world();
    const ref = await w.stage(pattern(BLOCK_BYTES + 1));
    const obj = w.object(ref.r2_key);
    obj[0] = obj[0]! ^ 1;
    const res = await handleFetch(
      new Request(`https://w/staging/fetch/${ref.file_handle}`, { headers: { Authorization: `Bearer ${ref.token}` } }),
      w.deps,
    );
    expect(res.status).toBe(410);
    expect(await w.state(ref)).toBe("corrupt");
  });
});
