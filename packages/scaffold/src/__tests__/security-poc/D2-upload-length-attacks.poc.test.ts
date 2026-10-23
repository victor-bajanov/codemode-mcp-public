// D2 — Length attacks on POST /staging/upload (issue #59, plan A7, D9, amendment "D9, unknown-length uploads").
//
// Attacker: anyone holding a freshly minted upload bearer (the public upload
//   endpoint takes a `stg_` token minted by register_file_handle), or a
//   client that lies in `Content-Length`.
// Precondition: a pending row; the upload handler streams the body into the
//   blockwise encrypter.
// Payloads: Content-Length 1 KiB with 50 MiB sent; Content-Length 50 MiB with
//   1 KiB sent; no Content-Length with maxBytes + 1 sent; Content-Length of
//   "1e309", "-1", "NaN", " 10", "0x10", "1.5", "" and "+1"; a trickle of
//   1-byte chunks.
// Control: the declared length is validated as plain decimal digits before
//   any D1 read (400) and capped (413); a body that runs past its declared
//   length is cancelled at declared + 1 (400, nothing written, row still
//   pending); a short body is 400 with no object; an unknown-length body is
//   cancelled once it passes maxBytes (413) and the reader is cancelled; the
//   block loop forwards each sealed block to R2 as it completes, so a slow
//   trickle never accumulates more than one block of plaintext.
//
// Pre-v2 reasoning: v1 buffered the whole body (`arrayBuffer()`) before any
// size or length check, so the lying-length payloads cost a full buffer and
// a one-shot encryption; the digit-only Content-Length check and the
// declared+1 cut-off are v2 controls (review WP-A finding 4 for the parser).
//
// FakeD1/FakeR2 only. No network.
import { describe, it, expect } from "vitest";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { handleUpload } from "../../staging/upload-handler";
import { registerFileHandleTool } from "../../staging/register-tool";
import { lookupByHash } from "../../staging/repo";
import { sha256Bearer } from "../../staging/crypto";
import { BLOCK_BYTES, GCM_TAG_BYTES, type StagingConfig } from "../../staging/types";

const NOW = 1_700_000_000;
const FIFTY_MIB = 50 * 1024 * 1024;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: FIFTY_MIB };

interface World {
  d1: FakeD1;
  r2: FakeR2;
  token: string;
  handle: string;
  prepares: () => number;
  upload: (body: BodyInit | null, headers: Record<string, string>, cfg?: StagingConfig) => Promise<Response>;
  rowState: () => Promise<string>;
}

async function world(cfg: StagingConfig = CFG): Promise<World> {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  let prepares = 0;
  const origPrepare = d1.prepare.bind(d1);
  d1.prepare = (sql: string) => {
    prepares += 1;
    return origPrepare(sql);
  };
  const D1 = d1 as unknown as D1Database;
  const R2 = r2 as unknown as R2Bucket;
  const tool = registerFileHandleTool({ STAGING_D1: D1, config: cfg, uploadOrigin: "https://w", now: () => NOW });
  const { token, file_handle } = await tool.handler({});
  return {
    d1,
    r2,
    token,
    handle: file_handle,
    prepares: () => prepares,
    upload: (body, headers, c = cfg) => {
      const init: RequestInit & { duplex?: "half" } = {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/pdf", ...headers },
        body,
      };
      if (body instanceof ReadableStream) init.duplex = "half";
      return handleUpload(new Request("https://w/staging/upload", init), {
        STAGING_D1: D1,
        STAGING_R2: R2,
        config: c,
        now: () => NOW + 1,
      });
    },
    rowState: async () => (await lookupByHash(D1, await sha256Bearer(token)))!.state,
  };
}

/** A pull-driven source of `total` bytes in `chunk`-byte pieces (no
 *  read-ahead), recording how much the consumer actually pulled and whether
 *  it was cancelled. */
function source(total: number, chunk: number) {
  let pulled = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        if (pulled >= total) {
          c.close();
          return;
        }
        const n = Math.min(chunk, total - pulled);
        c.enqueue(new Uint8Array(n));
        pulled += n;
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, pulled: () => pulled, cancelled: () => cancelled };
}

describe("D2 — lying Content-Length", () => {
  it("FIXED (#59): M4 declared 1 KiB, 50 MiB sent → 400 at declared + 1; no R2 write; row stays pending", async () => {
    const w = await world();
    const src = source(FIFTY_MIB, 256);
    const res = await w.upload(src.stream, { "Content-Length": "1024" });
    expect(res.status).toBe(400);
    expect(src.pulled()).toBeLessThanOrEqual(1024 + 256); // cut off at the first chunk past the declaration
    expect(src.cancelled()).toBe(true);
    expect(w.r2.store.size).toBe(0);
    expect(await w.rowState()).toBe("pending");
  });

  it("FIXED (#59): M4' declared 50 MiB, 1 KiB sent → 400; no object; row stays pending", async () => {
    const w = await world();
    const src = source(1024, 256);
    const res = await w.upload(src.stream, { "Content-Length": String(FIFTY_MIB) });
    expect(res.status).toBe(400);
    expect(w.r2.store.size).toBe(0);
    expect(await w.rowState()).toBe("pending");
    // A later honest retry on the same bearer still works: nothing was claimed.
    const ok = await w.upload(source(1024, 256).stream, { "Content-Length": "1024" });
    expect(ok.status).toBe(204);
    expect(await w.rowState()).toBe("claimed");
  });

  it("REFUTED: declared 1 KiB, 1 KiB + 1 sent → 400 (one byte over is a mismatch, not a truncation)", async () => {
    const w = await world();
    const res = await w.upload(source(1025, 1025).stream, { "Content-Length": "1024" });
    expect(res.status).toBe(400);
    expect(w.r2.store.size).toBe(0);
    expect(await w.rowState()).toBe("pending");
  });
});

describe("D2 — no Content-Length", () => {
  it("FIXED (#59): maxBytes + 1 without Content-Length → 413, reader cancelled at the first byte over, nothing persisted", async () => {
    const w = await world();
    const src = source(FIFTY_MIB + 1, BLOCK_BYTES);
    const res = await w.upload(src.stream, {});
    expect(res.status).toBe(413);
    expect(src.cancelled()).toBe(true);
    expect(src.pulled()).toBeLessThanOrEqual(FIFTY_MIB + BLOCK_BYTES);
    expect(w.r2.store.size).toBe(0);
    expect(w.r2.putKinds).toEqual([]); // the put never started: plaintext blocks are held until the body ends
    expect(await w.rowState()).toBe("pending");
  }, 60_000);

  it("REFUTED: exactly maxBytes without Content-Length is accepted (the cap is inclusive)", async () => {
    const small: StagingConfig = { ...CFG, maxBytes: 4096 };
    const w = await world(small);
    const res = await w.upload(source(4096, 1000).stream, {});
    expect(res.status).toBe(204);
    expect([...w.r2.store.values()][0]!.byteLength).toBe(4096 + GCM_TAG_BYTES);
  });
});

describe("D2 — malformed Content-Length values are refused before any D1 read", () => {
  // (Edge whitespace is stripped by the Headers API before our code runs, and
  // a non-ByteString value cannot be set at all, so " 10" and fullwidth digits
  // are not wire inputs; "1e309" is the Number()-parsed Infinity case.)
  for (const cl of ["1e309", "-1", "NaN", "0x10", "1.5", "", "+1", "1_000", "9".repeat(16)]) {
    it(`FIXED (#59): Content-Length ${JSON.stringify(cl)} → 400, zero D1 queries, body untouched`, async () => {
      const w = await world();
      const before = w.prepares();
      const src = source(64, 64);
      const res = await w.upload(src.stream, { "Content-Length": cl });
      expect(res.status).toBe(400);
      expect(w.prepares() - before).toBe(0);
      expect(src.pulled()).toBe(0);
      expect(w.r2.store.size).toBe(0);
    });
  }

  it("FIXED (#59): a declared length over maxBytes → 413 before any D1 read and without reading the body", async () => {
    const w = await world();
    const before = w.prepares();
    const src = source(64, 64);
    const res = await w.upload(src.stream, { "Content-Length": String(FIFTY_MIB + 1) });
    expect(res.status).toBe(413);
    expect(w.prepares() - before).toBe(0);
    expect(src.pulled()).toBe(0);
  });
});

describe("D2 — a slow trickle never accumulates more than one block", () => {
  it("REFUTED: 1-byte chunks with Content-Length: block 0's ciphertext reaches R2 before block 1's bytes are pulled", async () => {
    const w = await world();
    // Two full blocks plus one byte: a handler that buffered the whole body
    // before its first R2 write would have pulled 2·BLOCK_BYTES + 1 by the
    // time block 0's ciphertext arrived, well past the bound below. (With a
    // one-block body the bound equalled the total and the probe was vacuous.)
    const total = 2 * BLOCK_BYTES + 1;
    const src = source(total, 1);
    // Observe the R2 side as it is fed: how far had the source been pulled
    // when the first sealed block arrived?
    const pulledAtFirstChunk: number[] = [];
    const chunkSizes: number[] = [];
    const realPut = w.r2.put.bind(w.r2);
    w.r2.put = async (key: string, body: ReadableStream<Uint8Array>) => {
      const reader = body.getReader();
      const chunks: Uint8Array[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        pulledAtFirstChunk.push(src.pulled());
        chunkSizes.push(value.byteLength);
        chunks.push(value);
      }
      return realPut(key, new Uint8Array(Buffer.concat(chunks)));
    };
    const res = await w.upload(src.stream, { "Content-Length": String(total) });
    expect(res.status).toBe(204);
    expect(chunkSizes).toEqual([BLOCK_BYTES + GCM_TAG_BYTES, BLOCK_BYTES + GCM_TAG_BYTES, 1 + GCM_TAG_BYTES]);
    // The first sealed block was handed to R2 while the source had delivered
    // at most block 0 plus a chunk of look-ahead: the handler did not wait for
    // the whole body.
    expect(pulledAtFirstChunk[0]!).toBeLessThanOrEqual(BLOCK_BYTES + 1);
    expect(await w.rowState()).toBe("claimed");
  }, 60_000);
});
