// In-process memory ladder (plan A11). Drives upload → opener.readBlocks →
// base64 (lines) encoder → fixed-length sink for 1, 8, 24 and 50 MiB with an
// R2 stand-in that keeps no content, and asserts the ArrayBuffer high-water
// mark stays within 8 MiB of the baseline in both phases.
//
// Needs `global.gc` (run via `pnpm --filter @local/scaffold test:memory`, which
// passes --expose-gc). Node measures our allocations, not workerd's: the
// production 128 MB claim is proven by the live ladder (D15).
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { HashingR2 } from "./__fixtures__/hashing-r2";
import { handleUpload } from "../upload-handler";
import { createStagedFileOpener } from "../staged-file";
import { insertPending, lookupByHash } from "../repo";
import { deriveV2Key, sha256Bearer } from "../crypto";
import { mintFileHandle, mintToken } from "../tokens";
import { BLOCK_BYTES, blockCount, blockPlainLength, encryptBlock } from "../block-format";
import { Base64Encoder, base64Length } from "../codec";
import { createFixedLengthSink } from "../sinks";
import type { StagingConfig } from "../types";

const MiB = 1024 * 1024;
const LIMIT = 8 * MiB;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * MiB };
const NOW = 1_700_000_000;
const gc = (globalThis as { gc?: () => void }).gc;

/** Deterministic file content, generated per offset (never held whole). */
function fill(dst: Uint8Array, offset: number): void {
  for (let i = 0; i < dst.byteLength; i++) {
    const o = offset + i;
    dst[i] = (o * 2654435761) >>> 24 ^ (o & 0xff);
  }
}

function patternStream(size: number, chunk = 64 * 1024): ReadableStream<Uint8Array> {
  let off = 0;
  return new ReadableStream<Uint8Array>({
    pull(c) {
      if (off >= size) {
        c.close();
        return;
      }
      const n = Math.min(chunk, size - off);
      const b = new Uint8Array(n);
      fill(b, off);
      off += n;
      c.enqueue(b);
    },
  });
}

/** SHA-256 of the RFC 2045 base64 of the pattern, via Buffer (independent of codec.ts). */
function referenceHash(size: number): string {
  const h = createHash("sha256");
  const unit = 57 * 18_396; // ≈1 MiB, whole 57-byte lines
  for (let off = 0; off < size; off += unit) {
    const b = new Uint8Array(Math.min(unit, size - off));
    fill(b, off);
    const b64 = Buffer.from(b).toString("base64");
    for (let i = 0; i < b64.length; i += 76) h.update(b64.slice(i, i + 76) + "\r\n", "latin1");
  }
  return h.digest("hex");
}

// Two high-water marks: `live` collects garbage before each sample, so it is
// what the pipeline actually retains (the property under test — V8 collects
// dead buffers under pressure in workerd too); `raw` is informational and
// mostly shows how lazily Node's GC reclaims dead block buffers.
class Peak {
  private base = 0;
  live = 0;
  raw = 0;
  reset(): void {
    gc!();
    gc!();
    this.base = process.memoryUsage().arrayBuffers;
    this.live = this.base;
    this.raw = this.base;
  }
  sample = (): void => {
    const before = process.memoryUsage().arrayBuffers;
    if (before > this.raw) this.raw = before;
    gc!();
    const v = process.memoryUsage().arrayBuffers;
    if (v > this.live) this.live = v;
  };
  get delta(): number {
    return this.live - this.base;
  }
  get rawDelta(): number {
    return this.raw - this.base;
  }
}

describe.skipIf(!gc)("memory ladder (in-process)", () => {
  for (const sizeMiB of [1, 8, 24, 50]) {
    const size = sizeMiB * MiB;
    it(`${sizeMiB} MiB: upload and read+encode each stay under 8 MiB of ArrayBuffer growth`, async () => {
      const t0 = Date.now();
      const expected = referenceHash(size);
      const d1 = new FakeD1();
      const r2 = new HashingR2();
      const meter = new Peak();
      r2.onChunk = meter.sample;
      const token = mintToken();
      const handle = mintFileHandle();
      const token_hash = await sha256Bearer(token);
      await insertPending(d1 as unknown as D1Database, {
        token_hash, file_handle: handle, content_type_hint: null,
        expected_byte_len: null, filename: null, created_at: NOW, expires_at: NOW + 300,
      });
      const deps = { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => NOW + 1 };

      // Phase 1: upload.
      meter.reset();
      const res = await handleUpload(
        new Request("https://x.test/staging/upload", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/pdf", "Content-Length": String(size) },
          body: patternStream(size),
          duplex: "half",
        } as RequestInit),
        deps,
      );
      expect(res.status).toBe(204);
      const uploadDelta = meter.delta;
      const uploadRaw = meter.rawDelta;
      const [r2Key, stored] = [...r2.objects.entries()][0]!;

      // The R2 stand-in serves the object by re-sealing the pattern block by
      // block with the row's key material; its hash must match the upload's.
      const row = (await lookupByHash(d1 as unknown as D1Database, token_hash))!;
      const key = await deriveV2Key(token, handle);
      r2.generate = () => {
        const n = blockCount(size);
        let i = 0;
        return new ReadableStream<Uint8Array>({
          async pull(c) {
            if (i >= n) {
              c.close();
              return;
            }
            const plain = new Uint8Array(blockPlainLength(size, i));
            fill(plain, i * BLOCK_BYTES);
            c.enqueue(await encryptBlock(key, row.iv!, handle, i, n, size, plain));
            i++;
          },
        });
      };

      // Phase 2: open → readBlocks → base64-lines encoder → sink → consumer.
      meter.reset();
      const open = createStagedFileOpener(deps);
      const opened = await open({ file_handle: handle, token });
      if (!opened.ok) throw new Error(`open failed: ${opened.status}`);
      const sink = createFixedLengthSink(base64Length(size, "lines"));
      const out = createHash("sha256");
      const consumer = (async () => {
        const reader = sink.readable.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) return;
          out.update(value);
          meter.sample();
        }
      })();
      const enc = new Base64Encoder("lines");
      const emit = async (ascii: Uint8Array) => {
        meter.sample();
        await sink.write(ascii);
      };
      await opened.file.readBlocks(async (plain) => {
        meter.sample();
        await enc.push(plain, emit);
      });
      await enc.finish(emit);
      await sink.close();
      await consumer;
      const readDelta = meter.delta;
      const readRaw = meter.rawDelta;

      expect(r2.served.get(r2Key)!.digest("hex")).toBe(stored.sha256);
      expect(out.digest("hex")).toBe(expected);
      const ms = Date.now() - t0;
      console.log(
        `memory-ladder ${sizeMiB} MiB: upload live Δ${(uploadDelta / MiB).toFixed(2)} MiB ` +
          `(raw ${(uploadRaw / MiB).toFixed(2)}), read+encode live Δ${(readDelta / MiB).toFixed(2)} MiB ` +
          `(raw ${(readRaw / MiB).toFixed(2)}), ${ms} ms`,
      );
      expect(uploadDelta).toBeLessThan(LIMIT);
      expect(readDelta).toBeLessThan(LIMIT);
    }, 120_000);
  }
});

describe.skipIf(!!gc)("memory ladder (skipped)", () => {
  it.skip("needs --expose-gc: run `pnpm --filter @local/scaffold test:memory`", () => {});
});
