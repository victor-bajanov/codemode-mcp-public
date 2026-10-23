import { describe, it, expect, vi } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { handleUpload } from "../upload-handler";
import { insertPending } from "../repo";
import { mintToken, mintFileHandle } from "../tokens";
import { sha256Bearer } from "../crypto";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

interface Ctx { d1: FakeD1; r2: FakeR2; token: string; handle: string; }

async function seedPending(now: number, expires: number, opts?: { contentTypeHint?: string }): Promise<Ctx> {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const token = mintToken();
  const handle = mintFileHandle();
  const token_hash = await sha256Bearer(token);
  await insertPending(d1 as unknown as D1Database, {
    token_hash, file_handle: handle, content_type_hint: opts?.contentTypeHint ?? null,
    expected_byte_len: null, filename: null, created_at: now, expires_at: expires,
  });
  return { d1, r2, token, handle };
}

function nowSec(): number { return Math.floor(Date.now() / 1000); }

describe("handleUpload", () => {
  it("happy path: 204 + ciphertext in R2 + row claimed", async () => {
    const now = nowSec();
    const { d1, r2, token, handle } = await seedPending(now, now + 300);
    const body = new Uint8Array([1, 2, 3, 4, 5]);
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream", "Content-Length": String(body.byteLength) },
      body,
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG, now: () => now + 1,
    });
    expect(res.status).toBe(204);
    expect(r2.store.size).toBe(1);
    // Ciphertext != plaintext (with overwhelming probability):
    const stored = [...r2.store.values()][0]!;
    expect(stored.byteLength).toBe(body.byteLength + 16); // GCM tag
    expect(Buffer.from(stored.slice(0, 5)).equals(Buffer.from(body))).toBe(false);
    void handle;
  });

  it("403 when bearer is missing", async () => {
    const { d1, r2 } = await seedPending(nowSec(), nowSec() + 300);
    const req = new Request("https://example.test/staging/upload", { method: "POST", body: new Uint8Array([1]) });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: nowSec,
    });
    expect(res.status).toBe(403);
  });

  it("403 when bearer is unknown", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${mintToken()}`, "Content-Length": "1" },
      body: new Uint8Array([1]),
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: nowSec,
    });
    expect(res.status).toBe(403);
  });

  it("413 when Content-Length exceeds max", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 300);
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Length": String(CFG.maxBytes + 1) },
      body: new Uint8Array([1]),
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 1,
    });
    expect(res.status).toBe(413);
  });

  it("400 when Content-Type doesn't match the registered hint", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 300, { contentTypeHint: "image/png" });
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "image/jpeg", "Content-Length": "1" },
      body: new Uint8Array([1]),
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 1,
    });
    expect(res.status).toBe(400);
  });

  it("409 on double-upload (second 409)", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 300);
    const body = new Uint8Array([1]);
    const make = () => new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream", "Content-Length": "1" },
      body,
    });
    const res1 = await handleUpload(make(), {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 1,
    });
    expect(res1.status).toBe(204);
    const res2 = await handleUpload(make(), {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2,
    });
    expect(res2.status).toBe(409);
  });

  it("410 when upload arrives after the pending TTL", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 1);
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream", "Content-Length": "1" },
      body: new Uint8Array([1]),
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 10,
    });
    expect(res.status).toBe(410);
  });

  // F-13: the size cap is enforced while streaming, so a body with no
  // Content-Length cannot make the worker buffer more than maxBytes + one chunk.
  function countingStream(totalBytes: number, chunk: number) {
    const state = { pulled: 0 };
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        if (state.pulled >= totalBytes) { c.close(); return; }
        const n = Math.min(chunk, totalBytes - state.pulled);
        state.pulled += n;
        c.enqueue(new Uint8Array(n).fill(7));
      },
      // No read-ahead: a chunk is produced only when the consumer asks for it,
      // so `pulled` measures what the handler consumed.
    }, { highWaterMark: 0 });
    return { stream, state };
  }

  it("413 and stream cancelled once a chunked body passes maxBytes; nothing persisted", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 300);
    const small: StagingConfig = { ...CFG, maxBytes: 256 };
    const { stream, state } = countingStream(64 * 1024, 64);
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream" },
      body: stream,
      // @ts-expect-error — Node fetch needs duplex for stream bodies
      duplex: "half",
    });
    expect(req.headers.get("Content-Length")).toBeNull();
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: small, now: () => now + 1,
    });
    expect(res.status).toBe(413);
    // At most one chunk past the cap is ever pulled.
    expect(state.pulled).toBeLessThanOrEqual(small.maxBytes + 64);
    expect(r2.store.size).toBe(0);
    const row = [...d1.rows.values()][0]!;
    expect(row.state).toBe("pending");
  });

  it("a chunked body within maxBytes still uploads (204) with the right length", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 300);
    const { stream } = countingStream(1000, 64);
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream" },
      body: stream,
      // @ts-expect-error — Node fetch needs duplex for stream bodies
      duplex: "half",
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 1,
    });
    expect(res.status).toBe(204);
    expect(r2.store.size).toBe(1);
    expect([...r2.store.values()][0]!.byteLength).toBe(1000 + 16); // GCM tag
  });

  it("a request with no body is a zero-byte upload", async () => {
    const now = nowSec();
    const { d1, r2, token } = await seedPending(now, now + 300);
    const req = new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream" },
    });
    const res = await handleUpload(req, {
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 1,
    });
    expect(res.status).toBe(204);
    expect([...r2.store.values()][0]!.byteLength).toBe(16);
  });
});

describe("handleUpload — v2 block format", () => {
  const BLOCK = 1_048_576;

  function pat(n: number): Uint8Array {
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i++) a[i] = (i * 37 + 11) & 0xff;
    return a;
  }

  function chunkedStream(bytes: Uint8Array, chunk: number): { stream: ReadableStream<Uint8Array>; cancelled: () => boolean } {
    let off = 0;
    let cancelled = false;
    return {
      stream: new ReadableStream<Uint8Array>({
        pull(c) {
          if (off >= bytes.byteLength) { c.close(); return; }
          c.enqueue(bytes.slice(off, Math.min(bytes.byteLength, off + chunk)));
          off += chunk;
        },
        cancel() { cancelled = true; },
      }),
      cancelled: () => cancelled,
    };
  }

  async function upload(ctx: Ctx, body: BodyInit | null, headers: Record<string, string>, now: number, cfg = CFG) {
    const init: RequestInit & { duplex?: "half" } = {
      method: "POST",
      headers: { Authorization: `Bearer ${ctx.token}`, "Content-Type": "application/pdf", ...headers },
      body,
    };
    if (body instanceof ReadableStream) init.duplex = "half";
    return handleUpload(new Request("https://example.test/staging/upload", init), {
      STAGING_D1: ctx.d1 as unknown as D1Database, STAGING_R2: ctx.r2 as unknown as R2Bucket,
      config: cfg, now: () => now + 1,
    });
  }

  async function readBack(ctx: Ctx, now: number): Promise<Uint8Array> {
    const { createStagedFileOpener } = await import("../staged-file");
    const open = createStagedFileOpener({
      STAGING_D1: ctx.d1 as unknown as D1Database, STAGING_R2: ctx.r2 as unknown as R2Bucket,
      config: CFG, now: () => now + 2,
    });
    const r = await open({ file_handle: ctx.handle, token: ctx.token });
    if (!r.ok) throw new Error(`open failed: ${r.status}`);
    const parts: Uint8Array[] = [];
    await r.file.readBlocks(async (b) => { parts.push(b.slice()); });
    return Buffer.concat(parts);
  }

  async function row(ctx: Ctx) {
    const { lookupByHash } = await import("../repo");
    return lookupByHash(ctx.d1 as unknown as D1Database, await sha256Bearer(ctx.token));
  }

  for (const size of [0, 1, BLOCK, 3 * BLOCK + 5]) {
    it(`with Content-Length: streams the put, object is ciphertextLength, round-trips ${size} bytes, row v2`, async () => {
      const now = nowSec();
      const ctx = await seedPending(now, now + 300);
      const x = pat(size);
      const { stream } = chunkedStream(x, 65_536);
      const res = await upload(ctx, stream, { "Content-Length": String(size) }, now);
      expect(res.status).toBe(204);
      expect(ctx.r2.putKinds).toEqual(["stream"]);
      const { ciphertextLength } = await import("../block-format");
      expect([...ctx.r2.store.values()][0]!.byteLength).toBe(ciphertextLength(size));
      expect((await row(ctx))!.enc_version).toBe(2);
      expect(Buffer.from(await readBack(ctx, now)).equals(Buffer.from(x))).toBe(true);
    });
  }

  it("without Content-Length: identical object length, no buffer larger than one block handed to put", async () => {
    const now = nowSec();
    const ctx = await seedPending(now, now + 300);
    const x = pat(2 * BLOCK + 9);
    const { stream } = chunkedStream(x, 100_000);
    const res = await upload(ctx, stream, {}, now);
    expect(res.status).toBe(204);
    const { ciphertextLength } = await import("../block-format");
    expect([...ctx.r2.store.values()][0]!.byteLength).toBe(ciphertextLength(x.byteLength));
    expect(ctx.r2.maxPutBufferBytes).toBeLessThanOrEqual(BLOCK + 16);
    expect(Buffer.from(await readBack(ctx, now)).equals(Buffer.from(x))).toBe(true);
  });

  it("body longer than declared → 400, no R2 object, row still pending", async () => {
    const now = nowSec();
    const ctx = await seedPending(now, now + 300);
    const { stream, cancelled } = chunkedStream(pat(20), 8);
    const res = await upload(ctx, stream, { "Content-Length": "10" }, now);
    expect(res.status).toBe(400);
    expect(ctx.r2.store.size).toBe(0);
    expect((await row(ctx))!.state).toBe("pending");
    expect(cancelled()).toBe(true);
  });

  it("body shorter than declared → 400, no R2 object, row still pending", async () => {
    const now = nowSec();
    const ctx = await seedPending(now, now + 300);
    const { stream } = chunkedStream(pat(5), 8);
    const res = await upload(ctx, stream, { "Content-Length": "10" }, now);
    expect(res.status).toBe(400);
    expect(ctx.r2.store.size).toBe(0);
    expect((await row(ctx))!.state).toBe("pending");
  });

  it("a declared length over maxBytes → 413 before reading the body", async () => {
    const now = nowSec();
    const ctx = await seedPending(now, now + 300);
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({ pull(c) { pulled++; c.enqueue(new Uint8Array(4)); } });
    const res = await upload(ctx, stream, { "Content-Length": "11" }, now, { ...CFG, maxBytes: 10 });
    expect(res.status).toBe(413);
    expect(pulled).toBeLessThanOrEqual(1); // at most the stream's own start-up pull
    expect(ctx.r2.store.size).toBe(0);
  });
});

describe("handleUpload — review fixes", () => {
  function deps(ctx: Ctx, now: number) {
    return {
      STAGING_D1: ctx.d1 as unknown as D1Database, STAGING_R2: ctx.r2 as unknown as R2Bucket,
      config: CFG, now: () => now + 1,
    };
  }

  /** A body that delivers nothing until `release()`; counts pulls (HWM 0: no eager pull). */
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

  function req(ctx: Ctx, body: ReadableStream<Uint8Array> | Uint8Array, headers: Record<string, string> = {}) {
    return new Request("https://example.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${ctx.token}`, "Content-Type": "application/octet-stream", ...headers },
      body,
      duplex: "half",
    } as RequestInit);
  }

  it("F1: a second concurrent upload without Content-Length → 503 + Retry-After, body untouched; CL uploads unaffected; slot freed after", async () => {
    const now = nowSec();
    const a = await seedPending(now, now + 300);
    const b = await seedPending(now, now + 300);
    const c = await seedPending(now, now + 300);
    const held = heldStream();
    const first = handleUpload(req(a, held.stream), deps(a, now));
    await new Promise((r) => setTimeout(r, 10));
    expect(held.pulls()).toBeGreaterThan(0); // the first upload is reading

    const second = heldStream();
    const res2 = await handleUpload(req(b, second.stream), deps(b, now));
    expect(res2.status).toBe(503);
    expect(res2.headers.get("Retry-After")).toBe("1");
    expect(second.pulls()).toBe(0);

    const withCl = await handleUpload(req(c, new Uint8Array([9, 9]), { "Content-Length": "2" }), deps(c, now));
    expect(withCl.status).toBe(204);

    held.release();
    expect((await first).status).toBe(204);

    // Slot freed: b can now upload without Content-Length.
    const again = await handleUpload(req(b, new ReadableStream<Uint8Array>({ start: (cc) => { cc.enqueue(new Uint8Array([1])); cc.close(); } })), deps(b, now));
    expect(again.status).toBe(204);
  });

  it("F1: the slot is freed when an unknown-length upload fails", async () => {
    const now = nowSec();
    const a = await seedPending(now, now + 300);
    const b = await seedPending(now, now + 300);
    const tooBig = new ReadableStream<Uint8Array>({ start: (c) => { c.enqueue(new Uint8Array(20)); c.close(); } });
    const res = await handleUpload(req(a, tooBig), { ...deps(a, now), config: { ...CFG, maxBytes: 10 } });
    expect(res.status).toBe(413);
    const ok = await handleUpload(req(b, new ReadableStream<Uint8Array>({ start: (c) => { c.enqueue(new Uint8Array([1])); c.close(); } })), deps(b, now));
    expect(ok.status).toBe(204);
  });

  it.each(["1e3", " 10", "0x10", "", "1.5", "-1", "1234567890123456"])(
    "F4: Content-Length %j → 400 before any D1 lookup",
    async (cl) => {
      const now = nowSec();
      const ctx = await seedPending(now, now + 300);
      const prepare = vi.spyOn(ctx.d1, "prepare");
      // Headers trims surrounding whitespace in values; go round it with a raw header object.
      const r = req(ctx, new Uint8Array(0));
      const fake = new Proxy(r, {
        get(t, p) {
          if (p === "headers") {
            const h = new Headers(t.headers);
            return { get: (k: string) => (k.toLowerCase() === "content-length" ? cl : h.get(k)) };
          }
          const v = Reflect.get(t, p, t);
          return typeof v === "function" ? v.bind(t) : v;
        },
      });
      const res = await handleUpload(fake as Request, deps(ctx, now));
      expect(res.status).toBe(400);
      expect(prepare).not.toHaveBeenCalled();
    },
  );
});

describe("handleUpload — Mythos re-review fixes", () => {
  function stalled() {
    let cancelled = false;
    let sent = false;
    const stream = new ReadableStream<Uint8Array>(
      {
        async pull(c) {
          if (!sent) { sent = true; c.enqueue(new Uint8Array([1])); return; }
          await new Promise(() => {}); // trickle stops: never another byte
        },
        cancel() { cancelled = true; },
      },
      { highWaterMark: 0 },
    );
    return { stream, cancelled: () => cancelled };
  }

  it("1: a stalled upload without Content-Length → 408 after transferTimeoutMs; the shared slot is free again", async () => {
    const { tryAcquireUnknownLengthSlot } = await import("../unknown-length-slot");
    const now = nowSec();
    const ctx = await seedPending(now, now + 300);
    const s = stalled();
    const res = await handleUpload(
      new Request("https://example.test/staging/upload", {
        method: "POST",
        headers: { Authorization: `Bearer ${ctx.token}` },
        body: s.stream,
        duplex: "half",
      } as RequestInit),
      {
        STAGING_D1: ctx.d1 as unknown as D1Database, STAGING_R2: ctx.r2 as unknown as R2Bucket,
        config: { ...CFG, transferTimeoutMs: 50 }, now: () => now + 1,
      },
    );
    expect(res.status).toBe(408);
    expect(s.cancelled()).toBe(true);
    expect(ctx.r2.store.size).toBe(0);
    const release = tryAcquireUnknownLengthSlot();
    expect(release).not.toBeNull();
    release!();
  });

  it("5: busy → 503 without any R2 delete (nothing was written)", async () => {
    const { tryAcquireUnknownLengthSlot } = await import("../unknown-length-slot");
    const now = nowSec();
    const ctx = await seedPending(now, now + 300);
    const del = vi.spyOn(ctx.r2, "delete");
    const release = tryAcquireUnknownLengthSlot()!;
    try {
      const res = await handleUpload(
        new Request("https://example.test/staging/upload", {
          method: "POST",
          headers: { Authorization: `Bearer ${ctx.token}` },
          body: new ReadableStream<Uint8Array>({ start: (c) => { c.enqueue(new Uint8Array([1])); c.close(); } }),
          duplex: "half",
        } as RequestInit),
        { STAGING_D1: ctx.d1 as unknown as D1Database, STAGING_R2: ctx.r2 as unknown as R2Bucket, config: CFG, now: () => now + 1 },
      );
      expect(res.status).toBe(503);
      expect(del).not.toHaveBeenCalled();
    } finally {
      release();
    }
  });
});
