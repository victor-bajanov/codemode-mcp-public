import { describe, it, expect } from "vitest";
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
