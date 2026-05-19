import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { handleUpload } from "../upload-handler";
import { handleFetch } from "../fetch-handler";
import { insertPending, lookupByHash } from "../repo";
import { mintToken, mintFileHandle } from "../tokens";
import { sha256Bearer } from "../crypto";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

async function seed(now: number, body: Uint8Array, ct = "application/octet-stream") {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const token = mintToken();
  const handle = mintFileHandle();
  const token_hash = await sha256Bearer(token);
  await insertPending(d1 as unknown as D1Database, {
    token_hash, file_handle: handle, content_type_hint: null,
    expected_byte_len: null, filename: null, created_at: now, expires_at: now + 300,
  });
  const upRes = await handleUpload(
    new Request("https://x.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": ct, "Content-Length": String(body.byteLength) },
      body,
    }),
    { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 1 },
  );
  expect(upRes.status).toBe(204);
  return { d1, r2, token, handle };
}

describe("handleFetch", () => {
  it("happy path: returns decrypted bytes with original content-type", async () => {
    const now = 1_000_000;
    const plain = new Uint8Array([10, 20, 30, 40, 50]);
    const { d1, r2, token, handle } = await seed(now, plain, "image/png");
    const res = await handleFetch(
      new Request(`https://x.test/staging/fetch/${handle}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    const out = new Uint8Array(await res.arrayBuffer());
    expect(Buffer.from(out).equals(Buffer.from(plain))).toBe(true);
  });

  it("403 when bearer is missing", async () => {
    const now = 1_000_000;
    const { d1, r2, handle } = await seed(now, new Uint8Array([1]));
    const res = await handleFetch(
      new Request(`https://x.test/staging/fetch/${handle}`, { method: "GET" }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 },
    );
    expect(res.status).toBe(403);
  });

  it("403 when file_handle does not match the row", async () => {
    const now = 1_000_000;
    const { d1, r2, token } = await seed(now, new Uint8Array([1]));
    const res = await handleFetch(
      new Request(`https://x.test/staging/fetch/${mintFileHandle()}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 },
    );
    expect(res.status).toBe(403);
  });

  it("409 before upload (state='pending')", async () => {
    const now = 1_000_000;
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const token = mintToken();
    const handle = mintFileHandle();
    const token_hash = await sha256Bearer(token);
    await insertPending(d1 as unknown as D1Database, {
      token_hash, file_handle: handle, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: now, expires_at: now + 300,
    });
    const res = await handleFetch(
      new Request(`https://x.test/staging/fetch/${handle}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 },
    );
    expect(res.status).toBe(409);
  });

  it("410 after fetch TTL expires", async () => {
    const now = 1_000_000;
    const { d1, r2, token, handle } = await seed(now, new Uint8Array([1]));
    const res = await handleFetch(
      new Request(`https://x.test/staging/fetch/${handle}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + CFG.fetchTtlSeconds + 10 },
    );
    expect(res.status).toBe(410);
  });

  it("410 + row marked corrupt when ciphertext is tampered with", async () => {
    const now = 1_000_000;
    const { d1, r2, token, handle } = await seed(now, new Uint8Array([1, 2, 3]));
    const [r2key] = [...r2.store.keys()];
    const blob = r2.store.get(r2key!)!;
    blob[0] = (blob[0] ?? 0) ^ 0xff;
    const res = await handleFetch(
      new Request(`https://x.test/staging/fetch/${handle}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 },
    );
    expect(res.status).toBe(410);
    const row = await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(token));
    expect(row!.state).toBe("corrupt");
  });

  it("multi-use within fetch TTL (two successive GETs both succeed)", async () => {
    const now = 1_000_000;
    const plain = new Uint8Array([7, 8, 9]);
    const { d1, r2, token, handle } = await seed(now, plain);
    for (let i = 0; i < 2; i++) {
      const res = await handleFetch(
        new Request(`https://x.test/staging/fetch/${handle}`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        }),
        { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 + i },
      );
      expect(res.status).toBe(200);
      const out = new Uint8Array(await res.arrayBuffer());
      expect(Buffer.from(out).equals(Buffer.from(plain))).toBe(true);
    }
  });
});
