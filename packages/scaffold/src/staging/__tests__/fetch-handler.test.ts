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

async function seed(
  now: number,
  body: Uint8Array,
  ct = "application/octet-stream",
  filename: string | null = null,
) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const token = mintToken();
  const handle = mintFileHandle();
  const token_hash = await sha256Bearer(token);
  await insertPending(d1 as unknown as D1Database, {
    token_hash, file_handle: handle, content_type_hint: null,
    expected_byte_len: null, filename, created_at: now, expires_at: now + 300,
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

  describe("Content-Disposition", () => {
    async function fetchWithFilename(filename: string | null) {
      const now = 1_000_000;
      const { d1, r2, token, handle } = await seed(now, new Uint8Array([1]), "application/octet-stream", filename);
      return handleFetch(
        new Request(`https://x.test/staging/fetch/${handle}`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        }),
        { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => now + 2 },
      );
    }

    it("plain ASCII filename produces attachment; filename=\"...\" alongside X-Filename", async () => {
      const filename = "superchoice-product-disclosure-statement.pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Filename")).toBe(filename);
      expect(res.headers.get("Content-Disposition")).toBe(
        "attachment; filename=\"superchoice-product-disclosure-statement.pdf\"",
      );
    });

    it("backslash-escapes embedded quote and backslash characters", async () => {
      const filename = "weird\"name\\file.pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Filename")).toBe(filename);
      expect(res.headers.get("Content-Disposition")).toBe(
        "attachment; filename=\"weird\\\"name\\\\file.pdf\"",
      );
    });

    it("non-ASCII filename gets an ascii fallback plus RFC 5987 filename*", async () => {
      const filename = "résumé — final.pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      // X-Filename is a raw, unencoded header — the em dash (U+2014) is outside
      // the ByteString range Headers.set allows, so it's substituted with "_"
      // there. The full name survives in Content-Disposition's filename*
      // (RFC 5987, UTF-8).
      expect(res.headers.get("X-Filename")).toBe("résumé _ final.pdf");
      expect(res.headers.get("Content-Disposition")).toBe(
        "attachment; filename=\"r_sum_ _ final.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%E2%80%94%20final.pdf",
      );
    });

    it("no filename means Content-Disposition is bare and X-Filename is absent", async () => {
      const res = await fetchWithFilename(null);
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Filename")).toBeNull();
      expect(res.headers.get("Content-Disposition")).toBe("attachment");
    });

    it("a filename that is control characters only behaves like no filename", async () => {
      const res = await fetchWithFilename("\r\n\t");
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Filename")).toBeNull();
      expect(res.headers.get("Content-Disposition")).toBe("attachment");
    });

    it("strips CR/LF from the filename so the response never 500s", async () => {
      const filename = "report\r\n.pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Filename")).toBe("report.pdf");
      expect(res.headers.get("Content-Disposition")).toBe('attachment; filename="report.pdf"');
    });

    it("strips an unpaired surrogate instead of letting encodeURIComponent throw", async () => {
      const filename = "a\ud800b.pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Filename")).toBe("ab.pdf");
      expect(res.headers.get("Content-Disposition")).toBe('attachment; filename="ab.pdf"');
    });

    it("truncates a very long non-ASCII filename to 255 code points before building headers", async () => {
      const filename = "é".repeat(300) + ".pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      // The truncated name is 255 "é"s with the ".pdf" suffix cut off entirely.
      expect(res.headers.get("X-Filename")).toBe("é".repeat(255));
      const cd = res.headers.get("Content-Disposition");
      expect(cd).not.toBeNull();
      expect(cd!.length).toBeLessThanOrEqual(4096);
      expect(cd).toBe(
        `attachment; filename="${"_".repeat(255)}"; filename*=UTF-8''${"%C3%A9".repeat(255)}`,
      );
    });

    it("combines non-ASCII substitution with escaping of RFC 5987 attr-char exclusions", async () => {
      const filename = "résumé (v1)'s !*.pdf";
      const res = await fetchWithFilename(filename);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Disposition")).toBe(
        "attachment; filename=\"r_sum_ (v1)'s !*.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%28v1%29%27s%20%21%2A.pdf",
      );
    });
  });
});

describe("handleFetch — v2 streaming", () => {
  const BLOCK = 1_048_576;
  const pat = (n: number) => {
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i++) a[i] = (i * 13 + 1) & 0xff;
    return a;
  };
  const get = (d: { d1: FakeD1; r2: FakeR2; token: string; handle: string }, now: number, cfg: StagingConfig = CFG) =>
    handleFetch(
      new Request(`https://x.test/staging/fetch/${d.handle}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${d.token}` },
      }),
      { STAGING_D1: d.d1 as unknown as D1Database, STAGING_R2: d.r2 as unknown as R2Bucket, config: cfg, now: () => now + 2 },
    );

  it("streams a multi-block body with Content-Length = byte_len", async () => {
    const now = 1_000_000;
    const x = pat(2 * BLOCK + 7);
    const d = await seed(now, x, "application/pdf");
    const res = await get(d, now);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe(String(x.byteLength));
    expect(res.body).toBeInstanceOf(ReadableStream);
    expect(Buffer.from(await res.arrayBuffer()).equals(Buffer.from(x))).toBe(true);
  });

  it("an object of the wrong size → 410 + corrupt before any 200", async () => {
    const now = 1_000_000;
    const d = await seed(now, pat(BLOCK + 1));
    const [k, v] = [...d.r2.store.entries()][0]!;
    d.r2.store.set(k, v.subarray(0, v.byteLength - 1));
    const res = await get(d, now);
    expect(res.status).toBe(410);
    const row = await lookupByHash(d.d1 as unknown as D1Database, await sha256Bearer(d.token));
    expect(row!.state).toBe("corrupt");
  });

  it("a tamper in block 2 → the body errors after block 1 (never a clean EOF); row corrupt", async () => {
    const now = 1_000_000;
    const d = await seed(now, pat(2 * BLOCK + 7));
    const [, v] = [...d.r2.store.entries()][0]!;
    v[BLOCK + 16 + 5] = v[BLOCK + 16 + 5]! ^ 1;
    const res = await get(d, now);
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    let got = 0;
    const err = await (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return null;
        got += value.byteLength;
      }
    })().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(got).toBe(BLOCK);
    const row = await lookupByHash(d.d1 as unknown as D1Database, await sha256Bearer(d.token));
    expect(row!.state).toBe("corrupt");
  });

  it("refuses a v1 row of any size with 410 and never reads R2", async () => {
    const { seedV1Row } = await import("./__fixtures__/v1-row");
    const now = 1_000_000;
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const small = await seedV1Row(d1, r2, pat(32), { now, contentType: "text/plain" });
    const big = await seedV1Row(d1, r2, pat(33), { now });
    const cfg = { ...CFG, getFileMaxBytes: 32 };
    for (const row of [small, big]) {
      const res = await get({ d1, r2, token: row.token, handle: row.handle }, now, cfg);
      expect(res.status).toBe(410);
      expect(await res.text()).toBe("gone");
    }
    expect(r2.getCalls).toBe(0);
  });
});
