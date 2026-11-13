import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { handleUpload } from "../upload-handler";
import { handleFetch } from "../fetch-handler";
import { insertPending, lookupByHash } from "../repo";
import { mintToken, mintFileHandle } from "../tokens";
import { fileRefOf, sha256Bearer } from "../crypto";
import type { AuditSink } from "../../audit";
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
    owner: "user-A",
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
      owner: "user-A",
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

  // E-1 (2026-11 review). Attacker: anyone holding a leaked {file_handle, token} pair (e.g. a
  // fetch_url + bearer echoed into a chat). Pre-fix the public route was unlimited within the
  // fetch TTL. Each GET is now counted (fetch_count) before any R2 read, up to
  // STAGING_FETCH_MAX_USES (default 5); past the limit a GET is 410 with no R2 read.
  async function getN(
    seeded: Awaited<ReturnType<typeof seed>>,
    now: number,
    cfg: StagingConfig,
  ): Promise<(i: number) => Promise<Response>> {
    const { d1, r2, token, handle } = seeded;
    return (i: number) =>
      handleFetch(
        new Request(`https://x.test/staging/fetch/${handle}`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        }),
        { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: cfg, now: () => now + 2 + i },
      );
  }

  it("FIXED (E-1): with STAGING_FETCH_MAX_USES 5 the 5th GET is 200 and the 6th is 410 (no R2 read)", async () => {
    const now = 1_000_000;
    const plain = new Uint8Array([7, 8, 9]);
    const seeded = await seed(now, plain);
    const get = await getN(seeded, now, { ...CFG, fetchMaxUses: 5 });
    for (let i = 0; i < 5; i++) {
      const res = await get(i);
      expect(res.status).toBe(200);
      expect(Buffer.from(new Uint8Array(await res.arrayBuffer())).equals(Buffer.from(plain))).toBe(true);
    }
    const gets = seeded.r2.getCalls;
    const sixth = await get(5);
    expect(sixth.status).toBe(410);
    expect(await sixth.text()).toBe("gone");
    expect(seeded.r2.getCalls).toBe(gets); // refused before any R2 read
    const row = await lookupByHash(seeded.d1 as unknown as D1Database, await sha256Bearer(seeded.token));
    expect(row!.fetch_count).toBe(5);
  });

  it("FIXED (E-1): with STAGING_FETCH_MAX_USES 1 the second GET is 410", async () => {
    const now = 1_000_000;
    const seeded = await seed(now, new Uint8Array([7, 8, 9]));
    const get = await getN(seeded, now, { ...CFG, fetchMaxUses: 1 });
    const first = await get(0);
    expect(first.status).toBe(200);
    await first.arrayBuffer();
    const second = await get(1);
    expect(second.status).toBe(410);
    expect(await second.text()).toBe("gone");
  });

  it("FIXED (E-1): an unset limit (config without fetchMaxUses) defaults to 5", async () => {
    const now = 1_000_000;
    const seeded = await seed(now, new Uint8Array([1]));
    const get = await getN(seeded, now, CFG);
    for (let i = 0; i < 5; i++) {
      const res = await get(i);
      expect(res.status).toBe(200);
      await res.arrayBuffer();
    }
    expect((await get(5)).status).toBe(410);
  });

  it("a download that fails after counting still counts", async () => {
    const now = 1_000_000;
    const seeded = await seed(now, new Uint8Array([1, 2, 3]));
    seeded.r2.store.clear(); // the object vanishes after the row checks pass
    const get = await getN(seeded, now, { ...CFG, fetchMaxUses: 2 });
    expect((await get(0)).status).not.toBe(200);
    const row = await lookupByHash(seeded.d1 as unknown as D1Database, await sha256Bearer(seeded.token));
    expect(row!.fetch_count).toBe(1);
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

// E-1 (2026-11 review): the public download is bound to the owner recorded on the row and
// audited. Pre-fix `handleFetch` wrote no audit line at all and served rows without an owner.
describe("handleFetch — owner and audit (E-1)", () => {
  type Line = Parameters<AuditSink>[0];
  const deps = (d1: FakeD1, r2: FakeR2, lines: Line[], at: number, config: StagingConfig = CFG) => ({
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config,
    audit: ((e) => { lines.push(e); }) as AuditSink,
    now: () => at,
  });
  const req = (handle: string, token?: string) =>
    new Request(`https://x.test/staging/fetch/${handle}`, {
      method: "GET",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });

  it("FIXED (E-1): 200 then 410 (limit 1), two staging.download lines with the owner and one fileRef; no handle or token", async () => {
    const now = 1_000_000;
    const plain = new Uint8Array([1, 2, 3, 4]);
    const { d1, r2, token, handle } = await seed(now, plain);
    const lines: Line[] = [];
    const one = { ...CFG, fetchMaxUses: 1 };
    const a = await handleFetch(req(handle, token), deps(d1, r2, lines, now + 2, one));
    expect(a.status).toBe(200);
    await a.arrayBuffer();
    const b = await handleFetch(req(handle, token), deps(d1, r2, lines, now + 3, one));
    expect(b.status).toBe(410);
    expect(lines).toHaveLength(2);
    const ref = await fileRefOf(handle);
    expect(lines[0]).toEqual({
      method: "GET", path: "/staging/fetch", operationId: "staging.download", decision: "allow",
      principalId: "user-A",
      staging: { event: "download", fileRef: ref, byteLength: plain.byteLength, status: 200 },
    });
    expect(lines[1]).toMatchObject({
      method: "GET", path: "/staging/fetch", operationId: "staging.download", decision: "deny",
      reason: "staging-refused", principalId: "user-A",
      staging: { event: "download", fileRef: ref, status: 410 },
    });
    for (const l of lines) {
      const s = JSON.stringify(l);
      expect(s).not.toContain(handle);
      expect(s).not.toContain(token);
    }
  });

  it("FIXED (E-1): a legacy row (no owner, pre-0003 shape) is refused with a bare 403 before any R2 read", async () => {
    const now = 1_000_000;
    const { d1, r2, token, handle } = await seed(now, new Uint8Array([9]));
    const stored = [...d1.rows.values()][0]!;
    stored.owner = null; // the shape migration 0003 leaves on older rows
    const lines: Line[] = [];
    const gets = r2.getCalls;
    const res = await handleFetch(req(handle, token), deps(d1, r2, lines, now + 2));
    expect(res.status).toBe(403);
    expect(await res.text()).toBe("forbidden");
    expect(r2.getCalls).toBe(gets);
    expect(stored.fetch_count).toBe(0);
    expect(lines).toHaveLength(1);
    expect(lines[0]!.decision).toBe("deny");
    expect(lines[0]!.principalId).toBeUndefined();
    expect(lines[0]!.staging).toMatchObject({ event: "download", status: 403 });
  });

  it("FIXED (E-1): N+k concurrent GETs at limit N — exactly N 200s and k 410s (the count is atomic)", async () => {
    const now = 1_000_000;
    const { d1, r2, token, handle } = await seed(now, new Uint8Array([5, 6, 7]));
    const lines: Line[] = [];
    const cfg = { ...CFG, fetchMaxUses: 3 };
    const res = await Promise.all(
      [0, 1, 2, 3, 4].map(() => handleFetch(req(handle, token), deps(d1, r2, lines, now + 2, cfg))),
    );
    const statuses = res.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 200, 200, 410, 410]);
    expect([...d1.rows.values()][0]!.fetch_count).toBe(3);
    await Promise.all(res.map((r) => r.arrayBuffer()));
  });

  it("a row whose owner is \"\" is refused like a legacy row; the line names no principal", async () => {
    const now = 1_000_000;
    const { d1, r2, token, handle } = await seed(now, new Uint8Array([9]));
    [...d1.rows.values()][0]!.owner = "";
    const lines: Line[] = [];
    expect((await handleFetch(req(handle, token), deps(d1, r2, lines, now + 2))).status).toBe(403);
    expect(lines[0]).not.toHaveProperty("principalId");
  });

  it("a pending row is 409 and is not counted", async () => {
    const now = 1_000_000;
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const token = mintToken();
    const handle = mintFileHandle();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: await sha256Bearer(token), file_handle: handle, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: now, expires_at: now + 300, owner: "user-A",
    });
    const lines: Line[] = [];
    const res = await handleFetch(req(handle, token), deps(d1, r2, lines, now + 1));
    expect(res.status).toBe(409);
    expect([...d1.rows.values()][0]!.fetch_count).toBe(0);
    expect(lines[0]).toMatchObject({ decision: "deny", principalId: "user-A", staging: { status: 409 } });
  });

  it("a wrong token or a missing bearer logs a deny line with no principal and no fileRef", async () => {
    const now = 1_000_000;
    const { d1, r2, handle } = await seed(now, new Uint8Array([9]));
    const lines: Line[] = [];
    expect((await handleFetch(req(handle, mintToken()), deps(d1, r2, lines, now + 2))).status).toBe(403);
    expect((await handleFetch(req(handle), deps(d1, r2, lines, now + 2))).status).toBe(403);
    expect(lines).toHaveLength(2);
    for (const l of lines) {
      expect(l).toEqual({
        method: "GET", path: "/staging/fetch", operationId: "staging.download", decision: "deny",
        reason: "staging-refused", staging: { event: "download", status: 403 },
      });
    }
  });
});
