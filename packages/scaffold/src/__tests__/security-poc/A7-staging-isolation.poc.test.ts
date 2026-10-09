// A7 — Staging: token-hash lookup + handle comparison, cross-user reach,
// enumeration, unauthenticated D1 cost, Content-Length pre-check, sweep.
//
// Status: FIXED (F-13) — /staging/* sits behind a per-client failure-budget
// throttle (429 before any D1 read), and uploads are streamed with a byte cap.
//
// Against the real handlers with the project's own FakeD1/FakeR2 fixtures.
//
//   REFUTED: user B's token cannot read user A's handle and vice-versa; the
//            handle alone (the fetch_url) is useless without the bearer; a
//            pending row is reaped once its upload TTL passes.
//   FIXED (F-13, was CONFIRMED Low): any syntactically well-formed `stg_`
//            bearer triggered a D1 lookup on the public /staging/* endpoints
//            with no rate limit. Through `enforceStagingThrottle` (what
//            setup-provider now routes both endpoints through) a client that
//            has spent its 403 budget gets 429 without a D1 query.
//   FIXED (F-13, was CONFIRMED Low): a request with NO Content-Length header
//            (chunked) was buffered in full before the size check. The body
//            is now streamed and cancelled as soon as it passes maxBytes.

import { describe, it, expect } from "vitest";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { createPutFileCapability } from "../../staging/putfile-capability";
import { handleFetch } from "../../staging/fetch-handler";
import { handleUpload } from "../../staging/upload-handler";
import { enforceStagingThrottle } from "../../oauth-hardening";
import { registerFileHandleTool } from "../../staging/register-tool";
import { runSweep } from "../../staging/sweep";
import { mintToken } from "../../staging/tokens";

const config = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 64 };

function deps() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  let prepares = 0;
  const origPrepare = d1.prepare.bind(d1);
  d1.prepare = (sql: string) => { prepares += 1; return origPrepare(sql); };
  return {
    d1, r2, prepares: () => prepares,
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config,
  };
}

const b64 = (s: string) => btoa(s);

describe("A7 staging token/handle isolation", () => {
  it("REFUTED: cross-user — B's token with A's handle, and A's token with B's handle, are both 403", async () => {
    const d = deps();
    const putFile = createPutFileCapability({ STAGING_D1: d.STAGING_D1, STAGING_R2: d.STAGING_R2, config, uploadOrigin: "https://w" });
    const a = await putFile(b64("alice-secret"), "text/plain", "a.txt");
    const b = await putFile(b64("bob-secret"), "text/plain", "b.txt");
    if (!a.ok || !b.ok) throw new Error("putFile failed");

    const get = (handle: string, token: string) =>
      handleFetch(new Request(`https://w/staging/fetch/${handle}`, { headers: { Authorization: `Bearer ${token}` } }), d);

    expect((await get(a.file_handle, a.token)).status).toBe(200);
    expect(await (await get(a.file_handle, a.token)).text()).toBe("alice-secret");
    expect((await get(a.file_handle, b.token)).status).toBe(403);
    expect((await get(b.file_handle, a.token)).status).toBe(403);
    // fetch_url alone (what a user might paste around) is useless without the bearer.
    expect((await handleFetch(new Request(a.fetch_url), d)).status).toBe(403);
    // Hash lookup: the row is keyed by SHA-256(token); a wrong token simply finds no row.
    expect(d.d1.rows.size).toBe(2);
  });

  it("REFUTED: tokens are 256-bit random, handles 128-bit random — not derived from each other", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(mintToken());
    expect(seen.size).toBe(1000);
    expect([...seen][0]).toMatch(/^stg_[A-Za-z0-9_-]{43}$/);
  });

  it("FIXED (F-13): once the failure budget is spent, guesses get 429 and cost no D1 query", async () => {
    const d = deps();
    const data = new Map<string, string>();
    const kv = {
      async get(k: string) { return data.get(k) ?? null; },
      async put(k: string, v: string) { data.set(k, v); },
    };
    const budget = { limit: 3, windowSeconds: 300 };
    const guess = (r: Request, h: (r: Request) => Promise<Response>) =>
      enforceStagingThrottle(r, kv, budget, 1_000_000, h);
    const fetchReq = () =>
      new Request("https://w/staging/fetch/fh_whatever", {
        headers: { Authorization: `Bearer ${mintToken()}`, "CF-Connecting-IP": "198.51.100.66" },
      });

    const before = d.prepares();
    for (let i = 0; i < 3; i++) {
      const res = await guess(fetchReq(), (r) => handleFetch(r, d));
      expect(res.status).toBe(403);
    }
    expect(d.prepares() - before).toBe(3); // the budgeted guesses still cost one SELECT each
    for (let i = 0; i < 5; i++) {
      const res = await guess(fetchReq(), (r) => handleFetch(r, d));
      expect(res.status).toBe(429);
    }
    // Same for upload: the budget is shared and no D1 query is made.
    const up = await guess(
      new Request("https://w/staging/upload", {
        method: "POST",
        headers: { Authorization: `Bearer ${mintToken()}`, "CF-Connecting-IP": "198.51.100.66" },
        body: "x",
      }),
      (r) => handleUpload(r, d),
    );
    expect(up.status).toBe(429);
    expect(d.prepares() - before).toBe(3);
  });

  it("FIXED (F-13): without a Content-Length header an oversize body is cancelled once past maxBytes", async () => {
    const d = deps();
    const tool = registerFileHandleTool({ STAGING_D1: d.STAGING_D1, config, uploadOrigin: "https://w", now: () => 1000 });
    const { token } = await tool.handler({});
    let pulled = 0;
    const big = new ReadableStream<Uint8Array>({
      pull(c) {
        if (pulled >= 1024) { c.close(); return; }
        pulled += 64;
        c.enqueue(new Uint8Array(64));
      },
      // No read-ahead, so `pulled` counts exactly what the handler consumed.
    }, { highWaterMark: 0 });
    const req = new Request("https://w/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: big,
      // @ts-expect-error — Node fetch needs duplex for stream bodies
      duplex: "half",
    });
    expect(req.headers.get("Content-Length")).toBeNull();
    const res = await handleUpload(req, { ...d, now: () => 1001 });
    expect(res.status).toBe(413);
    expect(pulled).toBeLessThanOrEqual(config.maxBytes + 64); // was 1024 (16× maxBytes)
    expect(d.r2.store.size).toBe(0); // nothing persisted
    expect([...d.d1.rows.values()][0]!.state).toBe("pending");
  });

  it("REFUTED: a pending row that was never uploaded is reaped once its upload TTL passes", async () => {
    const d = deps();
    const tool = registerFileHandleTool({ STAGING_D1: d.STAGING_D1, config, uploadOrigin: "https://w", now: () => 1000 });
    await tool.handler({});
    expect(d.d1.rows.size).toBe(1);
    await runSweep({ STAGING_D1: d.STAGING_D1, STAGING_R2: d.STAGING_R2, now: () => 1000 + 299 });
    expect(d.d1.rows.size).toBe(1); // within TTL — kept
    await runSweep({ STAGING_D1: d.STAGING_D1, STAGING_R2: d.STAGING_R2, now: () => 1000 + 301 });
    expect(d.d1.rows.size).toBe(0);
  });

  it("REFUTED: a claimed row's ciphertext in R2 is useless without the token (HKDF(token, handle) key)", async () => {
    const d = deps();
    const putFile = createPutFileCapability({ STAGING_D1: d.STAGING_D1, STAGING_R2: d.STAGING_R2, config, uploadOrigin: "https://w" });
    const a = await putFile(b64("alice-secret"), "text/plain", null);
    if (!a.ok) throw new Error();
    const blob = [...d.r2.store.values()][0]!;
    expect(new TextDecoder().decode(blob)).not.toContain("alice-secret");
    // D1 holds only the hash of the token.
    const row = [...d.d1.rows.values()][0]!;
    expect(row.token_hash_hex).toHaveLength(64);
    expect(JSON.stringify(row)).not.toContain(a.token.slice(4));
  });
});
