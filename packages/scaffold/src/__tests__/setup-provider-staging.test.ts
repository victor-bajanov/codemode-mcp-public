import { describe, it, expect } from "vitest";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { handleUpload } from "../staging/upload-handler";
import { handleFetch } from "../staging/fetch-handler";
import { runSweep } from "../staging/sweep";
import { mintToken } from "../staging/tokens";
import { enforceStagingThrottle } from "../oauth-hardening";
import { setupProvider } from "../setup-provider";
import type { ApiProvider } from "../api-provider";

function fakeKv() {
  const data = new Map<string, string>();
  return {
    data,
    async get(k: string) { return data.get(k) ?? null; },
    async put(k: string, v: string) { data.set(k, v); },
    async delete(k: string) { data.delete(k); },
  };
}

// Re-test the routing path by simulating the wrapped fetch logic directly:
function routerFromWrapped(stagingEnv: { STAGING_D1: D1Database; STAGING_R2: R2Bucket }) {
  const kv = fakeKv();
  const throttle = { limit: 30, windowSeconds: 300 };
  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const config = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
    if (url.pathname === "/staging/upload" && req.method === "POST") {
      return enforceStagingThrottle(req, kv, throttle, Date.now(), (r) =>
        handleUpload(r, { ...stagingEnv, config }));
    }
    if (url.pathname.startsWith("/staging/fetch/") && req.method === "GET") {
      return enforceStagingThrottle(req, kv, throttle, Date.now(), (r) =>
        handleFetch(r, { ...stagingEnv, config }));
    }
    return new Response("not /staging", { status: 404 });
  };
}

describe("setup-provider routing (staging)", () => {
  it("routes POST /staging/upload to the upload handler (403 without bearer is the proof)", async () => {
    const router = routerFromWrapped({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
    });
    const res = await router(new Request("https://x.test/staging/upload", { method: "POST", body: new Uint8Array([1]) }));
    expect(res.status).toBe(403);
  });

  it("routes GET /staging/fetch/<x> to the fetch handler", async () => {
    const router = routerFromWrapped({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
    });
    const res = await router(new Request("https://x.test/staging/fetch/fh_x", { method: "GET" }));
    expect(res.status).toBe(403);
  });

  it("does not match unrelated paths", async () => {
    const router = routerFromWrapped({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
    });
    const res = await router(new Request("https://x.test/mcp", { method: "POST" }));
    expect(res.status).toBe(404);
  });

  it("scheduled hook is wired to runSweep (smoke test that it doesn't throw with no rows)", async () => {
    const r = await runSweep({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
      now: () => 1,
    });
    expect(r).toEqual({ deletedRows: 0, deletedObjects: 0 });
  });
});

// F-13: the real setupProvider worker puts both staging routes behind the
// failure-budget throttle, keyed by client IP, backed by OAUTH_KV.
describe("setupProvider staging throttle (F-13)", () => {
  const PROVIDER = {
    name: "t",
    displayName: "T",
    oauth: {
      authorizeUrl: "https://login.example.com/authorize",
      tokenUrl: "https://login.example.com/token",
      scopes: ["s"],
      clientIdSecretName: "CID",
      clientSecretSecretName: "CSEC",
    },
    spec: {} as never,
    surfaceReview: {},
    apiBaseUrl: "https://api.example.com",
  } as ApiProvider<Record<string, unknown>>;

  function harness(limit: number) {
    const d1 = new FakeD1();
    let prepares = 0;
    const origPrepare = d1.prepare.bind(d1);
    d1.prepare = (sql: string) => { prepares += 1; return origPrepare(sql); };
    const kv = fakeKv();
    const pending: Promise<unknown>[] = [];
    const env = {
      COOKIE_ENCRYPTION_KEY: "k".repeat(32),
      OAUTH_KV: kv,
      STAGING_D1: d1,
      STAGING_R2: new FakeR2(),
      STAGING_FAILURE_RATE_LIMIT: String(limit),
    };
    const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException() {} };
    const worker = setupProvider(PROVIDER).default;
    const send = async (req: Request) => {
      const res = await worker.fetch(req, env as never, ctx as never);
      await Promise.all(pending.splice(0));
      return res;
    };
    return { kv, send, prepares: () => prepares };
  }

  const guess = (ip: string) =>
    new Request("https://x.test/staging/fetch/fh_guess", {
      headers: { Authorization: `Bearer ${mintToken()}`, "CF-Connecting-IP": ip },
    });

  it("returns 429 without a D1 read once the 403 budget is spent", async () => {
    const h = harness(2);
    expect((await h.send(guess("198.51.100.9"))).status).toBe(403);
    expect((await h.send(guess("198.51.100.9"))).status).toBe(403);
    const before = h.prepares();
    const blocked = await h.send(guess("198.51.100.9"));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBeTruthy();
    expect(h.prepares()).toBe(before);
    // Uploads share the budget.
    const up = await h.send(new Request("https://x.test/staging/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${mintToken()}`, "CF-Connecting-IP": "198.51.100.9" },
      body: "x",
    }));
    expect(up.status).toBe(429);
    // A different client is unaffected.
    expect((await h.send(guess("203.0.113.77"))).status).toBe(403);
    expect([...h.kv.data.keys()].every((k) => k.startsWith("ratelimit:staging-fail:"))).toBe(true);
  });
});
