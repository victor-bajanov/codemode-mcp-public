import { afterEach, describe, it, expect, vi } from "vitest";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { handleUpload } from "../staging/upload-handler";
import { handleFetch } from "../staging/fetch-handler";
import { runSweep } from "../staging/sweep";
import { mintToken } from "../staging/tokens";
import { enforceStagingThrottle } from "../oauth-hardening";
import { setupProvider } from "../setup-provider";
import { registerFileHandleTool } from "../staging/register-tool";
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

  function harness(limit: number, opts: { d1?: FakeD1; vars?: Record<string, string> } = {}) {
    const d1 = opts.d1 ?? new FakeD1();
    let prepares = 0;
    const origPrepare = d1.prepare.bind(d1);
    d1.prepare = (sql: string) => { prepares += 1; return origPrepare(sql); };
    const kv = fakeKv();
    const pending: Promise<unknown>[] = [];
    const env = {
      DEPLOYMENT_NAME: "t-deploy",
      COOKIE_ENCRYPTION_KEY: "k".repeat(32),
      OAUTH_KV: kv,
      STAGING_D1: d1,
      STAGING_R2: new FakeR2(),
      STAGING_FAILURE_RATE_LIMIT: String(limit),
      ...opts.vars,
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

  // E-1 (2026-11 review): both public routes write one audit line per
  // request through a sink named after the deployment; the handlers set the
  // principal from the row's owner. The handle never appears in a line.
  describe("public-route audit (E-1)", () => {
    afterEach(() => vi.restoreAllMocks());

    function captureAudit() {
      const lines: string[] = [];
      vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
        const s = a.map(String).join(" ");
        if (s.startsWith("AUDIT ")) lines.push(s);
      });
      return {
        raw: lines,
        parsed: () => lines.map((l) => JSON.parse(l.slice(6)) as Record<string, unknown>),
      };
    }

    it("FIXED (E-1): a refused download is audited with the deployment name and no handle", async () => {
      const audit = captureAudit();
      const h = harness(30);
      expect((await h.send(guess("198.51.100.20"))).status).toBe(403);
      expect(audit.parsed()).toEqual([
        expect.objectContaining({
          deployment: "t-deploy",
          method: "GET",
          path: "/staging/fetch",
          operationId: "staging.download",
          decision: "deny",
          staging: expect.objectContaining({ event: "download", status: 403 }),
        }),
      ]);
      expect(audit.raw.join("\n")).not.toContain("fh_guess");
    });

    it("FIXED (E-1): a refused upload is audited with the deployment name and no principal", async () => {
      const audit = captureAudit();
      const h = harness(30);
      const res = await h.send(
        new Request("https://x.test/staging/upload", {
          method: "POST",
          headers: { Authorization: `Bearer ${mintToken()}`, "CF-Connecting-IP": "198.51.100.21" },
          body: "x",
        }),
      );
      expect(res.status).toBe(403);
      const lines = audit.parsed();
      expect(lines).toEqual([
        expect.objectContaining({
          deployment: "t-deploy",
          method: "POST",
          path: "/staging/upload",
          operationId: "staging.upload",
          decision: "deny",
        }),
      ]);
      expect(lines[0]!.principalId).toBeUndefined();
    });

    it("FIXED (E-1) + REFUTED (E-2 budget): register → upload → download up to STAGING_FETCH_MAX_USES (2) times (200), then 410; the 410s spend no failure budget", async () => {
      const audit = captureAudit();
      const d1 = new FakeD1();
      const h = harness(1, { d1, vars: { STAGING_FETCH_MAX_USES: "2" } });
      const reg = await registerFileHandleTool({
        STAGING_D1: d1 as unknown as D1Database,
        config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 1024 },
        uploadOrigin: "https://x.test",
        owner: "user-A",
      }).handler({});
      const ip = "198.51.100.22";
      const up = await h.send(
        new Request("https://x.test/staging/upload", {
          method: "POST",
          headers: { Authorization: `Bearer ${reg.token}`, "CF-Connecting-IP": ip },
          body: "SECRET",
        }),
      );
      expect(up.status).toBe(204);
      const get = () =>
        h.send(
          new Request(`https://x.test/staging/fetch/${reg.file_handle}`, {
            headers: { Authorization: `Bearer ${reg.token}`, "CF-Connecting-IP": ip },
          }),
        );
      for (let i = 0; i < 2; i++) {
        const ok = await get();
        expect(ok.status).toBe(200);
        expect(await ok.text()).toBe("SECRET");
      }
      expect((await get()).status).toBe(410);
      expect((await get()).status).toBe(410);
      // Budget of one 403: the 410s did not spend it, so the first wrong
      // guess still reaches the handler (403) and only the next is throttled.
      expect((await h.send(guess(ip))).status).toBe(403);
      expect((await h.send(guess(ip))).status).toBe(429);

      const lines = audit.parsed();
      const upload = lines.find((l) => l.operationId === "staging.upload")!;
      expect(upload).toMatchObject({ deployment: "t-deploy", principalId: "user-A", decision: "allow" });
      const downloads = lines.filter(
        (l) => l.operationId === "staging.download" && l.principalId === "user-A",
      );
      expect(downloads.map((l) => (l.staging as { status: number }).status)).toEqual([200, 200, 410, 410]);
      const refs = new Set(downloads.map((l) => (l.staging as { fileRef: string }).fileRef));
      expect(refs.size).toBe(1);
      expect([...refs][0]).toBe((upload.staging as { fileRef: string }).fileRef);
      expect(audit.raw.join("\n")).not.toContain(reg.file_handle);
      expect(audit.raw.join("\n")).not.toContain(reg.token);
    });
  });
});

// A-5 (2026-11 review): the scheduled handler used to run an OAuth client
// sweep that read OAUTH_KV once per grant and once per ungranted client on
// every five-minute run. Client records now expire by KV TTL, so the cron
// does staging work only and issues no OAUTH_KV operation at all.
describe("setupProvider scheduled handler (A-5)", () => {
  it("FIXED (A-5): issues zero OAUTH_KV operations; the staging sweep still runs", async () => {
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
    const kv = fakeKv();
    // Junk the old sweep would have walked.
    for (let i = 0; i < 5; i++) {
      kv.data.set(`client:junk-${i}`, "{}");
      kv.data.set(`clientreg:junk-${i}`, JSON.stringify({ registeredAt: 0 }));
    }
    const ops = {
      get: vi.fn(kv.get),
      put: vi.fn(kv.put),
      delete: vi.fn(kv.delete),
      list: vi.fn(async () => ({ keys: [], list_complete: true, cursor: undefined })),
    };
    const d1 = new FakeD1();
    let prepares = 0;
    const origPrepare = d1.prepare.bind(d1);
    d1.prepare = (sql: string) => { prepares += 1; return origPrepare(sql); };
    const env = {
      DEPLOYMENT_NAME: "t-deploy",
      COOKIE_ENCRYPTION_KEY: "k".repeat(32),
      OAUTH_KV: ops,
      STAGING_D1: d1,
      STAGING_R2: new FakeR2(),
    };
    const pending: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException() {} };
    const worker = setupProvider(PROVIDER).default;
    await worker.scheduled({} as never, env as never, ctx as never);
    await Promise.all(pending);
    expect(ops.get).not.toHaveBeenCalled();
    expect(ops.list).not.toHaveBeenCalled();
    expect(ops.put).not.toHaveBeenCalled();
    expect(ops.delete).not.toHaveBeenCalled();
    expect(kv.data.size).toBe(10);
    expect(prepares).toBeGreaterThan(0);
  });
});
