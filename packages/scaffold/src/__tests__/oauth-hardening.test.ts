import { describe, it, expect } from "vitest";
import {
  checkRateLimit,
  classifyHardenedRequest,
  clientIdentity,
  withNoStore,
  tooManyRequestsResponse,
  enforceOAuthHardening,
  stampClientRegistration,
  validateRegistrationRedirectUris,
  checkFailureBudget,
  recordFailure,
  enforceStagingThrottle,
  CLIENT_STAMP_PREFIX,
  type RateLimitStore,
} from "../oauth-hardening";

function fakeStore(): RateLimitStore & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    async get(k: string) {
      return data.get(k) ?? null;
    },
    async put(k: string, v: string) {
      data.set(k, v);
    },
  };
}

const CFG = { limit: 3, windowSeconds: 60 };
const HCFG = { register: CFG, token: CFG };

describe("checkRateLimit (fixed window counter)", () => {
  it("allows up to the limit then blocks the next request", async () => {
    const store = fakeStore();
    const id = { endpoint: "register", client: "1.2.3.4" };
    const now = 1_000_000;
    for (let i = 0; i < 3; i++) {
      const d = await checkRateLimit(store, id, CFG, now);
      expect(d.allowed).toBe(true);
    }
    const blocked = await checkRateLimit(store, id, CFG, now);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
    expect(blocked.retryAfterSeconds).toBeLessThanOrEqual(60);
  });

  it("resets the count in the next fixed window", async () => {
    const store = fakeStore();
    const id = { endpoint: "token", client: "9.9.9.9" };
    const t0 = 1_000_000; // ms
    for (let i = 0; i < 3; i++) await checkRateLimit(store, id, CFG, t0);
    expect((await checkRateLimit(store, id, CFG, t0)).allowed).toBe(false);
    // advance past the window boundary
    const t1 = t0 + 61_000;
    expect((await checkRateLimit(store, id, CFG, t1)).allowed).toBe(true);
  });

  it("tracks endpoints and clients independently", async () => {
    const store = fakeStore();
    const now = 500_000;
    for (let i = 0; i < 3; i++)
      await checkRateLimit(store, { endpoint: "register", client: "a" }, CFG, now);
    // same client, different endpoint — not blocked
    expect(
      (await checkRateLimit(store, { endpoint: "token", client: "a" }, CFG, now)).allowed,
    ).toBe(true);
    // different client, same endpoint — not blocked
    expect(
      (await checkRateLimit(store, { endpoint: "register", client: "b" }, CFG, now)).allowed,
    ).toBe(true);
  });
});

describe("classifyHardenedRequest", () => {
  it("matches POST /register and POST /token", () => {
    expect(
      classifyHardenedRequest(new Request("https://x.test/register", { method: "POST" })),
    ).toBe("register");
    expect(
      classifyHardenedRequest(new Request("https://x.test/token", { method: "POST" })),
    ).toBe("token");
  });

  it("ignores non-POST methods and unrelated / sub paths", () => {
    expect(classifyHardenedRequest(new Request("https://x.test/token", { method: "GET" }))).toBeNull();
    expect(
      classifyHardenedRequest(new Request("https://x.test/register/abc", { method: "POST" })),
    ).toBeNull();
    expect(
      classifyHardenedRequest(new Request("https://x.test/mcp", { method: "POST" })),
    ).toBeNull();
  });
});

describe("clientIdentity", () => {
  it("uses CF-Connecting-IP when present", () => {
    const req = new Request("https://x.test/token", {
      method: "POST",
      headers: { "CF-Connecting-IP": "203.0.113.7" },
    });
    expect(clientIdentity(req)).toBe("203.0.113.7");
  });

  it("falls back to a stable sentinel when the header is absent", () => {
    const req = new Request("https://x.test/token", { method: "POST" });
    expect(clientIdentity(req)).toBe("unknown");
  });

  // F-14: one subscriber typically controls a whole IPv6 /64.
  const idOf = (ip: string) =>
    clientIdentity(new Request("https://x.test/register", { headers: { "CF-Connecting-IP": ip } }));

  it("buckets IPv6 by /64 (compressed, full, upper-case and zero-padded forms agree)", () => {
    const want = "ip6:2001:db8:abcd:12::/64";
    expect(idOf("2001:db8:abcd:12::1")).toBe(want);
    expect(idOf("2001:db8:abcd:12:ffff:ffff:ffff:fffe")).toBe(want);
    expect(idOf("2001:0DB8:ABCD:0012:0000:0000:0000:0001")).toBe(want);
    expect(idOf("2001:db8:abcd:12:1::")).toBe(want);
    expect(idOf("2001:db8:abcd:13::1")).toBe("ip6:2001:db8:abcd:13::/64");
    expect(idOf("::1")).toBe("ip6:0:0:0:0::/64");
    expect(idOf("fe80::")).toBe("ip6:fe80:0:0:0::/64");
  });

  it("accepts an embedded dotted IPv4 tail", () => {
    expect(idOf("2001:db8:1:2::192.0.2.1")).toBe("ip6:2001:db8:1:2::/64");
    expect(idOf("64:ff9b::198.51.100.4")).toBe("ip6:64:ff9b:0:0::/64");
  });

  it("treats IPv4-mapped IPv6 as the IPv4 address", () => {
    expect(idOf("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(idOf("::FFFF:203.0.113.7")).toBe("203.0.113.7");
    expect(idOf("0:0:0:0:0:ffff:cb00:7107")).toBe("203.0.113.7");
  });

  it("leaves IPv4 per-address and uses an unparseable value verbatim", () => {
    expect(idOf("198.51.100.1")).toBe("198.51.100.1");
    expect(idOf("198.51.100.2")).toBe("198.51.100.2");
    for (const bad of ["1::2::3", "2001:db8:::1", "12345::1", "1:2:3:4:5:6:7:8:9", "::ffff:300.1.1.1", "g::1", "1:2:3:4:5:6:7:1.2.3.4"]) {
      expect(idOf(bad)).toBe(bad);
    }
  });
});

describe("validateRegistrationRedirectUris (F-2)", () => {
  const reg = (body: unknown, headers: Record<string, string> = {}) =>
    new Request("https://x.test/register", {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });

  it("rejects an http:// redirect URI on a non-loopback host with a no-store 400", async () => {
    const res = await validateRegistrationRedirectUris(
      reg({ redirect_uris: ["https://claude.ai/cb", "http://attacker.example/collect"] }),
    );
    expect(res).not.toBeNull();
    expect(res!.status).toBe(400);
    expect(res!.headers.get("cache-control")).toBe("no-store");
    expect(await res!.json()).toEqual({
      error: "invalid_redirect_uri",
      error_description: "http:// redirect URIs are only accepted for loopback hosts; use https",
    });
  });

  it("accepts https:// and loopback http:// URIs", async () => {
    const res = await validateRegistrationRedirectUris(
      reg({
        redirect_uris: [
          "https://claude.ai/api/mcp/auth_callback",
          "http://localhost:6274/oauth/callback",
          "http://127.0.0.1:33418/cb",
          "http://[::1]:8080/cb",
        ],
      }),
    );
    expect(res).toBeNull();
  });

  it("leaves non-JSON, oversized, non-array and custom-scheme bodies to the library", async () => {
    expect(await validateRegistrationRedirectUris(reg("not json"))).toBeNull();
    expect(await validateRegistrationRedirectUris(reg({ redirect_uris: "http://attacker.example" }))).toBeNull();
    expect(await validateRegistrationRedirectUris(reg({ redirect_uris: ["cursor://anysphere.cursor-retrieval/cb", "::bad::", 7] }))).toBeNull();
    expect(
      await validateRegistrationRedirectUris(
        reg({ redirect_uris: ["http://attacker.example/x"] }, { "content-length": String(2 * 1024 * 1024) }),
      ),
    ).toBeNull();
  });

  it("leaves the original request body readable", async () => {
    const req = reg({ redirect_uris: ["https://claude.ai/cb"] });
    await validateRegistrationRedirectUris(req);
    expect(await req.json()).toEqual({ redirect_uris: ["https://claude.ai/cb"] });
  });

  it("enforceOAuthHardening refuses the bad registration without calling the handler", async () => {
    const store = fakeStore();
    let called = 0;
    const handler = async () => { called += 1; return new Response("{}", { status: 201 }); };
    const bad = await enforceOAuthHardening(
      reg({ redirect_uris: ["http://attacker.example/collect"] }, { "CF-Connecting-IP": "1.1.1.1" }),
      store, HCFG, 1_000, handler,
    );
    expect(bad.status).toBe(400);
    expect(bad.headers.get("cache-control")).toBe("no-store");
    expect(called).toBe(0);
    const ok = await enforceOAuthHardening(
      reg({ redirect_uris: ["http://localhost:1234/cb"] }, { "CF-Connecting-IP": "1.1.1.2" }),
      store, HCFG, 1_000, handler,
    );
    expect(ok.status).toBe(201);
    expect(called).toBe(1);
    // A non-JSON body passes through to the handler (which rejects it itself).
    const raw = await enforceOAuthHardening(
      reg("garbage", { "CF-Connecting-IP": "1.1.1.3" }), store, HCFG, 1_000, handler,
    );
    expect(raw.status).toBe(201);
    expect(called).toBe(2);
  });

  it("is not applied to /token", async () => {
    const store = fakeStore();
    const res = await enforceOAuthHardening(
      new Request("https://x.test/token", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://attacker.example"] }),
      }),
      store, HCFG, 1_000, async () => new Response("{}", { status: 200 }),
    );
    expect(res.status).toBe(200);
  });
});

describe("staging failure-budget throttle (F-13)", () => {
  const FB = { limit: 2, windowSeconds: 300 };
  const req = (ip = "203.0.113.9") =>
    new Request("https://x.test/staging/fetch/fh_x", { headers: { "CF-Connecting-IP": ip } });

  it("only 403s count; 429 before the handler once the budget is spent", async () => {
    const store = fakeStore();
    let calls = 0;
    const forbidden = async () => { calls += 1; return new Response("forbidden", { status: 403 }); };
    const notFound = async () => { calls += 1; return new Response("nf", { status: 404 }); };
    for (let i = 0; i < 3; i++) {
      expect((await enforceStagingThrottle(req(), store, FB, 1_000, notFound)).status).toBe(404);
    }
    expect(store.data.size).toBe(0);
    expect((await enforceStagingThrottle(req(), store, FB, 1_000, forbidden)).status).toBe(403);
    expect((await enforceStagingThrottle(req(), store, FB, 1_000, forbidden)).status).toBe(403);
    const before = calls;
    const blocked = await enforceStagingThrottle(req(), store, FB, 1_000, forbidden);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(calls).toBe(before);
    // Another client, and the next window, are unaffected.
    expect((await enforceStagingThrottle(req("203.0.113.10"), store, FB, 1_000, forbidden)).status).toBe(403);
    expect((await enforceStagingThrottle(req(), store, FB, 301_000, forbidden)).status).toBe(403);
  });

  it("successful requests never write KV", async () => {
    const store = fakeStore();
    let puts = 0;
    const origPut = store.put.bind(store);
    store.put = async (k, v) => { puts += 1; await origPut(k, v); };
    for (let i = 0; i < 10; i++) {
      const res = await enforceStagingThrottle(req(), store, FB, 1_000, async () => new Response("ok"));
      expect(res.status).toBe(200);
    }
    expect(puts).toBe(0);
  });

  it("keys the counter by client and window with a TTL just past the window", async () => {
    const puts: Array<{ k: string; v: string; opts: unknown }> = [];
    const store: RateLimitStore = {
      async get() { return null; },
      async put(k, v, opts) { puts.push({ k, v, opts }); },
    };
    await recordFailure(store, "ip6:2001:db8:0:1::/64", FB, 600_000);
    expect(puts).toEqual([
      { k: "ratelimit:staging-fail:ip6:2001:db8:0:1::/64:2", v: "1", opts: { expirationTtl: 360 } },
    ]);
  });

  it("uses waitUntil for the failure write when given", async () => {
    const store = fakeStore();
    const pending: Promise<unknown>[] = [];
    const res = await enforceStagingThrottle(
      req(), store, FB, 1_000, async () => new Response("forbidden", { status: 403 }),
      (p) => { pending.push(p); },
    );
    expect(res.status).toBe(403);
    expect(pending).toHaveLength(1);
    await Promise.all(pending);
    expect([...store.data.values()]).toEqual(["1"]);
  });

  it("swallows store errors on write and fails open on read", async () => {
    const broken: RateLimitStore = {
      async get() { throw new Error("kv down"); },
      async put() { throw new Error("kv down"); },
    };
    await expect(recordFailure(broken, "c", FB, 0)).resolves.toBeUndefined();
    expect(await checkFailureBudget(broken, "c", FB, 0)).toEqual({ allowed: true, retryAfterSeconds: 0 });
    const res = await enforceStagingThrottle(
      req(), broken, FB, 0, async () => new Response("forbidden", { status: 403 }),
    );
    expect(res.status).toBe(403);
  });

  it("buckets IPv6 neighbours in one /64 together", async () => {
    const store = fakeStore();
    const forbidden = async () => new Response("forbidden", { status: 403 });
    await enforceStagingThrottle(req("2001:db8:1:2::a"), store, FB, 1_000, forbidden);
    await enforceStagingThrottle(req("2001:db8:1:2::b"), store, FB, 1_000, forbidden);
    expect((await enforceStagingThrottle(req("2001:db8:1:2::c"), store, FB, 1_000, forbidden)).status).toBe(429);
  });
});

describe("withNoStore", () => {
  it("adds no-store cache headers while preserving status and body", async () => {
    const res = new Response(JSON.stringify({ ok: true }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
    const wrapped = withNoStore(res);
    expect(wrapped.status).toBe(201);
    expect(wrapped.headers.get("Cache-Control")).toBe("no-store");
    expect(wrapped.headers.get("Pragma")).toBe("no-cache");
    expect(wrapped.headers.get("content-type")).toBe("application/json");
    expect(await wrapped.json()).toEqual({ ok: true });
  });
});

describe("tooManyRequestsResponse", () => {
  it("returns 429 with Retry-After and no-store headers", async () => {
    const res = tooManyRequestsResponse(42);
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("42");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });
});

describe("enforceOAuthHardening (composition)", () => {
  it("passes non-hardened requests straight through, untouched", async () => {
    const store = fakeStore();
    let called = 0;
    const handler = async () => {
      called++;
      return new Response("mcp", { status: 200 });
    };
    const req = new Request("https://x.test/mcp", { method: "POST" });
    const res = await enforceOAuthHardening(req, store, HCFG, 1000, handler);
    expect(called).toBe(1);
    expect(res.status).toBe(200);
    // no cache header injected on non-hardened paths
    expect(res.headers.get("Cache-Control")).toBeNull();
  });

  it("wraps hardened responses under the limit with no-store headers", async () => {
    const store = fakeStore();
    const handler = async () =>
      new Response(JSON.stringify({ client_id: "abc" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    const req = new Request("https://x.test/register", {
      method: "POST",
      headers: { "CF-Connecting-IP": "1.1.1.1" },
    });
    const res = await enforceOAuthHardening(req, store, HCFG, 1000, handler);
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Pragma")).toBe("no-cache");
  });

  it("blocks with 429 once the limit is exceeded and does not call the handler", async () => {
    const store = fakeStore();
    let called = 0;
    const handler = async () => {
      called++;
      return new Response("{}", { status: 200 });
    };
    const mk = () =>
      new Request("https://x.test/token", {
        method: "POST",
        headers: { "CF-Connecting-IP": "5.5.5.5" },
      });
    for (let i = 0; i < 3; i++) {
      const ok = await enforceOAuthHardening(mk(), store, HCFG, 2000, handler);
      expect(ok.status).toBe(200);
    }
    const blocked = await enforceOAuthHardening(mk(), store, HCFG, 2000, handler);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("Retry-After")).toBeTruthy();
    expect(called).toBe(3); // handler not invoked on the blocked request
  });

  it("applies register and token limits independently", async () => {
    const store = fakeStore();
    const cfg = { register: { limit: 1, windowSeconds: 300 }, token: { limit: 3, windowSeconds: 60 } };
    const handler = async () => new Response("{}", { status: 200 });
    const reg = () =>
      new Request("https://x.test/register", { method: "POST", headers: { "CF-Connecting-IP": "7.7.7.7" } });
    const tok = () =>
      new Request("https://x.test/token", { method: "POST", headers: { "CF-Connecting-IP": "7.7.7.7" } });

    // register: 1 allowed, 2nd blocked
    expect((await enforceOAuthHardening(reg(), store, cfg, 1000, handler)).status).toBe(200);
    expect((await enforceOAuthHardening(reg(), store, cfg, 1000, handler)).status).toBe(429);

    // token from the same IP is unaffected by the exhausted register bucket:
    // 3 allowed, 4th blocked
    for (let i = 0; i < 3; i++) {
      expect((await enforceOAuthHardening(tok(), store, cfg, 1000, handler)).status).toBe(200);
    }
    expect((await enforceOAuthHardening(tok(), store, cfg, 1000, handler)).status).toBe(429);
  });
});

describe("stampClientRegistration", () => {
  it("writes a registeredAt stamp keyed by client_id", async () => {
    const store = fakeStore();
    await stampClientRegistration(store, JSON.stringify({ client_id: "cid-1" }), 12345);
    const raw = store.data.get(`${CLIENT_STAMP_PREFIX}cid-1`);
    expect(raw).toBeDefined();
    expect(JSON.parse(raw!)).toEqual({ registeredAt: 12345 });
  });

  it("skips a non-JSON body", async () => {
    const store = fakeStore();
    await stampClientRegistration(store, "<html>not json</html>", 1);
    expect(store.data.size).toBe(0);
  });

  it("skips a body with no string client_id", async () => {
    const store = fakeStore();
    await stampClientRegistration(store, JSON.stringify({ foo: "bar" }), 1);
    await stampClientRegistration(store, JSON.stringify({ client_id: 42 }), 1);
    expect(store.data.size).toBe(0);
  });
});

describe("enforceOAuthHardening (registration stamping)", () => {
  const mkReg = () =>
    new Request("https://x.test/register", { method: "POST", headers: { "CF-Connecting-IP": "2.2.2.2" } });

  it("stamps a successful /register and preserves the response body", async () => {
    const store = fakeStore();
    const handler = async () =>
      new Response(JSON.stringify({ client_id: "reg-xyz", client_secret: "s" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    const res = await enforceOAuthHardening(mkReg(), store, HCFG, 999, handler);
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ client_id: "reg-xyz", client_secret: "s" });
    expect(JSON.parse(store.data.get(`${CLIENT_STAMP_PREFIX}reg-xyz`)!)).toEqual({ registeredAt: 999 });
  });

  it("does not stamp a failed /register", async () => {
    const store = fakeStore();
    const handler = async () => new Response(JSON.stringify({ error: "bad" }), { status: 400 });
    await enforceOAuthHardening(mkReg(), store, HCFG, 999, handler);
    const stamps = [...store.data.keys()].filter((k) => k.startsWith(CLIENT_STAMP_PREFIX));
    expect(stamps).toEqual([]);
  });

  it("does not stamp a /token response", async () => {
    const store = fakeStore();
    const handler = async () =>
      new Response(JSON.stringify({ client_id: "should-not-stamp" }), { status: 200 });
    const req = new Request("https://x.test/token", { method: "POST", headers: { "CF-Connecting-IP": "2.2.2.2" } });
    await enforceOAuthHardening(req, store, HCFG, 999, handler);
    const stamps = [...store.data.keys()].filter((k) => k.startsWith(CLIENT_STAMP_PREFIX));
    expect(stamps).toEqual([]);
  });
});
