import { afterEach, describe, it, expect, vi } from "vitest";
import {
  checkRateLimit,
  classifyHardenedRequest,
  clientIdentity,
  withNoStore,
  tooManyRequestsResponse,
  payloadTooLargeResponse,
  enforceOAuthHardening,
  readBodyCapped,
  refreshClientTtl,
  validateRegistrationRedirectUris,
  checkFailureBudget,
  recordFailure,
  enforceStagingThrottle,
  MAX_FORM_BODY_BYTES,
  MAX_REGISTRATION_BODY_BYTES,
  type HardeningConfig,
  type RateLimitStore,
} from "../oauth-hardening";
import { CHUNK, meteredBody } from "./oauth-worker-harness";

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
const TTL = { registeredSeconds: 1000, activeSeconds: 5000 };
const HCFG: HardeningConfig = {
  register: CFG,
  token: CFG,
  authorize: CFG,
  callback: CFG,
  clientTtl: TTL,
};

/** A store that also records the put options (the client TTL lives there). */
function optsStore(): RateLimitStore & {
  data: Map<string, string>;
  opts: Map<string, { expirationTtl?: number } | undefined>;
} {
  const data = new Map<string, string>();
  const opts = new Map<string, { expirationTtl?: number } | undefined>();
  return {
    data,
    opts,
    async get(k: string) {
      return data.get(k) ?? null;
    },
    async put(k: string, v: string, o?: { expirationTtl?: number }) {
      data.set(k, v);
      opts.set(k, o);
    },
  };
}



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

  it("FIXED (A-3): matches GET/HEAD/POST /authorize and GET/HEAD /callback", () => {
    const c = (path: string, method: string) =>
      classifyHardenedRequest(new Request(`https://x.test${path}`, { method }));
    expect(c("/authorize", "GET")).toBe("authorize");
    expect(c("/authorize", "HEAD")).toBe("authorize");
    expect(c("/authorize", "POST")).toBe("authorize");
    expect(c("/callback", "GET")).toBe("callback");
    expect(c("/callback", "HEAD")).toBe("callback");
    // Other methods pass through (Hono answers them); sub paths are not the endpoint.
    expect(c("/authorize", "PUT")).toBeNull();
    expect(c("/callback", "POST")).toBeNull();
    expect(c("/authorize/x", "GET")).toBeNull();
    expect(c("/callback/x", "GET")).toBeNull();
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
  const text = (body: unknown) => (typeof body === "string" ? body : JSON.stringify(body));

  it("rejects an http:// redirect URI on a non-loopback host with a no-store 400", async () => {
    const res = validateRegistrationRedirectUris(
      text({ redirect_uris: ["https://claude.ai/cb", "http://attacker.example/collect"] }),
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
    const res = validateRegistrationRedirectUris(
      text({
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

  it("leaves non-JSON, non-array and custom-scheme bodies to the library", async () => {
    expect(validateRegistrationRedirectUris("not json")).toBeNull();
    expect(validateRegistrationRedirectUris(text({ redirect_uris: "http://attacker.example" }))).toBeNull();
    expect(validateRegistrationRedirectUris(text({ redirect_uris: ["cursor://anysphere.cursor-retrieval/cb", "::bad::", 7] }))).toBeNull();
  });

  it("FIXED (A-3): a registration body over 1 MiB is 413 from the wrapper; the library is not called", async () => {
    const store = fakeStore();
    let called = 0;
    const handler = async () => { called += 1; return new Response("{}", { status: 201 }); };
    // Declared length over the cap (the pre-fix code handed this to the library).
    const declared = await enforceOAuthHardening(
      reg({ redirect_uris: ["http://attacker.example/x"] }, {
        "content-length": String(2 * 1024 * 1024),
        "CF-Connecting-IP": "1.1.1.9",
      }),
      store, HCFG, 1_000, handler,
    );
    expect(declared.status).toBe(413);
    // No declared length, 1 MiB + 1 byte of real body.
    const over = await enforceOAuthHardening(
      reg("a".repeat(MAX_REGISTRATION_BODY_BYTES + 1), { "CF-Connecting-IP": "1.1.1.8" }),
      store, HCFG, 1_000, handler,
    );
    expect(over.status).toBe(413);
    expect(called).toBe(0);
  });

  it("leaves the original request body readable for the handler", async () => {
    const store = fakeStore();
    let seen: unknown = null;
    const res = await enforceOAuthHardening(
      reg({ redirect_uris: ["https://claude.ai/cb"] }, { "CF-Connecting-IP": "1.1.1.7" }),
      store, HCFG, 1_000,
      async (r) => { seen = await r.json(); return new Response("{}", { status: 400 }); },
    );
    expect(res.status).toBe(400);
    expect(seen).toEqual({ redirect_uris: ["https://claude.ai/cb"] });
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
    const cfg = { ...HCFG, register: { limit: 1, windowSeconds: 300 }, token: { limit: 3, windowSeconds: 60 } };
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


// A-3 (2026-11 review): the library buffers request bodies whole, and the
// pre-fix wrapper read a whole `POST /register` body (tee'd) before checking
// its length; `POST /authorize` and `POST /token` had no bound at all. The
// wrapper now reads every hardened body with a streaming cap and answers 413
// before the handler runs.
describe("readBodyCapped (A-3)", () => {
  it("FIXED (A-3): a declared Content-Length over the cap is refused without touching the body", async () => {
    const body = meteredBody(24 * 1024 * 1024);
    const req = new Request("https://x.test/register", {
      method: "POST",
      headers: { "content-length": String(24 * 1024 * 1024) },
      body: body.stream,
      duplex: "half",
    } as RequestInit);
    expect(await readBodyCapped(req, 1024)).toEqual({ ok: false });
    expect(body.consumed()).toBe(0);
  });

  it("FIXED (A-3): a chunked body is cut off one chunk past the cap", async () => {
    const total = 24 * 1024 * 1024;
    const body = meteredBody(total);
    const req = new Request("https://x.test/register", {
      method: "POST",
      body: body.stream,
      duplex: "half",
    } as RequestInit);
    expect(await readBodyCapped(req, MAX_REGISTRATION_BODY_BYTES)).toEqual({ ok: false });
    expect(body.consumed()).toBeLessThanOrEqual(MAX_REGISTRATION_BODY_BYTES + CHUNK);
  });

  it("returns the text and bytes of a body at or under the cap", async () => {
    const at = await readBodyCapped(
      new Request("https://x.test/token", { method: "POST", body: "a".repeat(16) }),
      16,
    );
    expect(at).toMatchObject({ ok: true, text: "a".repeat(16) });
    const multi = await readBodyCapped(
      new Request("https://x.test/token", { method: "POST", body: "grant_type=x&client_id=%C3%A9" }),
      1024,
    );
    expect(multi.ok && multi.text).toBe("grant_type=x&client_id=%C3%A9");
    expect(multi.ok && multi.bytes.byteLength).toBe(29);
    const over = await readBodyCapped(
      new Request("https://x.test/token", { method: "POST", body: "a".repeat(17) }),
      16,
    );
    expect(over).toEqual({ ok: false });
  });

  it("treats a missing body as empty", async () => {
    const r = await readBodyCapped(new Request("https://x.test/token", { method: "POST" }), 16);
    expect(r.ok && r.text).toBe("");
  });

  it("payloadTooLargeResponse is a no-store 413 invalid_request", async () => {
    const res = payloadTooLargeResponse();
    expect(res.status).toBe(413);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      error: "invalid_request",
      error_description: "Request body too large",
    });
  });
});

describe("enforceOAuthHardening body caps (A-3)", () => {
  const post = (path: string, body: BodyInit, headers: Record<string, string> = {}) =>
    new Request(`https://x.test${path}`, {
      method: "POST",
      headers: { "CF-Connecting-IP": "203.0.113.20", ...headers },
      body,
      duplex: "half",
    } as RequestInit);

  it("FIXED (A-3): POST /token with a 24 MiB body is 413 after at most 16 KiB + one chunk; the handler is not called", async () => {
    const body = meteredBody(24 * 1024 * 1024);
    let called = 0;
    const res = await enforceOAuthHardening(
      post("/token", body.stream, { "content-type": "application/x-www-form-urlencoded" }),
      fakeStore(), HCFG, 1_000,
      async () => { called += 1; return new Response("{}"); },
    );
    expect(res.status).toBe(413);
    expect(body.consumed()).toBeLessThanOrEqual(MAX_FORM_BODY_BYTES + CHUNK);
    expect(called).toBe(0);
  });

  it("FIXED (A-3): POST /authorize with a body over 16 KiB is 413 before the handler", async () => {
    let called = 0;
    const res = await enforceOAuthHardening(
      post("/authorize", "consent_token=" + "a".repeat(MAX_FORM_BODY_BYTES)),
      fakeStore(), HCFG, 1_000,
      async () => { called += 1; return new Response("ok"); },
    );
    expect(res.status).toBe(413);
    expect(called).toBe(0);
  });

  it("hands the handler the same form under the cap (headers kept)", async () => {
    let form: [string, unknown][] = [];
    let cookie: string | null = null;
    const res = await enforceOAuthHardening(
      post("/authorize", "consent_token=t&action=approve", {
        "content-type": "application/x-www-form-urlencoded",
        Cookie: "__Host-cm-consent-x=1",
      }),
      fakeStore(), HCFG, 1_000,
      async (r) => {
        form = [...(await r.formData()).entries()];
        cookie = r.headers.get("cookie");
        return new Response("page", { status: 303, headers: { location: "https://login.example.com/" } });
      },
    );
    expect(res.status).toBe(303);
    expect(form).toEqual([["consent_token", "t"], ["action", "approve"]]);
    expect(cookie).toBe("__Host-cm-consent-x=1");
  });
});

describe("percent-encoded paths (A-3 review)", () => {
  // Hono decodes %xx before routing, so `/%61uthorize` reaches the consent
  // handler; the pre-fix classifier compared the raw path and let it skip the
  // bucket and the body cap.
  const at = (path: string, init: RequestInit = {}) =>
    new Request(`https://x.test${path}`, {
      ...init,
      headers: { "CF-Connecting-IP": "198.51.100.30", ...(init.headers as Record<string, string> | undefined) },
    });

  it("FIXED (A-3): classifies encoded endpoint paths as the endpoint they route to", () => {
    expect(classifyHardenedRequest(at("/%61uthorize"))).toBe("authorize");
    expect(classifyHardenedRequest(at("/%63allback"))).toBe("callback");
    expect(classifyHardenedRequest(at("/%72egister", { method: "POST" }))).toBe("register");
    expect(classifyHardenedRequest(at("/%74oken", { method: "POST" }))).toBe("token");
    expect(classifyHardenedRequest(at("/m%63p", { method: "POST" }))).toBeNull();
  });

  it("FIXED (A-3): an encoded /authorize hits 429 once the bucket is full", async () => {
    const store = fakeStore();
    const cfg = { ...HCFG, authorize: { limit: 1, windowSeconds: 300 } };
    let calls = 0;
    const handler = async () => { calls += 1; return new Response("page"); };
    expect((await enforceOAuthHardening(at("/authorize"), store, cfg, 1_000, handler)).status).toBe(200);
    expect((await enforceOAuthHardening(at("/%61uthorize"), store, cfg, 1_000, handler)).status).toBe(429);
    expect((await enforceOAuthHardening(at("/%63allback"), store, { ...cfg, callback: { limit: 0, windowSeconds: 300 } }, 1_000, handler)).status).toBe(429);
    expect(calls).toBe(1);
  });

  it("FIXED (A-3): an encoded POST /authorize is body-capped", async () => {
    let calls = 0;
    const res = await enforceOAuthHardening(
      at("/%61uthorize", { method: "POST", body: "consent_token=" + "a".repeat(MAX_FORM_BODY_BYTES) }),
      fakeStore(), HCFG, 1_000, async () => { calls += 1; return new Response("ok"); },
    );
    expect(res.status).toBe(413);
    expect(calls).toBe(0);
  });

  it("FIXED (A-3): a malformed percent-escape is refused 400 before the handler", async () => {
    let calls = 0;
    const handler = async () => { calls += 1; return new Response("ok"); };
    for (const path of ["/%61uthorize%ZZ", "/%E0%61uthorize", "/authorize%"]) {
      const res = await enforceOAuthHardening(at(path), fakeStore(), HCFG, 1_000, handler);
      expect(res.status).toBe(400);
      expect(res.headers.get("cache-control")).toBe("no-store");
    }
    expect(calls).toBe(0);
  });
});

describe("enforceOAuthHardening on /authorize and /callback (A-3)", () => {
  it("FIXED (A-3): rate limits each leg in its own bucket; passes responses through unchanged", async () => {
    const store = fakeStore();
    const cfg = { ...HCFG, authorize: { limit: 2, windowSeconds: 300 }, callback: { limit: 1, windowSeconds: 300 } };
    let calls = 0;
    const handler = async () => {
      calls += 1;
      return new Response("<html>consent</html>", {
        status: 200,
        headers: { "content-type": "text/html", "x-frame-options": "DENY" },
      });
    };
    const get = (path: string, ip = "198.51.100.4") =>
      new Request(`https://x.test${path}`, { headers: { "CF-Connecting-IP": ip } });

    const first = await enforceOAuthHardening(get("/authorize?client_id=c"), store, cfg, 1_000, handler);
    expect(first.status).toBe(200);
    expect(first.headers.get("x-frame-options")).toBe("DENY");
    expect(first.headers.get("pragma")).toBeNull(); // not rebuilt with no-store
    expect(await first.text()).toBe("<html>consent</html>");
    expect((await enforceOAuthHardening(get("/authorize"), store, cfg, 1_000, handler)).status).toBe(200);
    const blocked = await enforceOAuthHardening(get("/authorize"), store, cfg, 1_000, handler);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(calls).toBe(2);

    // /callback has its own bucket, and another IP its own budget.
    expect((await enforceOAuthHardening(get("/callback?state=s"), store, cfg, 1_000, handler)).status).toBe(200);
    expect((await enforceOAuthHardening(get("/callback?state=s"), store, cfg, 1_000, handler)).status).toBe(429);
    expect((await enforceOAuthHardening(get("/authorize", "198.51.100.5"), store, cfg, 1_000, handler)).status).toBe(200);
    expect([...store.data.keys()].sort()).toEqual([
      "ratelimit:authorize:198.51.100.4:0",
      "ratelimit:authorize:198.51.100.5:0",
      "ratelimit:callback:198.51.100.4:0",
    ]);
  });
});

// A-5 (2026-11 review): the client record now carries a KV TTL instead of a
// `clientreg:` stamp read by a five-minute sweep.
describe("refreshClientTtl (A-5)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("FIXED (A-5): re-puts the client record verbatim with the given TTL", async () => {
    const store = optsStore();
    store.data.set("client:c1", '{"clientId":"c1"}');
    expect(await refreshClientTtl(store, "c1", 777)).toBe(true);
    expect(store.data.get("client:c1")).toBe('{"clientId":"c1"}');
    expect(store.opts.get("client:c1")).toEqual({ expirationTtl: 777 });
  });

  it("is a no-op returning false for an unknown client", async () => {
    const store = optsStore();
    expect(await refreshClientTtl(store, "nope", 777)).toBe(false);
    expect(store.data.size).toBe(0);
  });

  it("swallows store errors and logs without the client id", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const broken: RateLimitStore = {
      async get() { throw new Error("kv down"); },
      async put() { throw new Error("kv down"); },
    };
    expect(await refreshClientTtl(broken, "secret-client-id", 1)).toBe(false);
    expect(err).toHaveBeenCalled();
    expect(JSON.stringify(err.mock.calls)).not.toContain("secret-client-id");
    expect(JSON.stringify(err.mock.calls)).toContain("oauth client ttl refresh failed");
  });
});

describe("enforceOAuthHardening client TTL (A-5)", () => {
  const reg = () =>
    new Request("https://x.test/register", {
      method: "POST",
      headers: { "CF-Connecting-IP": "2.2.2.2", "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://claude.ai/cb"] }),
    });
  const tok = (form: Record<string, string>, headers: Record<string, string> = {}) =>
    new Request("https://x.test/token", {
      method: "POST",
      headers: {
        "CF-Connecting-IP": "2.2.2.2",
        "content-type": "application/x-www-form-urlencoded",
        ...headers,
      },
      body: new URLSearchParams(form).toString(),
    });

  it("FIXED (A-5): a successful /register gives the new client record the unused TTL, writes no stamp, keeps the body", async () => {
    const store = optsStore();
    const handler = async () => {
      // The library writes the record with no TTL, then answers.
      await store.put("client:reg-xyz", '{"clientId":"reg-xyz"}');
      return new Response(JSON.stringify({ client_id: "reg-xyz", client_secret: "s" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    };
    const res = await enforceOAuthHardening(reg(), store, HCFG, 999, handler);
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({ client_id: "reg-xyz", client_secret: "s" });
    expect(store.opts.get("client:reg-xyz")).toEqual({ expirationTtl: TTL.registeredSeconds });
    expect([...store.data.keys()].filter((k) => k.startsWith("clientreg:"))).toEqual([]);
  });

  it("does not touch a client on a failed /register", async () => {
    const store = optsStore();
    store.data.set("client:x", "{}");
    await enforceOAuthHardening(reg(), store, HCFG, 999, async () =>
      new Response(JSON.stringify({ client_id: "x" }), { status: 400 }),
    );
    expect(store.opts.has("client:x")).toBe(false);
  });

  it("FIXED (A-5): a 200 /token renews the client to the active TTL (client_id from the form)", async () => {
    const store = optsStore();
    store.data.set("client:pub", '{"clientId":"pub"}');
    const res = await enforceOAuthHardening(
      tok({ grant_type: "refresh_token", refresh_token: "r", client_id: "pub" }),
      store, HCFG, 999, async () => new Response('{"access_token":"a"}', { status: 200 }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(store.opts.get("client:pub")).toEqual({ expirationTtl: TTL.activeSeconds });
  });

  it("FIXED (A-5): a 200 /token renews the client named in the Basic Authorization header", async () => {
    const store = optsStore();
    store.data.set("client:conf id", "{}");
    store.data.set("client:form-id", "{}");
    await enforceOAuthHardening(
      tok(
        { grant_type: "authorization_code", code: "c", client_id: "form-id" },
        { Authorization: `Basic ${btoa("conf%20id:sec%3Aret")}` },
      ),
      store, HCFG, 999, async () => new Response("{}", { status: 200 }),
    );
    expect(store.opts.get("client:conf id")).toEqual({ expirationTtl: TTL.activeSeconds });
    expect(store.opts.has("client:form-id")).toBe(false);
  });

  it("FIXED (A-5 review): a revocation 200 (token=, no grant_type) does not renew the client", async () => {
    const store = optsStore();
    store.data.set("client:pub", "{}");
    // The library answers revocation of any token, even junk, with 200.
    const res = await enforceOAuthHardening(
      tok({ client_id: "pub", token: "junk" }),
      store, HCFG, 999, async () => new Response("", { status: 200 }),
    );
    expect(res.status).toBe(200);
    expect(store.opts.has("client:pub")).toBe(false);
    // Nor does an unknown grant type that somehow answered 200.
    await enforceOAuthHardening(
      tok({ client_id: "pub", grant_type: "client_credentials" }),
      store, HCFG, 999, async () => new Response("{}", { status: 200 }),
    );
    expect(store.opts.has("client:pub")).toBe(false);
  });

  // The library only checks that Content-Type *includes*
  // application/x-www-form-urlencoded and then reads request.formData(), so a
  // multipart body with that string tacked on is parsed as multipart there
  // while URLSearchParams over the raw text sees a different form.
  const multipartToken = (parts: Array<[string, string]>) => {
    const b = "XXB";
    const body =
      parts.map(([n, v]) => `--${b}\r\nContent-Disposition: form-data; name="${n}"\r\n\r\n${v}\r\n`).join("") +
      `--${b}--\r\n`;
    return new Request("https://x.test/token", {
      method: "POST",
      headers: {
        "CF-Connecting-IP": "2.2.2.2",
        "content-type": `multipart/form-data; boundary=${b}; application/x-www-form-urlencoded`,
      },
      body,
    });
  };

  it("FIXED (A-5 review): a multipart revocation smuggling a victim's refresh form renews nobody", async () => {
    const store = optsStore();
    store.data.set("client:victim", "{}");
    store.data.set("client:attacker", "{}");
    let parsed: Record<string, unknown> = {};
    const res = await enforceOAuthHardening(
      multipartToken([
        ["z", "&client_id=victim&grant_type=refresh_token&"],
        ["client_id", "attacker"],
        ["token", "junk"],
      ]),
      store, HCFG, 999,
      async (r) => {
        // What the library sees: a revocation by `attacker`.
        parsed = Object.fromEntries((await r.formData()).entries());
        return new Response("", { status: 200 });
      },
    );
    expect(res.status).toBe(200);
    expect(parsed).toMatchObject({ client_id: "attacker", token: "junk" });
    expect(parsed.grant_type).toBeUndefined();
    expect(store.opts.has("client:victim")).toBe(false);
    expect(store.opts.has("client:attacker")).toBe(false);
  });

  it("FIXED (A-5 review): a multipart refresh renews nobody; only an exact urlencoded content type renews", async () => {
    const store = optsStore();
    store.data.set("client:pub", "{}");
    await enforceOAuthHardening(
      multipartToken([["grant_type", "refresh_token"], ["refresh_token", "r"], ["client_id", "pub"]]),
      store, HCFG, 999, async () => new Response("{}", { status: 200 }),
    );
    expect(store.opts.has("client:pub")).toBe(false);
    // Parameters on the urlencoded type are fine (essence compared).
    await enforceOAuthHardening(
      tok(
        { grant_type: "refresh_token", refresh_token: "r", client_id: "pub" },
        { "content-type": " Application/X-WWW-Form-Urlencoded ; charset=UTF-8" },
      ),
      store, HCFG, 999, async () => new Response("{}", { status: 200 }),
    );
    expect(store.opts.get("client:pub")).toEqual({ expirationTtl: TTL.activeSeconds });
  });

  it("does not renew on a failed /token", async () => {
    const store = optsStore();
    store.data.set("client:pub", "{}");
    await enforceOAuthHardening(
      tok({ grant_type: "authorization_code", code: "bad", client_id: "pub" }),
      store, HCFG, 999, async () => new Response('{"error":"invalid_grant"}', { status: 400 }),
    );
    expect(store.opts.has("client:pub")).toBe(false);
  });
});
