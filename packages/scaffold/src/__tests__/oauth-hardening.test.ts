import { describe, it, expect } from "vitest";
import {
  checkRateLimit,
  classifyHardenedRequest,
  clientIdentity,
  withNoStore,
  tooManyRequestsResponse,
  enforceOAuthHardening,
  stampClientRegistration,
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
