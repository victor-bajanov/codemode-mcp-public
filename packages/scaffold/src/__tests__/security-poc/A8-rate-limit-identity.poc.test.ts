// A8 — OAuth hardening: rate-limit identity, no-store, client-record TTL.
//
// Status: FIXED (F-14) — IPv6 clients are bucketed by /64; the "unknown"
// fallback is a documented dev-only residual (ACCEPTED). Updated for wave 5
// of the 2026-11 review: the `clientreg:` stamp and the sweep are gone (A-5;
// a 201 registration now puts a TTL on the library's own `client:<id>`
// record) and the `/authorize` and `/callback` browser legs are throttled
// too (A-3).
//
//   ACCEPTED (F-14, Informational): when CF-Connecting-IP is absent every
//       caller shares one "unknown" bucket. On Cloudflare the edge always sets
//       the header and clients cannot spoof it, so this only matters for local
//       `wrangler dev` / non-Cloudflare fronting. Fail-closed-ish (shared
//       bucket throttles everyone together) rather than fail-open.
//   FIXED (F-14, was CONFIRMED Low): the bucket was the raw IP string, so an
//       IPv6 client with a routed /64 (standard residential allocation) got
//       2^64 independent registration budgets. `clientIdentity` now buckets
//       IPv6 by /64 (IPv4-mapped addresses count as IPv4; IPv4 stays
//       per-address), so the 1-per-5-min /register clamp holds per /64.
//   REFUTED: /token and /register responses carry no-store/no-cache.
//   FIXED (A-5): a successful registration gives `client:<id>` a 30-day TTL
//       and writes no `clientreg:` stamp.
//   REFUTED: GET /register/<id> and /mcp are untouched by the limiter;
//       since A-3, /authorize is throttled (its own bucket).

import { describe, it, expect } from "vitest";
import {
  checkRateLimit,
  clientIdentity,
  enforceOAuthHardening,
} from "../../oauth-hardening";
import { readOAuthHardeningConfig } from "../../config";

function store() {
  const data = new Map<string, string>();
  const opts = new Map<string, unknown>();
  return {
    data,
    opts,
    async get(k: string) { return data.get(k) ?? null; },
    async put(k: string, v: string, o?: unknown) { data.set(k, v); if (o !== undefined) opts.set(k, o); else opts.delete(k); },
  };
}

// The shipped defaults: register 1/300 s, token 20/60 s, authorize 30/300 s,
// callback 10/300 s, client TTLs 30 d registered / 120 d active.
const CFG = readOAuthHardeningConfig({});

describe("A8 rate-limit identity", () => {
  it("ACCEPTED (F-14): missing CF-Connecting-IP collapses all callers into one 'unknown' bucket", async () => {
    const s = store();
    const r1 = new Request("https://w/register", { method: "POST" });
    const r2 = new Request("https://w/register", { method: "POST" });
    expect(clientIdentity(r1)).toBe("unknown");
    const h = async () => new Response("{}", { status: 201 });
    expect((await enforceOAuthHardening(r1, s, CFG, 0, h)).status).toBe(201);
    expect((await enforceOAuthHardening(r2, s, CFG, 0, h)).status).toBe(429);
  });

  it("FIXED (F-14): IPv6 neighbours in one /64 now share one registration budget", async () => {
    const s = store();
    const h = async () => new Response("{}", { status: 201 });
    const reg = (ip: string) =>
      enforceOAuthHardening(
        new Request("https://w/register", { method: "POST", headers: { "CF-Connecting-IP": ip } }),
        s, CFG, 0, h,
      );
    const statuses = [];
    for (const ip of ["2001:db8:abcd:1234::1", "2001:db8:abcd:1234::2", "2001:db8:abcd:1234::3"]) {
      statuses.push((await reg(ip)).status);
    }
    expect(statuses).toEqual([201, 429, 429]);
    expect(clientIdentity(new Request("https://w/", { headers: { "CF-Connecting-IP": "2001:db8:abcd:1234::3" } })))
      .toBe("ip6:2001:db8:abcd:1234::/64");
    // A different /64 still has its own budget.
    expect((await reg("2001:db8:abcd:1235::1")).status).toBe(201);
    // Same single IPv4 address: the clamp works, unchanged.
    const now = 0;
    const d = await checkRateLimit(s, { endpoint: "register", client: "198.51.100.1" }, CFG.register, now);
    const e = await checkRateLimit(s, { endpoint: "register", client: "198.51.100.1" }, CFG.register, now);
    expect([d.allowed, e.allowed]).toEqual([true, false]);
    // IPv4-mapped IPv6 shares the IPv4 address's bucket.
    expect((await reg("::ffff:198.51.100.1")).status).toBe(429);
  });

  it("FIXED (A-5): hardened responses get no-store; a 201 registration puts a 30-day TTL on client:<id> and writes no clientreg: stamp", async () => {
    const s = store();
    const req = new Request("https://w/register", { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.5" } });
    const res = await enforceOAuthHardening(req, s, CFG, 123_000, async () => {
      // The library writes the record with no TTL, then answers 201.
      await s.put("client:abc", JSON.stringify({ clientId: "abc" }));
      return new Response(JSON.stringify({ client_id: "abc" }), { status: 201, headers: { "content-type": "application/json" } });
    });
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");
    expect([...s.data.keys()].filter((k) => k.startsWith("clientreg:"))).toEqual([]);
    expect(s.data.get("client:abc")).toBe(JSON.stringify({ clientId: "abc" }));
    expect(s.opts.get("client:abc")).toEqual({ expirationTtl: 30 * 86_400 });
    const tok = await enforceOAuthHardening(
      new Request("https://w/token", { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.5" } }),
      s, CFG, 123_000, async () => new Response("{}", { status: 200 }),
    );
    expect(tok.headers.get("cache-control")).toBe("no-store");
  });

  it("REFUTED: GET /register/<id> and /mcp are untouched by the limiter; /authorize is throttled since A-3", async () => {
    const s = store();
    for (const url of ["https://w/register/abc", "https://w/mcp"]) {
      for (let i = 0; i < 3; i++) {
        const res = await enforceOAuthHardening(new Request(url), s, CFG, 0, async () => new Response("ok"));
        expect(res.status).toBe(200);
      }
    }
    expect(s.data.size).toBe(0);
    // The browser leg has its own bucket now.
    const page = await enforceOAuthHardening(new Request("https://w/authorize"), s, CFG, 0, async () => new Response("ok"));
    expect(page.status).toBe(200);
    expect([...s.data.keys()]).toEqual(["ratelimit:authorize:unknown:0"]);
  });
});
