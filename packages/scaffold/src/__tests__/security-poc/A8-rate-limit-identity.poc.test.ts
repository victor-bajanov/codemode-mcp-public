// A8 — OAuth hardening: rate-limit identity, no-store, registration stamp.
//
// Status: FIXED (F-14) — IPv6 clients are bucketed by /64; the "unknown"
// fallback is a documented dev-only residual (ACCEPTED).
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
//   REFUTED: /token and /register responses carry no-store/no-cache; a
//       successful registration is stamped for the sweep.

import { describe, it, expect } from "vitest";
import {
  checkRateLimit,
  clientIdentity,
  enforceOAuthHardening,
  CLIENT_STAMP_PREFIX,
} from "../../oauth-hardening";

function store() {
  const data = new Map<string, string>();
  return {
    data,
    async get(k: string) { return data.get(k) ?? null; },
    async put(k: string, v: string) { data.set(k, v); },
  };
}

const CFG = { register: { limit: 1, windowSeconds: 300 }, token: { limit: 20, windowSeconds: 60 } };

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

  it("REFUTED: hardened responses get no-store, and a 201 registration is stamped for the sweep", async () => {
    const s = store();
    const req = new Request("https://w/register", { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.5" } });
    const res = await enforceOAuthHardening(req, s, CFG, 123_000, async () =>
      new Response(JSON.stringify({ client_id: "abc" }), { status: 201, headers: { "content-type": "application/json" } }),
    );
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");
    expect(s.data.get(`${CLIENT_STAMP_PREFIX}abc`)).toBe(JSON.stringify({ registeredAt: 123_000 }));
    const tok = await enforceOAuthHardening(
      new Request("https://w/token", { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.5" } }),
      s, CFG, 123_000, async () => new Response("{}", { status: 200 }),
    );
    expect(tok.headers.get("cache-control")).toBe("no-store");
  });

  it("REFUTED: only POST /register and POST /token are throttled — GET /register/<id> and /mcp are untouched", async () => {
    const s = store();
    for (const url of ["https://w/register/abc", "https://w/mcp", "https://w/authorize"]) {
      for (let i = 0; i < 3; i++) {
        const res = await enforceOAuthHardening(new Request(url), s, CFG, 0, async () => new Response("ok"));
        expect(res.status).toBe(200);
      }
    }
    expect(s.data.size).toBe(0);
  });
});
