// A3 — TokenBroker slot was keyed by userId only; two live grants for one user
// on a rotating provider (Xero/Optical) clobbered each other.
//
// Status: FIXED (F-5) — slots are per grant (`token-slot:<userId>:<sha256(RT)>`),
// legacy `token-slot:<userId>` slots migrate to their owning grant on first use.
//
// Scenario (realistic: one person uses Claude.ai AND Claude Code, which are two
// distinct dynamically-registered MCP clients, each with its own grant and its
// own upstream refresh token RT_A / RT_B for the same upstream `sub`). Before
// the fix:
//   1. Grant A called the broker → seeded the slot from RT_A, rotated to
//      RT_A.r1, slot sealed under RT_A, written to `token-slot:<userId>`.
//   2. Grant B called the broker → could not decrypt (sealed under RT_A) →
//      treated it as a cache miss → seeded from RT_B → rotated → OVERWROTE the
//      single slot, now sealed under RT_B. RT_A.r1 (chain A's only live token)
//      was lost.
//   3. Grant A called again → could not decrypt → "reseeded from the original
//      props token" RT_A, which the upstream had already rotated and revoked
//      → 400 invalid_grant on every call until a fresh upstream re-auth, which
//      in turn killed grant B.
// Now each grant reads and writes only its own slot, so both chains survive
// (test 1). A pre-fix slot sealed under the calling grant is adopted, rewritten
// under the per-grant key and the legacy key deleted (test 2). A per-grant slot
// that cannot be decrypted on a rotating provider now raises a fixed
// re-authorisation error instead of replaying the spent original token.
//
// Also checked here:
//   - a single grant chain survives indefinitely (control).
//   - a KV dump of the slot reveals no tokens (control).
// (The old test 1 also noted that the `Refresh failed` text carried the
// upstream body but not the refresh token; the fixed scenario no longer
// fails, and the refresh error text itself is F-21.)

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createTokenBrokerDO, type TokenBrokerArgs } from "../../token-broker";
import type { ApiProvider } from "../../api-provider";
import { encryptSlot, decryptSlot } from "../../encrypt-slot";
import { hashRefreshToken, type GrantSlot } from "../../refresh";

const provider = {
  name: "xero",
  displayName: "Xero",
  oauth: {
    authorizeUrl: "https://x/authorize",
    tokenUrl: "https://identity.example.com/connect/token",
    scopes: ["offline_access"],
    clientIdSecretName: "XERO_CLIENT_ID",
    clientSecretSecretName: "XERO_CLIENT_SECRET",
  },
  spec: {} as never,
  surfaceReview: {} as never,
  apiBaseUrl: "https://api.x",
  tokenRotation: "rotating",
} as unknown as ApiProvider<Record<string, unknown>, never>;

function makeKV() {
  const data = new Map<string, string>();
  return {
    data,
    get: async (key: string, opts?: { type?: "json" | "text" }) => {
      const v = data.get(key);
      if (v === undefined) return null;
      return opts?.type === "json" ? JSON.parse(v) : v;
    },
    put: async (key: string, value: string) => { data.set(key, value); },
    delete: async (key: string) => { data.delete(key); },
  } as unknown as KVNamespace & { data: Map<string, string> };
}

/** Models a rotating IdP: every refresh invalidates the presented token. */
function makeRotatingUpstream(initiallyValid: string[]) {
  const valid = new Set(initiallyValid);
  const revoked = new Set<string>();
  let n = 0;
  const bodies: string[] = [];
  const spy = vi.fn<typeof fetch>(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const body = String(init?.body);
    bodies.push(body);
    const rt = new URLSearchParams(body).get("refresh_token")!;
    if (!valid.has(rt)) {
      return new Response(
        JSON.stringify({ error: "invalid_grant", error_description: "refresh token revoked" }),
        { status: 400, headers: { "content-type": "application/json" } },
      );
    }
    valid.delete(rt);
    revoked.add(rt);
    n += 1;
    const next = `${rt.split(".")[0]}.r${n}`;
    valid.add(next);
    return new Response(
      JSON.stringify({ access_token: `AT-${n}`, expires_in: 1800, refresh_token: next }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  });
  vi.stubGlobal("fetch", spy);
  return { spy, valid, revoked, bodies };
}

function makeBroker(kv: KVNamespace) {
  const TokenBrokerDO = createTokenBrokerDO(provider);
  return new TokenBrokerDO({} as DurableObjectState, {
    OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec",
  } as never);
}

describe("A3 broker slots across grants of one userId", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-07T00:00:00Z"));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("FIXED (F-5): two grants keep separate slots; the first grant still refreshes with its rotated token", async () => {
    const kv = makeKV();
    const up = makeRotatingUpstream(["RT_A", "RT_B"]);
    const broker = makeBroker(kv);
    const grantA: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    const grantB: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_B" };

    // 1. Grant A seeds and rotates RT_A → RT_A.r1
    expect(await broker.getOrRefreshAccessToken(grantA)).toBe("AT-1");
    expect(up.revoked.has("RT_A")).toBe(true);
    expect(up.valid.has("RT_A.r1")).toBe(true);

    // 2. Grant B seeds from RT_B into its OWN slot; A's slot is untouched.
    expect(await broker.getOrRefreshAccessToken(grantB)).toBe("AT-2");
    const keys = [...kv.data.keys()];
    expect(keys).toHaveLength(2);
    for (const k of keys) expect(k).toMatch(/^token-slot:user-1:[0-9a-f]{64}$/);
    expect(kv.data.has("token-slot:user-1")).toBe(false);

    // 3. Grant A again after expiry: decrypts its own slot and presents the
    //    live successor RT_A.r1, not the revoked original.
    vi.setSystemTime(new Date("2026-10-07T01:00:00Z"));
    expect(await broker.getOrRefreshAccessToken(grantA)).toBe("AT-3");
    expect(up.bodies.at(-1)).toContain("refresh_token=RT_A.r1");

    // Grant B still works too.
    vi.setSystemTime(new Date("2026-10-07T02:00:00Z"));
    expect(await broker.getOrRefreshAccessToken(grantB)).toBe("AT-4");
    expect(up.bodies.at(-1)).toContain("refresh_token=RT_B.r2");
  });

  it("FIXED (F-5): a legacy per-user slot sealed under the calling grant is adopted and migrated", async () => {
    const kv = makeKV();
    const up = makeRotatingUpstream(["RT_A.r1"]);
    kv.data.set("token-slot:user-1", JSON.stringify(await encryptSlot("RT_A", {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r1",
      lastUsedAt: Date.now() - 3_600_000,
    } satisfies GrantSlot)));

    expect(await makeBroker(kv).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" })).toBe("AT-1");
    expect(up.bodies).toHaveLength(1);
    expect(up.bodies[0]).toContain("refresh_token=RT_A.r1"); // the slot's live token, not RT_A

    const newKey = `token-slot:user-1:${await hashRefreshToken("RT_A")}`;
    expect([...kv.data.keys()]).toEqual([newKey]); // legacy key deleted
    const slot = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(newKey)!));
    // The migrated slot holds the successor the upstream just issued.
    expect(up.revoked.has("RT_A.r1")).toBe(true);
    expect(up.valid.has(slot!.currentRefreshToken)).toBe(true);
  });

  it("REFUTED (control): a single grant chain survives arbitrarily many rotations across broker instances", async () => {
    const kv = makeKV();
    makeRotatingUpstream(["RT_A"]);
    const grantA: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    for (let i = 1; i <= 5; i++) {
      vi.setSystemTime(new Date(2026, 9, 7, i)); // hourly → refresh each time
      const b = makeBroker(kv); // fresh DO instance each time (eviction)
      expect(await b.getOrRefreshAccessToken(grantA)).toBe(`AT-${i}`);
    }
  });

  it("REFUTED (control): a KV dump of the slot does not reveal tokens without the wrapping refresh token", async () => {
    const kv = makeKV();
    makeRotatingUpstream(["RT_A"]);
    await makeBroker(kv).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" });
    const raw = kv.data.get(`token-slot:user-1:${await hashRefreshToken("RT_A")}`)!;
    expect(raw).not.toContain("RT_A");
    expect(raw).not.toContain("AT-1");
    expect(JSON.parse(raw)).toEqual({ encryptedData: expect.any(String), wrappedKey: expect.any(String) });
  });
});
