import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createTokenBrokerDO, type TokenBrokerArgs } from "../token-broker";
import type { ApiProvider } from "../api-provider";
import { decryptSlot, encryptSlot } from "../encrypt-slot";
import { hashRefreshToken, type GrantSlot } from "../refresh";

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

const staticProvider = {
  ...provider,
  name: "google",
  displayName: "Google",
  tokenRotation: "static",
} as unknown as ApiProvider<Record<string, unknown>, never>;

const REAUTH_ERROR = /^Upstream connection needs re-authorisation: /;
const SLOT_TTL_SECONDS = 180 * 24 * 60 * 60;

/** Per-grant KV slot key: `token-slot:<userId>:<sha256(originalRefreshToken)>`. */
async function slotKey(userId: string, refreshToken: string): Promise<string> {
  return `token-slot:${userId}:${await hashRefreshToken(refreshToken)}`;
}

function makeKV() {
  const data = new Map<string, string>();
  return {
    data,
    get: vi.fn(async (key: string, opts?: { type?: "json" | "text" }) => {
      const v = data.get(key);
      if (v === undefined) return null;
      return opts?.type === "json" ? JSON.parse(v) : v;
    }),
    put: vi.fn(async (key: string, value: string) => { data.set(key, value); }),
    delete: vi.fn(async (key: string) => { data.delete(key); }),
  } as unknown as KVNamespace & { data: Map<string, string> };
}

function makeFetchSpy(
  responses: Array<{ access_token: string; expires_in: number; refresh_token?: string }>,
) {
  let i = 0;
  return vi.fn<typeof fetch>(async () => {
    const r = responses[i++];
    if (!r) throw new Error("fetch called more times than responses array length");
    return new Response(JSON.stringify(r), { status: 200, headers: { "content-type": "application/json" } });
  });
}

/** Models a rotating IdP: every refresh invalidates the presented token and
 *  issues `<chain>.r<n>`; presenting a spent token yields 400 invalid_grant. */
function makeRotatingUpstream(initiallyValid: string[]) {
  const valid = new Set(initiallyValid);
  const bodies: string[] = [];
  let n = 0;
  const spy = vi.fn<typeof fetch>(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const body = String(init?.body);
    bodies.push(body);
    const rt = new URLSearchParams(body).get("refresh_token")!;
    if (!valid.has(rt)) {
      return new Response(JSON.stringify({ error: "invalid_grant" }), {
        status: 400, headers: { "content-type": "application/json" },
      });
    }
    valid.delete(rt);
    n += 1;
    const next = `${rt.split(".")[0]}.r${n}`;
    valid.add(next);
    return new Response(
      JSON.stringify({ access_token: `AT-${n}`, expires_in: 1800, refresh_token: next }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  });
  return { spy, valid, bodies };
}

function makeBroker(
  env: { OAUTH_KV: KVNamespace; XERO_CLIENT_ID: string; XERO_CLIENT_SECRET: string },
  p: ApiProvider<Record<string, unknown>, never> = provider,
) {
  const TokenBrokerDO = createTokenBrokerDO(p);
  // We don't instantiate the DO via the runtime; we test the method as a
  // plain class. The runtime wires `this.env` from the namespace at construct
  // time — we supply it directly.
  const instance = new TokenBrokerDO({} as DurableObjectState, env as never);
  return instance;
}

describe("TokenBrokerDO.getOrRefreshAccessToken", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-19T00:00:00Z"));
  });

  it("seeds a fresh user from props.refreshToken on first call", async () => {
    const kv = makeKV();
    const fetchSpy = makeFetchSpy([{ access_token: "AT-1", expires_in: 1800, refresh_token: "RT-1" }]);
    vi.stubGlobal("fetch", fetchSpy);

    const broker = makeBroker({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });
    const args: TokenBrokerArgs = { userId: "user-A", refreshToken: "RT-seed" };

    const tok = await broker.getOrRefreshAccessToken(args);
    expect(tok).toBe("AT-1");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect([...kv.data.keys()]).toEqual([await slotKey("user-A", "RT-seed")]);
    expect(kv.put).toHaveBeenCalledWith(
      await slotKey("user-A", "RT-seed"),
      expect.any(String),
      { expirationTtl: SLOT_TTL_SECONDS },
    );
  });

  it("persists the rotated refresh token across simulated session restart (broker instance is replaced)", async () => {
    const kv = makeKV();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-1", expires_in: 60, refresh_token: "RT-1" },
      { access_token: "AT-2", expires_in: 1800, refresh_token: "RT-2" },
    ]);
    vi.stubGlobal("fetch", fetchSpy);

    const env = { OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" };
    const args: TokenBrokerArgs = { userId: "user-A", refreshToken: "RT-seed" };

    const broker1 = makeBroker(env);
    await broker1.getOrRefreshAccessToken(args);          // seeds RT-seed → RT-1 cached
    vi.setSystemTime(new Date("2026-05-19T00:00:45Z"));   // inside skew

    // Brand-new broker instance — simulates new MCP session / new caller DO.
    const broker2 = makeBroker(env);
    const tok2 = await broker2.getOrRefreshAccessToken(args);

    expect(tok2).toBe("AT-2");
    // Second upstream call must use the rotated RT-1, NOT the stale RT-seed.
    const secondBody = String((fetchSpy.mock.calls[1]![1]! as RequestInit).body);
    expect(secondBody).toContain("RT-1");
    expect(secondBody).not.toContain("RT-seed");

    // KV must now contain the rotated refresh token, otherwise a third
    // broker instance would replay the stale RT-1 from KV and re-trigger
    // the original bug.
    const sealedRaw = kv.data.get(await slotKey("user-A", "RT-seed"))!;
    const sealed = JSON.parse(sealedRaw);
    const decoded = await decryptSlot<GrantSlot>("RT-seed", sealed);
    expect(decoded?.currentRefreshToken).toBe("RT-2");
  });

  it("reseeds when props.refreshToken changes (user re-authenticated)", async () => {
    const kv = makeKV();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-old", expires_in: 60, refresh_token: "RT-old-1" },
      { access_token: "AT-new", expires_in: 1800, refresh_token: "RT-new-1" },
    ]);
    vi.stubGlobal("fetch", fetchSpy);

    const env = { OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" };
    const broker = makeBroker(env);

    await broker.getOrRefreshAccessToken({ userId: "user-A", refreshToken: "RT-OLD-SEED" });

    // User re-auths: props.refreshToken changes, so the grant's slot key
    // changes too → no slot under the new key → refreshes upstream with the
    // new seed.
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z"));
    const tok = await broker.getOrRefreshAccessToken({ userId: "user-A", refreshToken: "RT-NEW-SEED" });

    expect(tok).toBe("AT-new");
    const secondBody = String((fetchSpy.mock.calls[1]![1]! as RequestInit).body);
    expect(secondBody).toContain("RT-NEW-SEED");
    expect(kv.data.has(await slotKey("user-A", "RT-NEW-SEED"))).toBe(true);
  });

  it("distinct userIds get distinct KV keys", async () => {
    const kv = makeKV();
    vi.stubGlobal("fetch", makeFetchSpy([
      { access_token: "AT-A", expires_in: 1800 },
      { access_token: "AT-B", expires_in: 1800 },
    ]));
    const env = { OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" };
    const broker = makeBroker(env);
    await broker.getOrRefreshAccessToken({ userId: "user-A", refreshToken: "RT-A" });
    await broker.getOrRefreshAccessToken({ userId: "user-B", refreshToken: "RT-B" });
    expect(kv.data.has(await slotKey("user-A", "RT-A"))).toBe(true);
    expect(kv.data.has(await slotKey("user-B", "RT-B"))).toBe(true);
  });
});

describe("TokenBrokerDO per-grant slots (F-5)", () => {
  const env = (kv: KVNamespace) => ({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-19T00:00:00Z"));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("two grants of one userId on a rotating provider keep separate slots across several rotations", async () => {
    const kv = makeKV();
    const up = makeRotatingUpstream(["RT_A", "RT_B"]);
    vi.stubGlobal("fetch", up.spy);
    const grantA: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    const grantB: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_B" };

    for (let hour = 0; hour < 4; hour++) {
      vi.setSystemTime(new Date(Date.UTC(2026, 4, 19, hour))); // access tokens expire hourly
      const broker = makeBroker(env(kv)); // fresh DO instance each round (eviction)
      await expect(broker.getOrRefreshAccessToken(grantA)).resolves.toMatch(/^AT-\d+$/);
      await expect(broker.getOrRefreshAccessToken(grantB)).resolves.toMatch(/^AT-\d+$/);
    }

    expect(up.spy).toHaveBeenCalledTimes(8);
    expect([...kv.data.keys()].sort()).toEqual(
      [await slotKey("user-1", "RT_A"), await slotKey("user-1", "RT_B")].sort(),
    );
    // Each slot is sealed under its own grant's token and holds that chain's
    // live successor.
    const slotA = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(await slotKey("user-1", "RT_A"))!));
    const slotB = await decryptSlot<GrantSlot>("RT_B", JSON.parse(kv.data.get(await slotKey("user-1", "RT_B"))!));
    expect(up.valid.has(slotA!.currentRefreshToken)).toBe(true);
    expect(up.valid.has(slotB!.currentRefreshToken)).toBe(true);
    expect(slotA!.currentRefreshToken).toMatch(/^RT_A\.r\d+$/);
    expect(slotB!.currentRefreshToken).toMatch(/^RT_B\.r\d+$/);
  });

  it("adopts a legacy slot sealed under the calling grant, rewrites it under the per-grant key and deletes the legacy key", async () => {
    const kv = makeKV();
    const legacy: GrantSlot = {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r7",
      lastUsedAt: Date.now() - 3_600_000,
    };
    kv.data.set("token-slot:user-1", JSON.stringify(await encryptSlot("RT_A", legacy)));
    const up = makeRotatingUpstream(["RT_A.r7"]);
    vi.stubGlobal("fetch", up.spy);

    const tok = await makeBroker(env(kv)).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" });

    expect(tok).toBe("AT-1");
    expect(up.bodies).toHaveLength(1);
    // The upstream saw the legacy slot's rotated token, not the original.
    expect(new URLSearchParams(up.bodies[0]!).get("refresh_token")).toBe("RT_A.r7");
    const key = await slotKey("user-1", "RT_A");
    expect([...kv.data.keys()]).toEqual([key]);
    expect(kv.put).toHaveBeenCalledWith(key, expect.any(String), { expirationTtl: SLOT_TTL_SECONDS });
    expect(kv.delete).toHaveBeenCalledWith("token-slot:user-1");
    const migrated = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(key)!));
    expect(migrated?.currentRefreshToken).toBe("RT_A.r1");
  });

  it("migrates a legacy slot even on a cache hit (no rotation, still rewritten once)", async () => {
    const kv = makeKV();
    const legacy: GrantSlot = {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r2",
      accessToken: "AT-cached",
      accessExpiresAt: Date.now() + 1_800_000,
      lastUsedAt: Date.now(),
    };
    kv.data.set("token-slot:user-1", JSON.stringify(await encryptSlot("RT_A", legacy)));
    const up = makeRotatingUpstream([]);
    vi.stubGlobal("fetch", up.spy);

    const tok = await makeBroker(env(kv)).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" });

    expect(tok).toBe("AT-cached");
    expect(up.spy).not.toHaveBeenCalled();
    const key = await slotKey("user-1", "RT_A");
    expect([...kv.data.keys()]).toEqual([key]);
    const migrated = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(key)!));
    expect(migrated?.currentRefreshToken).toBe("RT_A.r2");
  });

  it("leaves a legacy slot sealed under another grant in place and seeds from the caller's own token", async () => {
    const kv = makeKV();
    const legacyRaw = JSON.stringify(await encryptSlot("RT_A", {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r3",
      lastUsedAt: Date.now(),
    } satisfies GrantSlot));
    kv.data.set("token-slot:user-1", legacyRaw);
    const up = makeRotatingUpstream(["RT_B"]);
    vi.stubGlobal("fetch", up.spy);

    const tok = await makeBroker(env(kv)).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_B" });

    expect(tok).toBe("AT-1");
    expect(new URLSearchParams(up.bodies[0]!).get("refresh_token")).toBe("RT_B");
    expect(kv.data.get("token-slot:user-1")).toBe(legacyRaw); // untouched, for grant A to migrate
    expect(kv.delete).not.toHaveBeenCalled();
    expect(kv.data.has(await slotKey("user-1", "RT_B"))).toBe(true);
  });

  it("a corrupt per-grant slot on a rotating provider throws the re-authorisation error without calling upstream", async () => {
    const kv = makeKV();
    const key = await slotKey("user-1", "RT_A");
    // Sealed under a different token: decrypts to `undefined`, like corruption.
    const corrupt = JSON.stringify(await encryptSlot("SOMETHING-ELSE", { currentRefreshToken: "x" }));
    kv.data.set(key, corrupt);
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);

    await expect(
      makeBroker(env(kv)).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" }),
    ).rejects.toThrow(REAUTH_ERROR);
    expect(up.spy).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();
    expect(kv.data.get(key)).toBe(corrupt);
  });

  it("a corrupt per-grant slot on a static provider is a cache miss and reseeds", async () => {
    const kv = makeKV();
    const key = await slotKey("user-1", "RT_G");
    kv.data.set(key, JSON.stringify({ encryptedData: "AAAA", wrappedKey: "AAAA" }));
    const fetchSpy = makeFetchSpy([{ access_token: "AT-static", expires_in: 3600 }]);
    vi.stubGlobal("fetch", fetchSpy);

    const tok = await makeBroker(env(kv), staticProvider)
      .getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_G" });

    expect(tok).toBe("AT-static");
    expect(String((fetchSpy.mock.calls[0]![1]! as RequestInit).body)).toContain("refresh_token=RT_G");
    const reseeded = await decryptSlot<GrantSlot>("RT_G", JSON.parse(kv.data.get(key)!));
    expect(reseeded?.currentRefreshToken).toBe("RT_G");
    expect(reseeded?.accessToken).toBe("AT-static");
  });
});
