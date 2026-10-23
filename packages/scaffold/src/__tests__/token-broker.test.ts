import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createTokenBrokerDO, type TokenBrokerArgs, type TokenBrokerDeadlines } from "../token-broker";
import type { ApiProvider } from "../api-provider";
import { decryptSlot, encryptSlot } from "../encrypt-slot";

/** Lets a test make the broker's slot sealing fail; otherwise passes through. */
const sealing = vi.hoisted(() => ({ fail: false }));
vi.mock("../encrypt-slot", async (importOriginal) => {
  const real = await importOriginal<typeof import("../encrypt-slot")>();
  return {
    ...real,
    encryptSlot: vi.fn(async (...a: Parameters<typeof real.encryptSlot>) => {
      if (sealing.fail) throw new Error("seal failed");
      return real.encryptSlot(...a);
    }),
  };
});
import { hashRefreshToken, REFRESH_HARD_CAP_MS, RefreshFailedError, type GrantSlot } from "../refresh";
import { seedGrantSlot } from "../grant-slot";
import { makeDoState, makeDoStorage, type FakeDoStorage } from "./fake-do-state";

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
 *  issues `<chain>.r<n>`; presenting a spent token yields 400 invalid_grant.
 *  `issued` is how many tokens the IdP has already handed out, so the next
 *  one is `.r<issued + 1>`. */
function makeRotatingUpstream(initiallyValid: string[], issued = 0) {
  const valid = new Set(initiallyValid);
  const bodies: string[] = [];
  let n = issued;
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
  storage: FakeDoStorage = makeDoStorage(),
  deadlines?: TokenBrokerDeadlines,
) {
  const TokenBrokerDO = createTokenBrokerDO(p, deadlines);
  // We don't instantiate the DO via the runtime; we test the method as a
  // plain class. The runtime wires `this.ctx` and `this.env` at construct
  // time — we supply them directly. Passing the same `storage` to a second
  // broker models the DO being evicted and re-created: its Durable Object
  // storage survives, its memory doesn't.
  const instance = new TokenBrokerDO(makeDoState(storage), env as never);
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

/** A promise released by hand, so a fake upstream can hold every in-flight
 *  refresh open until the test has issued all its concurrent calls. */
function deferred() {
  let release!: () => void;
  const promise = new Promise<void>((r) => { release = r; });
  return { promise, release };
}

/** WebCrypto resolves on the libuv threadpool, so no fixed number of event-loop
 *  turns is sure to cover it: on a loaded CI runner it takes longer. Every
 *  `crypto.subtle` call here is held for `CRYPTO_LAG_TURNS` real turns (more
 *  than settle()'s quiet window) to model that, and counted while pending. */
const CRYPTO_LAG_TURNS = 60;
const realSetImmediate = setImmediate;
let cryptoPending = 0;
for (const name of ["digest", "importKey", "sign", "generateKey", "encrypt", "decrypt", "wrapKey", "unwrapKey"] as const) {
  const real = (crypto.subtle[name] as (...a: unknown[]) => Promise<unknown>).bind(crypto.subtle);
  Object.defineProperty(crypto.subtle, name, {
    configurable: true,
    value: async (...a: unknown[]) => {
      cryptoPending++;
      try {
        for (let i = 0; i < CRYPTO_LAG_TURNS; i++) await new Promise((r) => realSetImmediate(r));
        return await real(...a);
      } finally {
        cryptoPending--;
      }
    },
  });
}

/** Let every issued call run as far as it can: until no WebCrypto call is
 *  pending and 50 event-loop turns have passed since the last one settled.
 *  WebCrypto runs off the JS thread, so a fixed turn count isn't enough. */
async function settle(): Promise<void> {
  for (let quiet = 0; quiet < 50; ) {
    await new Promise((r) => realSetImmediate(r));
    quiet = cryptoPending === 0 ? quiet + 1 : 0;
  }
}

/** Wrap `inner` so each request waits on `gate` before the upstream answers. */
function gatedFetch(inner: typeof fetch, gate: Promise<void>) {
  return vi.fn<typeof fetch>(async (url, init) => {
    await gate;
    return inner(url, init);
  });
}

describe("TokenBrokerDO single-flight", () => {
  const env = (kv: KVNamespace) => ({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });

  beforeEach(() => {
    // Only Date is faked: the settle() helper needs the real setImmediate.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-05-19T00:00:00Z"));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it("ten concurrent calls on one grant share a single upstream refresh", async () => {
    const kv = makeKV();
    const up = makeRotatingUpstream(["RT_A"]);
    const gate = deferred();
    const fetchSpy = gatedFetch(up.spy, gate.promise);
    vi.stubGlobal("fetch", fetchSpy);
    const broker = makeBroker(env(kv));
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    const calls = Array.from({ length: 10 }, () => broker.getOrRefreshAccessToken(args));
    await settle();
    gate.release();
    const results = await Promise.allSettled(calls);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(results.map((r) => r.status)).toEqual(Array(10).fill("fulfilled"));
    expect(new Set(results.map((r) => (r as PromiseFulfilledResult<string>).value))).toEqual(new Set(["AT-1"]));
    const slot = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(await slotKey("user-1", "RT_A"))!));
    expect(slot?.currentRefreshToken).toBe("RT_A.r1");
  });

  it("a failed refresh rejects every waiter once, and the next call retries", async () => {
    const kv = makeKV();
    const up = makeRotatingUpstream([]); // every token is already spent
    const gate = deferred();
    const fetchSpy = gatedFetch(up.spy, gate.promise);
    vi.stubGlobal("fetch", fetchSpy);
    const broker = makeBroker(env(kv));
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    const calls = Array.from({ length: 10 }, () => broker.getOrRefreshAccessToken(args));
    await settle();
    gate.release();
    const results = await Promise.allSettled(calls);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    for (const r of results) {
      expect(r.status).toBe("rejected");
      expect((r as PromiseRejectedResult).reason).toEqual(new RefreshFailedError(400, "invalid_grant"));
    }

    // The failed flight was cleared, not cached: a new call tries again.
    await expect(broker.getOrRefreshAccessToken(args)).rejects.toThrow("Refresh failed 400 (invalid_grant)");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("uses the rotated refresh token from DO storage when KV still serves the pre-rotation slot", async () => {
    const kv = makeKV();
    const key = await slotKey("user-1", "RT_A");
    const preRotation = JSON.stringify(await encryptSlot("RT_A", {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A",
      lastUsedAt: Date.now(),
    } satisfies GrantSlot));
    kv.data.set(key, preRotation);
    // KV read-after-write lag: reads keep returning the pre-rotation slot.
    (kv.get as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (k: string) =>
      k === key ? JSON.parse(preRotation) : null);
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);
    const broker = makeBroker(env(kv));
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z")); // AT-1 has expired

    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(up.bodies.map((b) => new URLSearchParams(b).get("refresh_token"))).toEqual(["RT_A", "RT_A.r1"]);
  });

  it("a KV write failure after a rotation still serves the token; the rotated chain lives in DO storage", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    const put = kv.put as unknown as ReturnType<typeof vi.fn>;
    put.mockImplementation(async () => { throw new Error("KV put failed: RT_A.r1 AT-1"); });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);
    const broker = makeBroker(env(kv), provider, storage);
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    // The rotation succeeds upstream and is recorded in storage; only the KV
    // copy fails. The token is valid, so the call gets it, and one line is
    // logged with no token material and no error object.
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    expect(kv.data.has(key)).toBe(false);
    expect(errors.mock.calls).toEqual([["Xero token slot KV write failed"]]);

    // A cache hit is served from storage and doesn't retry the KV write: KV
    // is only a copy, never read while storage holds the grant.
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    expect(put).toHaveBeenCalledTimes(1);

    // After an eviction the new instance refreshes with the rotated token.
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z"));
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(up.bodies.map((b) => new URLSearchParams(b).get("refresh_token"))).toEqual(["RT_A", "RT_A.r1"]);
  });

  it("every waiter of a flight whose KV write fails gets the token", async () => {
    const kv = makeKV();
    (kv.put as unknown as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      throw new Error("KV put failed");
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    const up = makeRotatingUpstream(["RT_A"]);
    const gate = deferred();
    const fetchSpy = gatedFetch(up.spy, gate.promise);
    vi.stubGlobal("fetch", fetchSpy);
    const broker = makeBroker(env(kv));
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    const calls = Array.from({ length: 5 }, () => broker.getOrRefreshAccessToken(args));
    await settle();
    gate.release();

    await expect(Promise.all(calls)).resolves.toEqual(Array(5).fill("AT-1"));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("a sealing failure after a rotation fails the call: no token is returned whose chain wasn't recorded", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);
    const broker = makeBroker(env(kv), provider, storage);
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    sealing.fail = true;
    let err: unknown;
    try {
      err = await broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    } finally {
      sealing.fail = false;
    }
    expect(err).toEqual(new Error("Upstream token could not be saved. Retry the call; if it keeps failing, reconnect this MCP server."));
    expect(storage.put).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();
    expect(errors.mock.calls).toEqual([["Xero token slot seal failed"]]);
  });

  it("a DO storage write failure after a rotation fails the call, but the KV mirror already holds the rotated chain, so the next call recovers it", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    // Storage holds the grant at RT_A.r1, its access token expired.
    storage.data.set(key, {
      sealed: await encryptSlot("RT_A", {
        seedKey: await hashRefreshToken("RT_A"),
        currentRefreshToken: "RT_A.r1",
        accessToken: "AT-old",
        accessExpiresAt: Date.now() - 60_000,
        lastUsedAt: Date.now() - 3_600_000,
      } satisfies GrantSlot),
      writtenAt: Date.now() - 3_600_000,
    });
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    vi.stubGlobal("fetch", up.spy);
    vi.spyOn(console, "warn").mockImplementation(() => {});

    // The upstream rotates RT_A.r1 → RT_A.r2, then the storage write fails:
    // the call fails, but the rotated chain was mirrored to KV first.
    storage.put.mockImplementationOnce(async () => { throw new Error("storage unavailable"); });
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).rejects.toThrow("storage unavailable");
    expect((await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(key)!)))?.currentRefreshToken).toBe("RT_A.r2");

    // Storage still says RT_A.r1, which the upstream has spent. The next
    // call is rejected, recovers RT_A.r2 from KV, and is served AT-2 (still
    // valid) without another refresh.
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(up.bodies.map((b) => new URLSearchParams(b).get("refresh_token"))).toEqual(["RT_A.r1", "RT_A.r1"]);
    const stored = storage.data.get(key) as { sealed: Parameters<typeof decryptSlot>[1] };
    expect((await decryptSlot<GrantSlot>("RT_A", stored.sealed))?.currentRefreshToken).toBe("RT_A.r2");
  });

  it("a failed legacy-key delete after a migration is best effort and logged as a delete failure", async () => {
    const kv = makeKV();
    const legacy: GrantSlot = {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r7",
      lastUsedAt: Date.now() - 3_600_000,
    };
    kv.data.set("token-slot:user-1", JSON.stringify(await encryptSlot("RT_A", legacy)));
    (kv.delete as unknown as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      throw new Error("KV delete failed");
    });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const up = makeRotatingUpstream(["RT_A.r7"]);
    vi.stubGlobal("fetch", up.spy);

    const tok = await makeBroker(env(kv)).getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" });

    expect(tok).toBe("AT-1");
    expect(errors.mock.calls).toEqual([["Xero legacy token slot delete failed"]]);
    // The per-grant copy was written before the delete was attempted.
    const migrated = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(await slotKey("user-1", "RT_A"))!));
    expect(migrated?.currentRefreshToken).toBe("RT_A.r1");
  });

  it("a migration deletes the legacy key even when the per-grant KV write fails, and isn't retried after", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    kv.data.set("token-slot:user-1", JSON.stringify(await encryptSlot("RT_A", {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r7",
      lastUsedAt: Date.now() - 3_600_000,
    } satisfies GrantSlot)));
    (kv.put as unknown as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      throw new Error("KV put failed");
    });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const up = makeRotatingUpstream(["RT_A.r7"]);
    vi.stubGlobal("fetch", up.spy);
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    // Storage holds the adopted chain, so the legacy slot has nothing left to
    // give this grant: it is deleted regardless of the KV copy.
    expect(kv.data.has("token-slot:user-1")).toBe(false);
    expect(errors.mock.calls).toEqual([["Xero token slot KV write failed"]]);

    // A new instance reads storage and never looks at KV for this grant again.
    (kv.get as unknown as ReturnType<typeof vi.fn>).mockClear();
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z"));
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(kv.get).not.toHaveBeenCalled();
    expect(up.bodies.map((b) => new URLSearchParams(b).get("refresh_token"))).toEqual(["RT_A.r7", "RT_A.r1"]);
  });

  it("a static provider's refresh is aborted at 30 s: the timeout reaches every waiter and clears the flight, so the next call refreshes again", async () => {
    const kv = makeKV();
    // The 30 s deadline, under the test's control.
    const deadlines: AbortController[] = [];
    const deadlineMs: number[] = [];
    vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) => {
      const c = new AbortController();
      deadlines.push(c);
      deadlineMs.push(ms);
      return c.signal;
    });
    const hanging = vi.fn<typeof fetch>((_input, init) => new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal;
      signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
    }));
    vi.stubGlobal("fetch", hanging);
    const broker = makeBroker(env(kv), staticProvider);
    const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

    const calls = Array.from({ length: 5 }, () => broker.getOrRefreshAccessToken(args));
    await settle();
    expect(hanging).toHaveBeenCalledTimes(1);
    expect(deadlineMs).toEqual([30_000]);
    deadlines[0]!.abort(new DOMException("The operation timed out.", "TimeoutError"));
    const results = await Promise.allSettled(calls);
    for (const r of results) {
      expect(r.status).toBe("rejected");
      expect((r as PromiseRejectedResult).reason).toEqual(new Error("Refresh timed out after 30000 ms"));
    }

    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    expect(up.spy).toHaveBeenCalledTimes(1);
  });

  it("concurrent calls for two grants of one user refresh once per grant, without cross-talk", async () => {
    const kv = makeKV();
    const up = makeRotatingUpstream(["RT_A", "RT_B"]);
    const gate = deferred();
    const fetchSpy = gatedFetch(up.spy, gate.promise);
    vi.stubGlobal("fetch", fetchSpy);
    const broker = makeBroker(env(kv));
    const grantA: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    const grantB: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_B" };

    const callsA = Array.from({ length: 5 }, () => broker.getOrRefreshAccessToken(grantA));
    const callsB = Array.from({ length: 5 }, () => broker.getOrRefreshAccessToken(grantB));
    await settle();
    gate.release();
    const tokensA = await Promise.all(callsA);
    const tokensB = await Promise.all(callsB);

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(new Set(tokensA).size).toBe(1);
    expect(new Set(tokensB).size).toBe(1);
    expect(tokensA[0]).not.toBe(tokensB[0]);
    const slotA = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(await slotKey("user-1", "RT_A"))!));
    const slotB = await decryptSlot<GrantSlot>("RT_B", JSON.parse(kv.data.get(await slotKey("user-1", "RT_B"))!));
    expect(slotA?.currentRefreshToken).toMatch(/^RT_A\.r\d+$/);
    expect(slotB?.currentRefreshToken).toMatch(/^RT_B\.r\d+$/);
    expect(slotA?.accessToken).toBe(tokensA[0]);
    expect(slotB?.accessToken).toBe(tokensB[0]);
  });
});

interface StoredSlotRecord {
  sealed: { encryptedData: string; wrappedKey: string };
  writtenAt: number;
}

describe("TokenBrokerDO durable slot (Durable Object storage)", () => {
  const env = (kv: KVNamespace) => ({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });
  const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-05-19T00:00:00Z"));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  /** KV whose reads of `key` keep returning `stale` (KV's colo cache after a
   *  write): the broker primed it with the pre-rotation value. */
  async function staleKv(key: string) {
    const kv = makeKV();
    const preRotation = JSON.stringify(await encryptSlot("RT_A", {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A",
      lastUsedAt: Date.now(),
    } satisfies GrantSlot));
    kv.data.set(key, preRotation);
    (kv.get as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (k: string) =>
      k === key ? JSON.parse(preRotation) : null);
    return kv;
  }

  it("after an eviction, the new instance refreshes with the rotated token although KV still serves the pre-rotation slot", async () => {
    const key = await slotKey("user-1", "RT_A");
    const kv = await staleKv(key);
    const storage = makeDoStorage();
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z")); // AT-1 has expired

    // The DO was evicted: a fresh instance, same Durable Object storage.
    const evicted = makeBroker(env(kv), provider, storage);
    await expect(evicted.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(up.bodies.map((b) => new URLSearchParams(b).get("refresh_token"))).toEqual(["RT_A", "RT_A.r1"]);
  });

  it("stores the slot sealed under the grant's original token: the raw storage value holds no token", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A"]).spy);

    await makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args);

    const key = await slotKey("user-1", "RT_A");
    expect([...storage.data.keys()]).toEqual([key]);
    const raw = storage.data.get(key) as StoredSlotRecord;
    const dump = JSON.stringify(raw);
    for (const secret of ["RT_A", "RT_A.r1", "AT-1"]) expect(dump).not.toContain(secret);
    expect(raw.writtenAt).toBe(Date.now());
    const slot = await decryptSlot<GrantSlot>("RT_A", raw.sealed);
    expect(slot).toMatchObject({ currentRefreshToken: "RT_A.r1", accessToken: "AT-1" });
  });

  it("writes the KV copy before DO storage, so a failed storage write can't lose a rotated chain", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A"]).spy);

    await makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args);

    const storagePut = storage.put.mock.invocationCallOrder[0]!;
    const kvPut = (kv.put as unknown as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
    expect(kvPut).toBeLessThan(storagePut);
  });

  it("a cache hit reads storage only: no KV read and no write", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);
    await makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args);
    (kv.get as unknown as ReturnType<typeof vi.fn>).mockClear();
    (kv.put as unknown as ReturnType<typeof vi.fn>).mockClear();
    storage.put.mockClear();

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
    expect(kv.get).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();
    expect(storage.put).not.toHaveBeenCalled();
    expect(up.spy).toHaveBeenCalledTimes(1);
  });

  it("adopts the sign-in seed from KV into storage on a storage miss", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    await seedGrantSlot(kv, {
      userId: "user-1", refreshToken: "RT_A", accessToken: "AT-seed", expiresIn: 1800, now: Date.now(),
    });
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-seed");
    expect(up.spy).not.toHaveBeenCalled();
    const raw = storage.data.get(await slotKey("user-1", "RT_A")) as StoredSlotRecord;
    expect(await decryptSlot<GrantSlot>("RT_A", raw.sealed)).toMatchObject({
      currentRefreshToken: "RT_A", accessToken: "AT-seed",
    });

    // From now on storage is the authority: losing the KV copy changes nothing.
    kv.data.clear();
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-seed");
    expect(up.spy).not.toHaveBeenCalled();
  });

  it("a static provider's refreshed access token survives an eviction (no second refresh)", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-g1", expires_in: 3600 },
      { access_token: "AT-g2", expires_in: 3600 },
    ]);
    vi.stubGlobal("fetch", fetchSpy);
    const g: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_G" };

    await expect(makeBroker(env(kv), staticProvider, storage).getOrRefreshAccessToken(g)).resolves.toBe("AT-g1");
    vi.setSystemTime(new Date("2026-05-19T02:00:00Z"));
    await expect(makeBroker(env(kv), staticProvider, storage).getOrRefreshAccessToken(g)).resolves.toBe("AT-g2");
    vi.setSystemTime(new Date("2026-05-19T02:01:00Z"));
    await expect(makeBroker(env(kv), staticProvider, storage).getOrRefreshAccessToken(g)).resolves.toBe("AT-g2");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("a corrupt storage slot on a rotating provider asks for re-authorisation without calling upstream or KV", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    storage.data.set(key, { sealed: await encryptSlot("SOMETHING-ELSE", { x: 1 }), writtenAt: Date.now() });
    const up = makeRotatingUpstream(["RT_A"]);
    vi.stubGlobal("fetch", up.spy);

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).rejects.toThrow(REAUTH_ERROR);
    expect(up.spy).not.toHaveBeenCalled();
    expect(kv.get).not.toHaveBeenCalled();
  });

  it("a corrupt storage slot on a static provider reseeds and overwrites it", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_G");
    storage.data.set(key, { sealed: { encryptedData: "AAAA", wrappedKey: "AAAA" }, writtenAt: Date.now() });
    vi.stubGlobal("fetch", makeFetchSpy([{ access_token: "AT-static", expires_in: 3600 }]));

    await expect(makeBroker(env(kv), staticProvider, storage)
      .getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_G" })).resolves.toBe("AT-static");
    const raw = storage.data.get(key) as StoredSlotRecord;
    expect(await decryptSlot<GrantSlot>("RT_G", raw.sealed)).toMatchObject({ accessToken: "AT-static" });
  });
});

describe("TokenBrokerDO storage pruning", () => {
  const env = (kv: KVNamespace) => ({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });
  const DAY = 24 * 60 * 60 * 1000;
  const T0 = Date.UTC(2026, 4, 19);
  const TTL_MS = SLOT_TTL_SECONDS * 1000;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(T0);
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it("the first slot write arms an alarm one slot TTL out; later writes leave the earlier alarm", async () => {
    const storage = makeDoStorage();
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A", "RT_B"]).spy);
    const broker = makeBroker(env(makeKV()), provider, storage);

    await broker.getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" });
    expect(storage.alarmAt).toBe(T0 + TTL_MS);
    vi.setSystemTime(T0 + 10 * DAY);
    await broker.getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_B" });
    expect(storage.alarmAt).toBe(T0 + TTL_MS);
  });

  it("the alarm deletes slots not written for a slot TTL and re-arms for the oldest survivor", async () => {
    const storage = makeDoStorage();
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A", "RT_B"]).spy);
    const broker = makeBroker(env(makeKV()), provider, storage);
    await broker.getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_A" });
    vi.setSystemTime(T0 + 100 * DAY);
    await broker.getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_B" });

    vi.setSystemTime(T0 + TTL_MS);
    await broker.alarm();

    expect([...storage.data.keys()]).toEqual([await slotKey("user-1", "RT_B")]);
    expect(storage.alarmAt).toBe(T0 + 100 * DAY + TTL_MS);

    vi.setSystemTime(T0 + 100 * DAY + TTL_MS);
    storage.setAlarm.mockClear();
    await broker.alarm();
    expect(storage.data.size).toBe(0);
    expect(storage.setAlarm).not.toHaveBeenCalled();
  });

  it("the alarm deletes more than 128 expired slots in batches the runtime accepts", async () => {
    const storage = makeDoStorage();
    const sealed = { encryptedData: "AAAA", wrappedKey: "AAAA" };
    vi.setSystemTime(T0 + TTL_MS + DAY);
    for (let i = 0; i < 300; i++) {
      storage.data.set(`token-slot:user-1:expired-${String(i).padStart(3, "0")}`, { sealed, writtenAt: T0 });
    }
    const fresh = "token-slot:user-1:fresh";
    storage.data.set(fresh, { sealed, writtenAt: Date.now() });
    const broker = makeBroker(env(makeKV()), provider, storage);

    await broker.alarm();

    expect([...storage.data.keys()]).toEqual([fresh]);
    for (const [keys] of storage.delete.mock.calls) {
      expect((keys as string[]).length).toBeLessThanOrEqual(128);
    }
    expect(storage.alarmAt).toBe(Date.now() + TTL_MS);
  });

  it("a refresh that starts between delete batches keeps its slot: each batch re-checks the flights", async () => {
    const storage = makeDoStorage();
    const junk = { encryptedData: "AAAA", wrappedKey: "AAAA" };
    // "0-…" sorts before any hex digest, so the grant's own slot is listed
    // last, in the final batch.
    for (let i = 0; i < 300; i++) {
      storage.data.set(`token-slot:user-1:0-expired-${String(i).padStart(3, "0")}`, { sealed: junk, writtenAt: T0 });
    }
    const a: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    const key = await slotKey("user-1", "RT_A");
    storage.data.set(key, {
      sealed: await encryptSlot("RT_A", {
        seedKey: await hashRefreshToken("RT_A"), currentRefreshToken: "RT_A.r1", lastUsedAt: T0,
      } satisfies GrantSlot),
      writtenAt: T0,
    });
    vi.setSystemTime(T0 + TTL_MS + DAY);
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    const gate = deferred();
    vi.stubGlobal("fetch", gatedFetch(up.spy, gate.promise));
    const broker = makeBroker(env(makeKV()), provider, storage);

    // The grant's refresh starts while the first batch is being deleted.
    let call: Promise<string> | undefined;
    const realDelete = storage.delete.getMockImplementation()!;
    storage.delete.mockImplementationOnce(async (keys: string | string[]) => {
      const n = await realDelete(keys);
      call = broker.getOrRefreshAccessToken(a);
      await settle();
      return n;
    });
    await broker.alarm();

    expect([...storage.data.keys()]).toEqual([key]);
    expect(storage.alarmAt).toBe(Date.now() + 60_000);
    gate.release();
    await expect(call).resolves.toBe("AT-2");
    expect(new URLSearchParams(up.bodies[0]!).get("refresh_token")).toBe("RT_A.r1");
  });

  it("the alarm leaves a grant whose refresh is in flight, and retries the prune later", async () => {
    const storage = makeDoStorage();
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A"]).spy);
    const broker = makeBroker(env(makeKV()), provider, storage);
    const a: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
    await broker.getOrRefreshAccessToken(a);
    const key = await slotKey("user-1", "RT_A");

    // A slot TTL later, the grant is used again while the alarm fires.
    vi.setSystemTime(T0 + TTL_MS + 1);
    const up = makeRotatingUpstream(["RT_A.r1"]);
    const gate = deferred();
    vi.stubGlobal("fetch", gatedFetch(up.spy, gate.promise));
    const call = broker.getOrRefreshAccessToken(a);
    await settle();
    await broker.alarm();
    expect(storage.data.has(key)).toBe(true);
    expect(storage.alarmAt).toBeGreaterThan(Date.now());

    gate.release();
    await expect(call).resolves.toBe("AT-1");
    const raw = storage.data.get(key) as StoredSlotRecord;
    expect(raw.writtenAt).toBe(T0 + TTL_MS + 1);
    expect(new URLSearchParams(up.bodies[0]!).get("refresh_token")).toBe("RT_A.r1");
    const slot = await decryptSlot<GrantSlot>("RT_A", raw.sealed);
    expect(up.valid.has(slot!.currentRefreshToken)).toBe(true);
  });
});

/** A rollback to a KV-only broker rotates a grant's chain in KV only, so on
 *  redeploy DO storage holds a refresh token the upstream has spent. After the
 *  upstream rejects it with `invalid_grant`, the flight reads the grant's KV
 *  slot once and, if it holds a different token, retries with it once. */
describe("TokenBrokerDO rollback recovery", () => {
  const env = (kv: KVNamespace) => ({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });
  const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
  const INVALID_GRANT = "Refresh failed 400 (invalid_grant)";
  const RECOVERED_LOG = "Xero token slot recovered from KV";

  beforeEach(() => {
    // Only Date is faked: the settle() helper needs the real setImmediate.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-05-19T00:00:00Z"));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  /** A slot on chain `currentRefreshToken`, sealed later under `seed`. The
   *  access token expired a minute ago unless `liveAccessToken` is given. */
  async function slot(seed: string, currentRefreshToken: string, liveAccessToken?: string): Promise<GrantSlot> {
    return {
      seedKey: await hashRefreshToken(seed),
      currentRefreshToken,
      accessToken: liveAccessToken ?? "AT-old",
      accessExpiresAt: liveAccessToken ? Date.now() + 1_800_000 : Date.now() - 60_000,
      lastUsedAt: Date.now() - 3_600_000,
    };
  }

  async function seedStorage(storage: FakeDoStorage, key: string, seal: string, s: GrantSlot) {
    storage.data.set(key, { sealed: await encryptSlot(seal, s), writtenAt: Date.now() - 3_600_000 });
  }

  async function seedKv(kv: KVNamespace & { data: Map<string, string> }, key: string, seal: string, s: unknown) {
    kv.data.set(key, JSON.stringify(await encryptSlot(seal, s)));
  }

  async function storedSlot(storage: FakeDoStorage, key: string, seal = "RT_A") {
    return decryptSlot<GrantSlot>(seal, (storage.data.get(key) as StoredSlotRecord).sealed);
  }

  async function kvSlot(kv: KVNamespace & { data: Map<string, string> }, key: string, seal = "RT_A") {
    return decryptSlot<GrantSlot>(seal, JSON.parse(kv.data.get(key)!));
  }

  function kvGets(kv: KVNamespace, key?: string): number {
    const calls = (kv.get as unknown as ReturnType<typeof vi.fn>).mock.calls;
    return key === undefined ? calls.length : calls.filter((c) => c[0] === key).length;
  }

  function presented(bodies: string[]): Array<string | null> {
    return bodies.map((b) => new URLSearchParams(b).get("refresh_token"));
  }

  /** Every console line, for asserting no token material was logged. */
  function captureLogs() {
    return {
      warn: vi.spyOn(console, "warn").mockImplementation(() => {}),
      error: vi.spyOn(console, "error").mockImplementation(() => {}),
      log: vi.spyOn(console, "log").mockImplementation(() => {}),
    };
  }

  /** Storage stranded at `RT_A.r1`; KV holds the chain a rolled-back broker
   *  rotated on to `RT_A.r3`, which is the upstream's only live token. */
  async function stranded(opts: { kvLiveAccessToken?: string } = {}) {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A", await slot("RT_A", "RT_A.r1"));
    await seedKv(kv, key, "RT_A", await slot("RT_A", "RT_A.r3", opts.kvLiveAccessToken));
    const up = makeRotatingUpstream(["RT_A.r3"], 3);
    return { kv, storage, key, up };
  }

  it("recovers a rollback-stranded grant: the spent storage token is rejected, the KV chain is adopted and rotated", async () => {
    const { kv, storage, key, up } = await stranded();
    vi.stubGlobal("fetch", up.spy);
    const logs = captureLogs();

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-4");

    expect(presented(up.bodies)).toEqual(["RT_A.r1", "RT_A.r3"]);
    expect((await storedSlot(storage, key))?.currentRefreshToken).toBe("RT_A.r4");
    expect((await kvSlot(kv, key))?.currentRefreshToken).toBe("RT_A.r4");
    expect(logs.warn.mock.calls).toEqual([[RECOVERED_LOG]]);
    expect(logs.error).not.toHaveBeenCalled();
    const logged = JSON.stringify([logs.warn.mock.calls, logs.error.mock.calls, logs.log.mock.calls]);
    for (const secret of ["RT_A", "AT-"]) expect(logged).not.toContain(secret);

    // Storage now holds the live chain: the next refresh needs no recovery.
    (kv.get as unknown as ReturnType<typeof vi.fn>).mockClear();
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z"));
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-5");
    expect(presented(up.bodies)).toEqual(["RT_A.r1", "RT_A.r3", "RT_A.r4"]);
    expect(kv.get).not.toHaveBeenCalled();
    expect(logs.warn).toHaveBeenCalledTimes(1);
  });

  it("a recovered KV slot with a live access token is served without a second POST and adopted into storage", async () => {
    const { kv, storage, key, up } = await stranded({ kvLiveAccessToken: "AT-kv" });
    vi.stubGlobal("fetch", up.spy);
    captureLogs();

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-kv");

    expect(presented(up.bodies)).toEqual(["RT_A.r1"]);
    expect(await storedSlot(storage, key)).toMatchObject({ currentRefreshToken: "RT_A.r3", accessToken: "AT-kv" });
    expect(kv.put).not.toHaveBeenCalled(); // the chain didn't change: KV already holds it
  });

  it("KV holding the same spent token rethrows the original invalid_grant after one POST and writes nothing", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A", await slot("RT_A", "RT_A.r1"));
    await seedKv(kv, key, "RT_A", await slot("RT_A", "RT_A.r1"));
    const before = structuredClone(storage.data.get(key));
    const up = makeRotatingUpstream([]);
    vi.stubGlobal("fetch", up.spy);
    const logs = captureLogs();

    const err = await makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(RefreshFailedError);
    expect((err as Error).message).toBe(INVALID_GRANT);
    expect(up.spy).toHaveBeenCalledTimes(1);
    expect(kvGets(kv)).toBe(1);
    expect(kvGets(kv, key)).toBe(1);
    expect(storage.put).not.toHaveBeenCalled();
    expect(storage.data.get(key)).toEqual(before);
    expect(kv.put).not.toHaveBeenCalled();
    expect(logs.warn).not.toHaveBeenCalled();
  });

  it("a newer KV token the upstream also rejects is tried once, with no loop, and nothing is written", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A", await slot("RT_A", "RT_A.r1"));
    await seedKv(kv, key, "RT_A", await slot("RT_A", "RT_A.r2"));
    const kvBefore = kv.data.get(key);
    const up = makeRotatingUpstream([]);
    vi.stubGlobal("fetch", up.spy);
    captureLogs();

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).rejects.toThrow(INVALID_GRANT);

    expect(presented(up.bodies)).toEqual(["RT_A.r1", "RT_A.r2"]);
    expect(kvGets(kv)).toBe(1);
    expect(storage.put).not.toHaveBeenCalled();
    expect((await storedSlot(storage, key))?.currentRefreshToken).toBe("RT_A.r1");
    expect(kv.put).not.toHaveBeenCalled();
    expect(kv.data.get(key)).toBe(kvBefore);
  });

  it("no KV slot, a KV slot that doesn't decrypt under the grant, or one with no refresh token, rethrows the original invalid_grant", async () => {
    for (const kvContent of ["absent", "undecryptable", "no refresh token"] as const) {
      const kv = makeKV();
      const storage = makeDoStorage();
      const key = await slotKey("user-1", "RT_A");
      await seedStorage(storage, key, "RT_A", await slot("RT_A", "RT_A.r1"));
      if (kvContent === "undecryptable") {
        await seedKv(kv, key, "SOMETHING-ELSE", await slot("RT_A", "RT_A.r3"));
      } else if (kvContent === "no refresh token") {
        await seedKv(kv, key, "RT_A", { seedKey: await hashRefreshToken("RT_A"), lastUsedAt: Date.now() });
      }
      const up = makeRotatingUpstream(["RT_A.r3"], 3);
      vi.stubGlobal("fetch", up.spy);
      const logs = captureLogs();

      const err = await makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args).catch((e: unknown) => e);

      expect(err, kvContent).toBeInstanceOf(RefreshFailedError);
      expect((err as Error).message, kvContent).toBe(INVALID_GRANT);
      expect(presented(up.bodies), kvContent).toEqual(["RT_A.r1"]);
      expect(kvGets(kv, key), kvContent).toBe(1);
      expect(storage.put, kvContent).not.toHaveBeenCalled();
      expect(kv.put, kvContent).not.toHaveBeenCalled();
      expect(logs.warn, kvContent).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  it("a KV read that throws during recovery rethrows the original invalid_grant, not the KV error", async () => {
    const { kv, storage, key, up } = await stranded();
    (kv.get as unknown as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      throw new Error("KV get failed");
    });
    vi.stubGlobal("fetch", up.spy);
    const logs = captureLogs();

    const err = await makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(RefreshFailedError);
    expect((err as Error).message).toBe(INVALID_GRANT);
    expect(presented(up.bodies)).toEqual(["RT_A.r1"]);
    expect(kvGets(kv, key)).toBe(1);
    expect(storage.put).not.toHaveBeenCalled();
    expect(logs.warn).not.toHaveBeenCalled();
  });

  it("ten concurrent waiters share one recovery: one KV read, two POSTs, one token", async () => {
    const { kv, storage, key, up } = await stranded();
    const gate = deferred();
    const fetchSpy = gatedFetch(up.spy, gate.promise);
    vi.stubGlobal("fetch", fetchSpy);
    const logs = captureLogs();
    const broker = makeBroker(env(kv), provider, storage);

    const calls = Array.from({ length: 10 }, () => broker.getOrRefreshAccessToken(args));
    await settle();
    gate.release();

    await expect(Promise.all(calls)).resolves.toEqual(Array(10).fill("AT-4"));
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(kvGets(kv, key)).toBe(1);
    expect(kvGets(kv, "token-slot:user-1")).toBe(0);
    expect(kvGets(kv)).toBe(1);
    expect(logs.warn).toHaveBeenCalledTimes(1);
    expect((await storedSlot(storage, key))?.currentRefreshToken).toBe("RT_A.r4");
  });

  it("recovery reads only the calling grant's KV slot: another grant's live chain is never presented or touched", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const keyA = await slotKey("user-1", "RT_A");
    const keyB = await slotKey("user-1", "RT_B");
    // Grant A (say, a disconnected client) has a live chain in KV; grant B's
    // own chain is spent and its KV slot is gone.
    await seedStorage(storage, keyA, "RT_A", await slot("RT_A", "RT_A.r1"));
    await seedKv(kv, keyA, "RT_A", await slot("RT_A", "RT_A.r3"));
    await seedStorage(storage, keyB, "RT_B", await slot("RT_B", "RT_B.r1"));
    const storageA = structuredClone(storage.data.get(keyA));
    const kvA = kv.data.get(keyA);
    const up = makeRotatingUpstream(["RT_A.r3"], 3);
    vi.stubGlobal("fetch", up.spy);
    captureLogs();
    const grantB: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_B" };

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(grantB)).rejects.toThrow(INVALID_GRANT);
    expect(presented(up.bodies)).toEqual(["RT_B.r1"]);
    expect(kvGets(kv, keyA)).toBe(0);
    expect(storage.data.get(keyA)).toEqual(storageA);
    expect(kv.data.get(keyA)).toBe(kvA);
    expect(storage.put).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();

    // Even a copy of A's live chain under B's key is useless to B: it is
    // sealed under RT_A, so B can't decrypt it and never presents it.
    kv.data.set(keyB, kvA!);
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(grantB)).rejects.toThrow(INVALID_GRANT);
    expect(presented(up.bodies)).toEqual(["RT_B.r1", "RT_B.r1"]);
    expect(up.valid.has("RT_A.r3")).toBe(true);
    expect(storage.put).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("only invalid_grant triggers recovery: a 5xx, another OAuth code and the hard-cap timeout each fail after one POST with no KV read", async () => {
    const cases: Array<{ name: string; fetch: () => typeof fetch; abort?: boolean; error: string }> = [
      { name: "500", fetch: () => vi.fn<typeof fetch>(async () => new Response("down", { status: 500 })), error: "Refresh failed 500" },
      {
        name: "invalid_client",
        fetch: () => vi.fn<typeof fetch>(async () => new Response(JSON.stringify({ error: "invalid_client" }), { status: 400 })),
        error: "Refresh failed 400 (invalid_client)",
      },
      {
        name: "timeout",
        fetch: () => vi.fn<typeof fetch>((_input, init) => new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;
          signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
        })),
        abort: true,
        // A rotating refresh is aborted only at the hard cap.
        error: `Refresh timed out after ${REFRESH_HARD_CAP_MS} ms`,
      },
    ];
    for (const c of cases) {
      const { kv, storage } = await stranded();
      const deadlines: AbortController[] = [];
      vi.spyOn(AbortSignal, "timeout").mockImplementation(() => {
        const ctl = new AbortController();
        deadlines.push(ctl);
        return ctl.signal;
      });
      const fetchSpy = c.fetch();
      vi.stubGlobal("fetch", fetchSpy);
      const logs = captureLogs();

      const call = makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args).catch((e: unknown) => e);
      if (c.abort) {
        await settle();
        deadlines[0]!.abort(new DOMException("The operation timed out.", "TimeoutError"));
      }
      const err = await call;

      expect((err as Error).message, c.name).toBe(c.error);
      expect(fetchSpy, c.name).toHaveBeenCalledTimes(1);
      expect(kvGets(kv), c.name).toBe(0);
      expect(storage.put, c.name).not.toHaveBeenCalled();
      expect(logs.warn, c.name).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    }
  });

  it("a successful refresh of a storage slot reads no KV", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A", await slot("RT_A", "RT_A.r1"));
    await seedKv(kv, key, "RT_A", await slot("RT_A", "RT_A.r3"));
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    vi.stubGlobal("fetch", up.spy);

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(presented(up.bodies)).toEqual(["RT_A.r1"]);
    expect(kv.get).not.toHaveBeenCalled();
  });

  it("a slot read from KV (storage miss) that the upstream rejects is not re-read: one KV read, one POST", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedKv(kv, key, "RT_A", await slot("RT_A", "RT_A.r1"));
    const up = makeRotatingUpstream([]);
    vi.stubGlobal("fetch", up.spy);
    const logs = captureLogs();

    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args)).rejects.toThrow(INVALID_GRANT);
    expect(up.spy).toHaveBeenCalledTimes(1);
    expect(kvGets(kv, key)).toBe(1);
    expect(kvGets(kv)).toBe(1);
    expect(logs.warn).not.toHaveBeenCalled();
  });

  it("a static provider never recovers: invalid_grant fails after one POST with no KV read", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_G");
    await seedStorage(storage, key, "RT_G", await slot("RT_G", "RT_G"));
    await seedKv(kv, key, "RT_G", await slot("RT_G", "RT_G.other"));
    const fetchSpy = vi.fn<typeof fetch>(async () =>
      new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }));
    vi.stubGlobal("fetch", fetchSpy);
    const logs = captureLogs();

    await expect(makeBroker(env(kv), staticProvider, storage)
      .getOrRefreshAccessToken({ userId: "user-1", refreshToken: "RT_G" })).rejects.toThrow(INVALID_GRANT);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(kv.get).not.toHaveBeenCalled();
    expect(logs.warn).not.toHaveBeenCalled();
  });
});

/** A rotating provider's refresh token is single-use, so aborting a refresh
 *  POST the upstream has already committed loses the new chain. Callers stop
 *  waiting at the 30 s soft deadline, but the POST and the persist keep
 *  running, registered as the grant's flight, until they settle or reach the
 *  hard cap. */
describe("TokenBrokerDO soft deadline (rotating providers)", () => {
  const env = (kv: KVNamespace) => ({ OAUTH_KV: kv, XERO_CLIENT_ID: "cid", XERO_CLIENT_SECRET: "csec" });
  const args: TokenBrokerArgs = { userId: "user-1", refreshToken: "RT_A" };
  const SOFT_TIMEOUT = "Refresh timed out after 30000 ms";
  const T0 = Date.UTC(2026, 4, 19);

  beforeEach(() => {
    // setTimeout is faked so the test drives both deadlines; settle() needs
    // the real setImmediate.
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    vi.setSystemTime(T0);
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  /** `AbortSignal.timeout` on the fake clock. Returns each deadline's ms. */
  function fakeAbortDeadlines(): number[] {
    const made: number[] = [];
    vi.spyOn(AbortSignal, "timeout").mockImplementation((ms: number) => {
      made.push(ms);
      const c = new AbortController();
      setTimeout(() => c.abort(new DOMException("The operation timed out.", "TimeoutError")), ms);
      return c.signal;
    });
    return made;
  }

  /** The first `held` requests reach `inner` (so the upstream commits) only
   *  once released, and reject as soon as their signal aborts; the rest pass
   *  straight through. A request aborted before release still reaches the
   *  upstream on release, as a request already on the wire would. */
  function heldFetch(inner: typeof fetch, held = 1) {
    const gate = deferred();
    let n = 0;
    const spy = vi.fn<typeof fetch>((url, init) => {
      if (n++ >= held) return inner(url, init);
      return new Promise<Response>((resolve, reject) => {
        const signal = init?.signal;
        signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
        void gate.promise.then(() => inner(url, init)).then(resolve, reject);
      });
    });
    return { spy, release: gate.release };
  }

  async function seedStorage(storage: FakeDoStorage, key: string, currentRefreshToken: string, writtenAt = T0) {
    storage.data.set(key, {
      sealed: await encryptSlot("RT_A", {
        seedKey: await hashRefreshToken("RT_A"),
        currentRefreshToken,
        accessToken: "AT-old",
        accessExpiresAt: writtenAt - 60_000,
        lastUsedAt: writtenAt,
      } satisfies GrantSlot),
      writtenAt,
    });
  }

  async function storedChain(storage: FakeDoStorage, key: string) {
    return (await decryptSlot<GrantSlot>("RT_A", (storage.data.get(key) as StoredSlotRecord).sealed))?.currentRefreshToken;
  }

  function presented(bodies: string[]): Array<string | null> {
    return bodies.map((b) => new URLSearchParams(b).get("refresh_token"));
  }

  it("a caller that reaches the soft deadline leaves the refresh running; a call in the late window joins it, and the late result is saved and served", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    const held = heldFetch(up.spy);
    vi.stubGlobal("fetch", held.spy);
    const abortMs = fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));
    expect(storage.put).not.toHaveBeenCalled();

    // The late window: the POST is still on the wire. A new call joins it
    // instead of presenting the token the upstream is about to spend.
    await vi.advanceTimersByTimeAsync(10_000);
    const second = broker.getOrRefreshAccessToken(args);
    await settle();
    expect(held.spy).toHaveBeenCalledTimes(1);

    held.release();
    await expect(second).resolves.toBe("AT-2");
    expect(presented(up.bodies)).toEqual(["RT_A.r1"]);
    expect(kv.get).not.toHaveBeenCalled();
    expect(await storedChain(storage, key)).toBe("RT_A.r2");
    const kvCopy = await decryptSlot<GrantSlot>("RT_A", JSON.parse(kv.data.get(key)!));
    expect(kvCopy?.currentRefreshToken).toBe("RT_A.r2");

    // Served from the saved slot: no further POST.
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(held.spy).toHaveBeenCalledTimes(1);
    // The POST was never aborted at 30 s: its only deadline is the hard cap.
    expect(abortMs).toEqual([REFRESH_HARD_CAP_MS]);
  });

  it("a late success with no caller left waiting is still saved, and the next call is served from it", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    const held = heldFetch(up.spy);
    vi.stubGlobal("fetch", held.spy);
    fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));

    held.release();
    await settle();
    expect(await storedChain(storage, key)).toBe("RT_A.r2");
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(held.spy).toHaveBeenCalledTimes(1);
    expect(up.valid.has("RT_A.r2")).toBe(true);
  });

  it("a late failure settles the flight for whoever joined it, writes nothing, and the next call refreshes normally", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    let failNext = true;
    const flaky = vi.fn<typeof fetch>(async (u, init) => {
      if (failNext) { failNext = false; return new Response("down", { status: 500 }); }
      return up.spy(u, init);
    });
    const held = heldFetch(flaky);
    vi.stubGlobal("fetch", held.spy);
    fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));
    const joined = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    expect(held.spy).toHaveBeenCalledTimes(1);

    held.release();
    expect(await joined).toEqual(new RefreshFailedError(500, undefined));
    expect(storage.put).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();

    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(presented(up.bodies)).toEqual(["RT_A.r1"]);
  });

  it("a late failure after every caller has given up raises no unhandled rejection, writes nothing, and the next call refreshes normally", async () => {
    const unhandled: unknown[] = [];
    const trap = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", trap);
    try {
      const kv = makeKV();
      const storage = makeDoStorage();
      const key = await slotKey("user-1", "RT_A");
      await seedStorage(storage, key, "RT_A.r1");
      const up = makeRotatingUpstream(["RT_A.r1"], 1);
      const held = heldFetch(vi.fn<typeof fetch>(async () => new Response("down", { status: 500 })));
      vi.stubGlobal("fetch", held.spy);
      fakeAbortDeadlines();
      const broker = makeBroker(env(kv), provider, storage);

      const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
      await settle();
      await vi.advanceTimersByTimeAsync(30_000);
      expect(await first).toEqual(new Error(SOFT_TIMEOUT));

      // The flight fails with nobody waiting on it.
      held.release();
      await settle();
      expect(unhandled).toEqual([]);
      expect(storage.put).not.toHaveBeenCalled();
      expect(kv.put).not.toHaveBeenCalled();

      vi.stubGlobal("fetch", up.spy);
      await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
      expect(presented(up.bodies)).toEqual(["RT_A.r1"]);
    } finally {
      process.off("unhandledRejection", trap);
    }
  });

  it("a call's soft-deadline timer is cleared when its flight settles first", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    // AbortSignal.timeout is left real: only the broker's own timers are on
    // the fake clock.
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A.r1"], 1).spy);
    const broker = makeBroker(env(kv), provider, storage);

    const tokens = await Promise.all(Array.from({ length: 25 }, () => broker.getOrRefreshAccessToken(args)));
    expect(new Set(tokens)).toEqual(new Set(["AT-2"]));
    // A cache hit settles first too.
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the hard cap (300 s) aborts the POST: the flight settles with a timeout, nothing is written, and the next call refreshes normally", async () => {
    expect(REFRESH_HARD_CAP_MS).toBe(300_000);
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    // An upstream that never answers this request.
    const hanging = heldFetch(up.spy);
    vi.stubGlobal("fetch", hanging.spy);
    fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));

    // Joins 10 s before the cap, so it is still waiting when the cap fires.
    await vi.advanceTimersByTimeAsync(260_000);
    const joined = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    expect(hanging.spy).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await joined).toEqual(new Error(`Refresh timed out after ${REFRESH_HARD_CAP_MS} ms`));
    expect(storage.put).not.toHaveBeenCalled();
    expect(kv.put).not.toHaveBeenCalled();

    // The flight is gone: the next call starts a fresh refresh.
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-2");
    expect(hanging.spy).toHaveBeenCalledTimes(2);
  });

  it("the soft deadline and the hard cap are injectable", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const hanging = heldFetch(makeRotatingUpstream(["RT_A.r1"], 1).spy);
    vi.stubGlobal("fetch", hanging.spy);
    const abortMs = fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage, { timeoutMs: 50, hardCapMs: 200 });

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(50);
    expect(await first).toEqual(new Error("Refresh timed out after 50 ms"));
    expect(abortMs).toEqual([200]);
    // Joins 40 ms before the cap, inside its own 50 ms wait.
    await vi.advanceTimersByTimeAsync(110);
    const joined = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(40);
    expect(await joined).toEqual(new Error("Refresh timed out after 200 ms"));
  });

  it("rollback recovery runs inside the late flight, each POST under the hard cap, and its result is saved and served", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    // Storage stranded on the spent RT_A.r1; KV holds the live RT_A.r3.
    await seedStorage(storage, key, "RT_A.r1");
    kv.data.set(key, JSON.stringify(await encryptSlot("RT_A", {
      seedKey: await hashRefreshToken("RT_A"),
      currentRefreshToken: "RT_A.r3",
      lastUsedAt: T0,
    } satisfies GrantSlot)));
    const up = makeRotatingUpstream(["RT_A.r3"], 3);
    const held = heldFetch(up.spy);
    vi.stubGlobal("fetch", held.spy);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const abortMs = fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));
    const joined = broker.getOrRefreshAccessToken(args);
    await settle();
    expect(held.spy).toHaveBeenCalledTimes(1);

    // The held POST is rejected (invalid_grant); recovery's retry with the
    // KV chain is the flight's second POST.
    held.release();
    await expect(joined).resolves.toBe("AT-4");
    expect(presented(up.bodies)).toEqual(["RT_A.r1", "RT_A.r3"]);
    expect(abortMs).toEqual([REFRESH_HARD_CAP_MS, REFRESH_HARD_CAP_MS]);
    expect(await storedChain(storage, key)).toBe("RT_A.r4");
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-4");
    expect(held.spy).toHaveBeenCalledTimes(2);
  });

  it("the prune alarm leaves a slot whose flight outlived its callers, and the late result is saved", async () => {
    const TTL_MS = SLOT_TTL_SECONDS * 1000;
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1", T0);
    vi.setSystemTime(T0 + TTL_MS - 1_000);
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    const held = heldFetch(up.spy);
    vi.stubGlobal("fetch", held.spy);
    fakeAbortDeadlines();
    const broker = makeBroker(env(kv), provider, storage);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));

    // The slot is now past its TTL and the alarm fires mid-flight.
    await broker.alarm();
    expect(storage.data.has(key)).toBe(true);
    expect(storage.alarmAt).toBe(Date.now() + 60_000);

    held.release();
    await settle();
    expect(await storedChain(storage, key)).toBe("RT_A.r2");
    expect((storage.data.get(key) as StoredSlotRecord).writtenAt).toBe(Date.now());
  });

  it("each flight is passed to ctx.waitUntil once, settled without rejecting, so the object isn't evicted while it outlives its callers", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    const held = heldFetch(up.spy);
    vi.stubGlobal("fetch", held.spy);
    fakeAbortDeadlines();
    const waitUntil = vi.fn<(p: Promise<unknown>) => void>();
    const TokenBrokerDO = createTokenBrokerDO(provider);
    const broker = new TokenBrokerDO(makeDoState(storage, waitUntil), env(kv) as never);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));
    const joined = broker.getOrRefreshAccessToken(args);
    await settle();
    expect(waitUntil).toHaveBeenCalledTimes(1);

    held.release();
    await expect(joined).resolves.toBe("AT-2");
    await expect(waitUntil.mock.calls[0]![0]).resolves.toBeUndefined();

    // A failed flight's waitUntil promise resolves too: the waiters get the
    // error, the runtime gets no rejection to report.
    vi.setSystemTime(T0 + 3_600_000);
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => new Response("down", { status: 500 })));
    await expect(broker.getOrRefreshAccessToken(args)).rejects.toThrow("Refresh failed 500");
    expect(waitUntil).toHaveBeenCalledTimes(2);
    await expect(waitUntil.mock.calls[1]![0]).resolves.toBeUndefined();
  });

  it("a static provider gets no soft deadline: its POST is aborted at 30 s, and the timeout is the caller's error", async () => {
    const kv = makeKV();
    let aborted = false;
    const hanging = vi.fn<typeof fetch>((_input, init) => new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal;
      signal?.addEventListener("abort", () => { aborted = true; reject(signal.reason); }, { once: true });
    }));
    vi.stubGlobal("fetch", hanging);
    const abortMs = fakeAbortDeadlines();
    const broker = makeBroker(env(kv), staticProvider);

    const first = broker.getOrRefreshAccessToken(args).catch((e: unknown) => e);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await first).toEqual(new Error(SOFT_TIMEOUT));
    expect(aborted).toBe(true);
    expect(abortMs).toEqual([30_000]);

    // The flight was cleared with the abort: the next call refreshes again.
    vi.stubGlobal("fetch", makeRotatingUpstream(["RT_A"]).spy);
    await expect(broker.getOrRefreshAccessToken(args)).resolves.toBe("AT-1");
  });

  // Residual (SECURITY.md §6): the flight lives in the object's memory. If
  // the object is reset after the upstream rotated but before the KV mirror,
  // the new chain exists nowhere and the grant must reconnect. A reset after
  // the mirror is healed by rollback recovery (see "a DO storage write
  // failure after a rotation" above).
  it("residual: a reset after the upstream rotated but before the KV mirror loses the chain", async () => {
    const kv = makeKV();
    const storage = makeDoStorage();
    const key = await slotKey("user-1", "RT_A");
    await seedStorage(storage, key, "RT_A.r1");
    const up = makeRotatingUpstream(["RT_A.r1"], 1);
    // The upstream rotates, but the answer never reaches the old object.
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async (u, init) => {
      await up.spy(u, init);
      return new Promise<Response>(() => {});
    }));
    fakeAbortDeadlines();
    void makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args).catch(() => {});
    await settle();
    expect(up.valid.has("RT_A.r2")).toBe(true);

    // A new instance over the same storage has no flight to join.
    vi.stubGlobal("fetch", up.spy);
    await expect(makeBroker(env(kv), provider, storage).getOrRefreshAccessToken(args))
      .rejects.toThrow("Refresh failed 400 (invalid_grant)");
    expect(await storedChain(storage, key)).toBe("RT_A.r1");
  });
});
