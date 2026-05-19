import { describe, it, expect, vi, beforeEach } from "vitest";
import { createTokenBrokerDO, type TokenBrokerArgs } from "../token-broker";
import type { ApiProvider } from "../api-provider";
import { decryptSlot } from "../encrypt-slot";
import type { GrantSlot } from "../refresh";

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

function makeBroker(env: { OAUTH_KV: KVNamespace; XERO_CLIENT_ID: string; XERO_CLIENT_SECRET: string }) {
  const TokenBrokerDO = createTokenBrokerDO(provider);
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
    expect(kv.data.has("token-slot:user-A")).toBe(true);
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
    const sealedRaw = kv.data.get("token-slot:user-A")!;
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

    // User re-auths: props.refreshToken changes. Old sealed slot can no
    // longer be unwrapped → broker treats as cache miss → refreshes upstream
    // with the new seed.
    vi.setSystemTime(new Date("2026-05-19T01:00:00Z"));
    const tok = await broker.getOrRefreshAccessToken({ userId: "user-A", refreshToken: "RT-NEW-SEED" });

    expect(tok).toBe("AT-new");
    const secondBody = String((fetchSpy.mock.calls[1]![1]! as RequestInit).body);
    expect(secondBody).toContain("RT-NEW-SEED");
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
    expect(kv.data.has("token-slot:user-A")).toBe(true);
    expect(kv.data.has("token-slot:user-B")).toBe(true);
  });
});
