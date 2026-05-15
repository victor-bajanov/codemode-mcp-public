// packages/scaffold/src/__tests__/refresh.test.ts
//
// Tests for getOrRefreshAccessToken — per-grant DO-slot token refresh
// supporting both static (Gmail) and rotating (Xero) refresh-token regimes.
//
// The refresh fn must:
//   - On first call for a fresh seed: refresh upstream, persist slot, return access token.
//   - On subsequent call within expiry skew window: return cached access token without upstream call.
//   - On expired access token: refresh upstream, persist updated access token + expiresAt.
//   - rotation="rotating" + refresh response with new refresh_token: persist new currentRefreshToken.
//   - rotation="static" + refresh response with new refresh_token: keep original currentRefreshToken.
//   - Two distinct seed keys (multi-grant): produce independent slots; refreshing one does not touch the other.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { getOrRefreshAccessToken, hashRefreshToken } from "../refresh";

type Slot = {
  seedKey: string;
  currentRefreshToken: string;
  accessToken?: string;
  accessExpiresAt?: number;
  lastUsedAt: number;
};

function makeStorage() {
  const data = new Map<string, unknown>();
  return {
    data,
    async get<T>(key: string): Promise<T | undefined> {
      return data.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      data.set(key, value);
    },
  };
}

const TOKEN_URL = "https://identity.example.com/connect/token";

function makeFetchSpy(
  responses: Array<{ access_token: string; expires_in: number; refresh_token?: string }>,
) {
  let i = 0;
  return vi.fn<typeof fetch>(async (_input, _init) => {
    const r = responses[i++];
    if (!r) throw new Error("fetch called more times than responses array length");
    return new Response(JSON.stringify(r), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
}

describe("getOrRefreshAccessToken", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-05T00:00:00Z"));
  });

  it("first call seeds the slot and returns the upstream access token", async () => {
    const storage = makeStorage();
    const fetchSpy = makeFetchSpy([{ access_token: "AT-1", expires_in: 1800 }]);
    vi.stubGlobal("fetch", fetchSpy);

    const token = await getOrRefreshAccessToken({
      storage,
      rotation: "static",
      refreshToken: "RT-seed",
      clientId: "CID",
      clientSecret: "CSEC",
      tokenUrl: TOKEN_URL,
    });

    expect(token).toBe("AT-1");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const slot = (await storage.get<Slot>(`grants:${await hashRefreshToken("RT-seed")}`))!;
    expect(slot.currentRefreshToken).toBe("RT-seed");
    expect(slot.accessToken).toBe("AT-1");
  });

  it("returns cached access token within skew window without refreshing", async () => {
    const storage = makeStorage();
    const fetchSpy = makeFetchSpy([{ access_token: "AT-1", expires_in: 1800 }]);
    vi.stubGlobal("fetch", fetchSpy);

    await getOrRefreshAccessToken({
      storage, rotation: "static", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    // Advance 5 minutes — well within the 30-min token life and outside the 30s skew.
    vi.setSystemTime(new Date("2026-05-05T00:05:00Z"));

    const token2 = await getOrRefreshAccessToken({
      storage, rotation: "static", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    expect(token2).toBe("AT-1");
    expect(fetchSpy).toHaveBeenCalledTimes(1);   // still just the first fetch
  });

  it("refreshes when the cached access token is within the 30s skew of expiry", async () => {
    const storage = makeStorage();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-1", expires_in: 60 },          // first refresh: 60s lifetime
      { access_token: "AT-2", expires_in: 1800 },        // second refresh
    ]);
    vi.stubGlobal("fetch", fetchSpy);

    await getOrRefreshAccessToken({
      storage, rotation: "static", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    // 35 seconds in: cached token has 25s left, inside the 30s skew.
    vi.setSystemTime(new Date("2026-05-05T00:00:35Z"));

    const token2 = await getOrRefreshAccessToken({
      storage, rotation: "static", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    expect(token2).toBe("AT-2");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("rotation='rotating' updates currentRefreshToken when upstream returns one", async () => {
    const storage = makeStorage();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-1", expires_in: 60, refresh_token: "RT-rotated-1" },
      { access_token: "AT-2", expires_in: 1800, refresh_token: "RT-rotated-2" },
    ]);
    vi.stubGlobal("fetch", fetchSpy);

    await getOrRefreshAccessToken({
      storage, rotation: "rotating", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    const slotKey = `grants:${await hashRefreshToken("RT-seed")}`;
    let slot = (await storage.get<Slot>(slotKey))!;
    expect(slot.currentRefreshToken).toBe("RT-rotated-1");

    vi.setSystemTime(new Date("2026-05-05T00:00:45Z"));   // expired
    await getOrRefreshAccessToken({
      storage, rotation: "rotating", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    slot = (await storage.get<Slot>(slotKey))!;
    expect(slot.currentRefreshToken).toBe("RT-rotated-2");
    expect(slot.accessToken).toBe("AT-2");

    // Verify second fetch used the rotated token, not the original seed.
    const secondCallBody = (fetchSpy.mock.calls[1]![1]! as RequestInit).body;
    expect(String(secondCallBody)).toContain("RT-rotated-1");
  });

  it("rotation='static' keeps currentRefreshToken pinned even when upstream returns a new one", async () => {
    const storage = makeStorage();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-1", expires_in: 60, refresh_token: "RT-google-might-rotate" },
      { access_token: "AT-2", expires_in: 1800 },
    ]);
    vi.stubGlobal("fetch", fetchSpy);

    await getOrRefreshAccessToken({
      storage, rotation: "static", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    const slotKey = `grants:${await hashRefreshToken("RT-seed")}`;
    const slot = (await storage.get<Slot>(slotKey))!;
    expect(slot.currentRefreshToken).toBe("RT-seed");

    vi.setSystemTime(new Date("2026-05-05T00:00:45Z"));
    await getOrRefreshAccessToken({
      storage, rotation: "static", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    // Second refresh used the original seed, not the upstream-returned rotated token.
    const secondCallBody = (fetchSpy.mock.calls[1]![1]! as RequestInit).body;
    expect(String(secondCallBody)).toContain("RT-seed");
  });

  it("two distinct seed tokens get independent slots", async () => {
    const storage = makeStorage();
    const fetchSpy = makeFetchSpy([
      { access_token: "AT-A", expires_in: 1800 },
      { access_token: "AT-B", expires_in: 1800 },
    ]);
    vi.stubGlobal("fetch", fetchSpy);

    const a = await getOrRefreshAccessToken({
      storage, rotation: "rotating", refreshToken: "RT-A",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });
    const b = await getOrRefreshAccessToken({
      storage, rotation: "rotating", refreshToken: "RT-B",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    });

    expect(a).toBe("AT-A");
    expect(b).toBe("AT-B");
    expect(storage.data.size).toBe(2);
  });

  it("propagates upstream 4xx as a thrown error (caller should map to 401)", async () => {
    const storage = makeStorage();
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }),
    ));

    await expect(getOrRefreshAccessToken({
      storage, rotation: "rotating", refreshToken: "RT-seed",
      clientId: "CID", clientSecret: "CSEC", tokenUrl: TOKEN_URL,
    })).rejects.toThrow();
  });
});
