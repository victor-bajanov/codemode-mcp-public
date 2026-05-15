import type { TokenRotation } from "./api-provider";

export interface GrantSlot {
  seedKey: string;
  currentRefreshToken: string;
  accessToken?: string;
  accessExpiresAt?: number;   // epoch ms
  lastUsedAt: number;
}

export interface RefreshTokenStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

export interface RefreshArgs {
  storage: RefreshTokenStorage;
  rotation: TokenRotation;
  refreshToken: string;
  clientId: string;
  clientSecret: string;
  tokenUrl: string;
  fetcher?: typeof fetch;
}

const SKEW_MS = 30_000;

export async function hashRefreshToken(token: string): Promise<string> {
  const bytes = new TextEncoder().encode(token);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function getOrRefreshAccessToken(args: RefreshArgs): Promise<string> {
  const f = args.fetcher ?? fetch;
  const seedKey = await hashRefreshToken(args.refreshToken);
  const storageKey = `grants:${seedKey}`;
  const now = Date.now();

  const existing = await args.storage.get<GrantSlot>(storageKey);
  const slot: GrantSlot = existing ?? {
    seedKey,
    currentRefreshToken: args.refreshToken,
    lastUsedAt: now,
  };

  // Cache hit (with skew buffer)
  if (
    slot.accessToken &&
    slot.accessExpiresAt !== undefined &&
    now < slot.accessExpiresAt - SKEW_MS
  ) {
    slot.lastUsedAt = now;
    await args.storage.put(storageKey, slot);
    return slot.accessToken;
  }

  // Refresh upstream
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: slot.currentRefreshToken,
    client_id: args.clientId,
    client_secret: args.clientSecret,
  });
  const res = await f(args.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Refresh failed ${res.status}: ${text}`);
  }
  const json = JSON.parse(text) as {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
  };

  slot.accessToken = json.access_token;
  slot.accessExpiresAt = now + json.expires_in * 1000;
  slot.lastUsedAt = now;
  if (args.rotation === "rotating" && json.refresh_token) {
    slot.currentRefreshToken = json.refresh_token;
  }
  await args.storage.put(storageKey, slot);
  return slot.accessToken;
}
