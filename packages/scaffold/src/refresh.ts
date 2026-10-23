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
  /** Abort deadline for the refresh POST and its body read, in ms. Defaults
   *  to {@link REFRESH_TIMEOUT_MS}. The token broker passes
   *  {@link REFRESH_HARD_CAP_MS} for rotating providers. */
  timeoutMs?: number;
}

const SKEW_MS = 30_000;

/** For a static provider, when the refresh POST is aborted; for a rotating
 *  one, how long each broker call waits for the grant's flight. Without a
 *  deadline a token endpoint that never answers would hold the broker's
 *  single flight for the grant (and every caller waiting on it)
 *  indefinitely. */
export const REFRESH_TIMEOUT_MS = 30_000;

/** When a rotating provider's refresh POST is aborted. Its callers stop
 *  waiting at {@link REFRESH_TIMEOUT_MS}, but the POST keeps running: the
 *  upstream may already have spent the presented refresh token, so aborting
 *  it would lose the new one. The cap only releases a grant whose token
 *  endpoint never answers. */
export const REFRESH_HARD_CAP_MS = 300_000;

/** Shape an OAuth `error` code must have to be echoed in errors and logs. */
const OAUTH_ERROR_CODE_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/**
 * Extract the RFC 6749 §5.2 `error` code from a token-endpoint error body, or
 * `undefined` when the body is not JSON, has no string `error`, or the code is
 * not a short token-shaped string. Only this code is ever surfaced: the rest
 * of the body is upstream-controlled text (and, from a misconfigured echoing
 * endpoint, could contain the request's own credentials).
 */
export function oauthErrorCode(body: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const code = (parsed as { error?: unknown }).error;
    return typeof code === "string" && OAUTH_ERROR_CODE_RE.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A non-2xx answer from the token endpoint. The message is
 * `Refresh failed <status>` plus ` (<code>)` when the body named a
 * token-shaped OAuth `error` code; `status` and `code` carry the same facts
 * for callers that branch on them (the token broker recovers a
 * rollback-stranded chain only on `invalid_grant`). Timeouts and fetch errors
 * are not this type.
 */
export class RefreshFailedError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, code: string | undefined) {
    super(code ? `Refresh failed ${status} (${code})` : `Refresh failed ${status}`);
    this.name = "RefreshFailedError";
    this.status = status;
    this.code = code;
  }
}

export async function hashRefreshToken(token: string): Promise<string> {
  const bytes = new TextEncoder().encode(token);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Return a valid upstream access token for the grant seeded by
 * `args.refreshToken`, refreshing it upstream when the cached one is missing
 * or within {@link SKEW_MS} of expiry.
 *
 * The refresh POST is aborted after `timeoutMs` ({@link REFRESH_TIMEOUT_MS}
 * by default) and throws `Error("Refresh timed out after <ms> ms")`. Other
 * fetch errors propagate unchanged.
 *
 * A non-2xx refresh throws a {@link RefreshFailedError}
 * (`Refresh failed <status>`), with ` (<error>)` appended when the token
 * endpoint returned JSON carrying a token-shaped OAuth `error` code (F-21).
 * The response body itself is neither included in the error (which reaches
 * the sandbox and the model) nor logged.
 */
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
  const timeoutMs = args.timeoutMs ?? REFRESH_TIMEOUT_MS;
  const signal = AbortSignal.timeout(timeoutMs);
  let res: Response;
  let text: string;
  try {
    res = await f(args.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal,
    });
    text = await res.text();
  } catch (err) {
    // The deadline's TimeoutError is a DOMException; the caller (and, over
    // DO RPC, the sandbox) gets a plain Error with a clear message instead.
    if (signal.aborted) throw new Error(`Refresh timed out after ${timeoutMs} ms`);
    throw err;
  }
  if (!res.ok) {
    throw new RefreshFailedError(res.status, oauthErrorCode(text));
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
