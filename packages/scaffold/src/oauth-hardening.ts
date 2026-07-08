/**
 * Hardening for the library-owned OAuth endpoints (`POST /register`,
 * `POST /token`), which `@cloudflare/workers-oauth-provider` serves without
 * rate limiting or cache-control headers.
 *
 * Two controls, both applied by {@link enforceOAuthHardening} at the worker
 * `fetch` boundary before/after delegating to the OAuth provider:
 *
 *  1. Rate limiting — a fixed-window counter keyed by (endpoint, client IP)
 *     backed by the already-bound OAUTH_KV. Closes the "unlimited open client
 *     registration" and "unthrottled token probing" findings. KV is only
 *     eventually consistent, so the count is approximate — acceptable for
 *     coarse abuse throttling, where the goal is to deny sustained bursts, not
 *     to meter exactly. An attacker can no longer register 50 clients or fire
 *     100 token probes without hitting HTTP 429.
 *
 *  2. Cache-Control — RFC 6749 §5.1 mandates `Cache-Control: no-store` and
 *     `Pragma: no-cache` on responses that carry tokens/credentials. The
 *     library omits them; we add them to every hardened-endpoint response so a
 *     caching intermediary can never retain a client secret or token.
 */

export interface RateLimitStore {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number },
  ): Promise<void>;
}

export interface RateLimitConfig {
  /** Max requests permitted per client, per endpoint, per window. */
  limit: number;
  /** Fixed-window length in seconds. */
  windowSeconds: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds until the current window resets (0 when allowed). */
  retryAfterSeconds: number;
}

const KEY_PREFIX = "ratelimit:";

/**
 * Fixed-window rate-limit check. Reads the current window's counter, denies if
 * it already reached the limit, otherwise increments it and permits the call.
 */
export async function checkRateLimit(
  store: RateLimitStore,
  identity: { endpoint: string; client: string },
  cfg: RateLimitConfig,
  nowMs: number,
): Promise<RateLimitDecision> {
  const nowSec = Math.floor(nowMs / 1000);
  const windowIndex = Math.floor(nowSec / cfg.windowSeconds);
  const key = `${KEY_PREFIX}${identity.endpoint}:${identity.client}:${windowIndex}`;

  const raw = await store.get(key);
  const count = raw ? Number.parseInt(raw, 10) : 0;
  const windowEndsAtSec = (windowIndex + 1) * cfg.windowSeconds;
  const retryAfterSeconds = Math.max(1, windowEndsAtSec - nowSec);

  if (Number.isFinite(count) && count >= cfg.limit) {
    return { allowed: false, retryAfterSeconds };
  }

  // TTL slightly beyond the window so a stale key can't outlive its bucket.
  await store.put(key, String((Number.isFinite(count) ? count : 0) + 1), {
    expirationTtl: cfg.windowSeconds + 60,
  });
  return { allowed: true, retryAfterSeconds: 0 };
}

/** Per-endpoint rate-limit configuration for the two hardened endpoints. */
export interface HardeningConfig {
  register: RateLimitConfig;
  token: RateLimitConfig;
}

export type HardenedEndpoint = "register" | "token";

/** KV key prefix for the scaffold-owned registration timestamp stamp. */
export const CLIENT_STAMP_PREFIX = "clientreg:";

/**
 * Record a registration timestamp for a freshly-registered client so the
 * scheduled sweep can age ungranted clients. The library stores `client:<id>`
 * with no timestamp field, so we stamp a parallel `clientreg:<id>` key from the
 * `/register` response. Best-effort: a non-JSON body or a body without a string
 * `client_id` is silently skipped (nothing to key on). No TTL — the stamp is a
 * tiny key deleted alongside its client when the sweep reaps it, and left in
 * place for legitimate (granted) clients.
 */
export async function stampClientRegistration(
  store: RateLimitStore,
  responseText: string,
  nowMs: number,
): Promise<void> {
  let clientId: unknown;
  try {
    clientId = (JSON.parse(responseText) as { client_id?: unknown }).client_id;
  } catch {
    return;
  }
  if (typeof clientId !== "string" || clientId.length === 0) return;
  await store.put(
    `${CLIENT_STAMP_PREFIX}${clientId}`,
    JSON.stringify({ registeredAt: nowMs }),
  );
}

/**
 * Returns which hardened endpoint a request targets, or null if it is not one.
 * Scoped to `POST /register` and `POST /token` exactly — GET reads of
 * `/register/<id>` and the MCP API route are untouched.
 */
export function classifyHardenedRequest(request: Request): HardenedEndpoint | null {
  if (request.method !== "POST") return null;
  const { pathname } = new URL(request.url);
  if (pathname === "/register") return "register";
  if (pathname === "/token") return "token";
  return null;
}

/** Best-effort client identifier for rate-limit bucketing. */
export function clientIdentity(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "unknown";
}

/** Return a copy of `res` with RFC 6749 §5.1 no-store cache headers set. */
export function withNoStore(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
}

/** Build a 429 response with Retry-After and no-store headers. */
export function tooManyRequestsResponse(retryAfterSeconds: number): Response {
  return withNoStore(
    new Response(
      JSON.stringify({
        error: "rate_limited",
        error_description: "Too many requests. Retry after the indicated delay.",
      }),
      {
        status: 429,
        headers: {
          "content-type": "application/json",
          "Retry-After": String(retryAfterSeconds),
        },
      },
    ),
  );
}

/**
 * Apply rate limiting + no-store hardening around the OAuth provider handler.
 * Non-hardened requests pass straight through; hardened requests are rate
 * limited (429 before the handler runs, using the per-endpoint config) and,
 * when permitted, have their response wrapped with no-store cache headers.
 *
 * A successful `POST /register` additionally has its `client_id` stamped with a
 * registration timestamp (see {@link stampClientRegistration}) so the scheduled
 * sweep can age ungranted clients.
 */
export async function enforceOAuthHardening(
  request: Request,
  store: RateLimitStore,
  cfg: HardeningConfig,
  nowMs: number,
  handler: (request: Request) => Promise<Response>,
): Promise<Response> {
  const endpoint = classifyHardenedRequest(request);
  if (!endpoint) return handler(request);

  const decision = await checkRateLimit(
    store,
    { endpoint, client: clientIdentity(request) },
    cfg[endpoint],
    nowMs,
  );
  if (!decision.allowed) {
    return tooManyRequestsResponse(decision.retryAfterSeconds);
  }

  const response = await handler(request);

  // Stamp a registration timestamp for the sweep. The body is consumed to read
  // client_id, so rebuild the response from its text before returning.
  if (endpoint === "register" && response.ok) {
    const text = await response.text();
    await stampClientRegistration(store, text, nowMs);
    return withNoStore(
      new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      }),
    );
  }

  return withNoStore(response);
}
