/**
 * Hardening for the library-owned OAuth endpoints (`POST /register`,
 * `POST /token`), which `@cloudflare/workers-oauth-provider` serves without
 * rate limiting or cache-control headers, plus the failure-budget throttle in
 * front of the public `/staging/*` endpoints ({@link enforceStagingThrottle}).
 *
 * Three controls, all applied by {@link enforceOAuthHardening} at the worker
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
 *
 *  3. Redirect-URI rule (F-2) — `POST /register` refuses `http://` redirect
 *     URIs whose host is not loopback, so a registered client can only receive
 *     authorisation codes over TLS or on the operator's own machine.
 *
 * Rate-limit identities bucket IPv6 clients by /64 (F-14), the allocation a
 * single subscriber typically controls; see {@link clientIdentity}.
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

/**
 * Parse an IPv6 address (with `::` compression and an optional dotted IPv4
 * tail) into its eight 16-bit groups, or `null` when it is not one.
 */
function parseIpv6(raw: string): number[] | null {
  let s = raw.toLowerCase();
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(":");
  if (s.slice(lastColon + 1).includes(".")) {
    const octets = s.slice(lastColon + 1).split(".");
    if (octets.length !== 4) return null;
    const bytes: number[] = [];
    for (const o of octets) {
      if (!/^\d{1,3}$/.test(o)) return null;
      const n = Number(o);
      if (n > 255) return null;
      bytes.push(n);
    }
    tail = [(bytes[0]! << 8) | bytes[1]!, (bytes[2]! << 8) | bytes[3]!];
    // Stand two zero groups in for the IPv4 tail (keeping the separating
    // colon so `::1.2.3.4` still splits on `::` below); swapped back after.
    s = s.slice(0, lastColon + 1) + "0:0";
  }

  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };

  let groups: number[];
  const halves = s.split("::");
  if (halves.length > 2) return null;
  if (halves.length === 2) {
    const left = parseGroups(halves[0]!);
    const right = parseGroups(halves[1]!);
    if (!left || !right) return null;
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    groups = [...left, ...new Array<number>(fill).fill(0), ...right];
  } else {
    const all = parseGroups(s);
    if (!all || all.length !== 8) return null;
    groups = all;
  }
  if (tail.length === 2) groups = [...groups.slice(0, 6), ...tail];
  return groups;
}

/**
 * Best-effort client identifier for rate-limit bucketing.
 *
 * IPv4 stays per address (a /24 would throttle unrelated NAT neighbours).
 * IPv6 is bucketed by /64 as `ip6:<h0>:<h1>:<h2>:<h3>::/64` (lower-case,
 * unpadded), because a single subscriber routinely controls a whole /64 and
 * would otherwise get 2^64 independent budgets (F-14). IPv4-mapped IPv6
 * (`::ffff:a.b.c.d`) is treated as the IPv4 address. An unparseable value is
 * used verbatim; a missing header falls back to the shared `"unknown"` bucket
 * (only reachable off Cloudflare, e.g. local `wrangler dev`).
 */
export function clientIdentity(request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip === null) return "unknown";
  if (!ip.includes(":")) return ip;
  const g = parseIpv6(ip);
  if (!g) return ip;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return `${g[6]! >> 8}.${g[6]! & 0xff}.${g[7]! >> 8}.${g[7]! & 0xff}`;
  }
  return `ip6:${g.slice(0, 4).map((h) => h.toString(16)).join(":")}::/64`;
}

/** Hosts for which `/register` still accepts a plaintext `http://` redirect URI. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Bodies larger than this are left to the library (which rejects them itself). */
const MAX_REGISTRATION_BODY_BYTES = 1024 * 1024;

/**
 * Enforce the redirect-URI rule on a `POST /register` body (F-2): every string
 * in `redirect_uris` that is an `http://` URL must name a loopback host
 * (`localhost`, `127.0.0.1`, `[::1]`). Returns a no-store 400
 * `invalid_redirect_uri` response on a violation, otherwise `null`.
 *
 * `https://` URIs (claude.ai) and loopback `http://` URIs (Claude Code, MCP
 * Inspector) pass unchanged; custom schemes, unparseable URIs, oversized and
 * non-JSON bodies are left to the library's own validation. Reads a clone, so
 * the original request stays readable for the handler.
 */
export async function validateRegistrationRedirectUris(
  request: Request,
): Promise<Response | null> {
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_REGISTRATION_BODY_BYTES) return null;
  let body: unknown;
  try {
    const text = await request.clone().text();
    if (text.length > MAX_REGISTRATION_BODY_BYTES) return null;
    body = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof body !== "object" || body === null) return null;
  const uris = (body as { redirect_uris?: unknown }).redirect_uris;
  if (!Array.isArray(uris)) return null;
  for (const uri of uris) {
    if (typeof uri !== "string") continue;
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      continue;
    }
    if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
      return withNoStore(
        new Response(
          JSON.stringify({
            error: "invalid_redirect_uri",
            error_description:
              "http:// redirect URIs are only accepted for loopback hosts; use https",
          }),
          { status: 400, headers: { "content-type": "application/json" } },
        ),
      );
    }
  }
  return null;
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
 * A `POST /register` whose `redirect_uris` break the loopback-only `http://`
 * rule is refused with 400 before the handler runs (see
 * {@link validateRegistrationRedirectUris}). A successful `POST /register`
 * additionally has its `client_id` stamped with a registration timestamp (see {@link stampClientRegistration}) so the scheduled
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

  if (endpoint === "register") {
    const refusal = await validateRegistrationRedirectUris(request);
    if (refusal) return refusal;
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

// --- /staging/* failure-budget throttle (F-13) ---

/** Failures permitted per client per fixed window before `/staging/*` answers 429. */
export interface FailureBudgetConfig {
  limit: number;
  windowSeconds: number;
}

const STAGING_FAILURE_KEY_PREFIX = `${KEY_PREFIX}staging-fail:`;

function failureWindow(client: string, cfg: FailureBudgetConfig, nowMs: number) {
  const nowSec = Math.floor(nowMs / 1000);
  const windowIndex = Math.floor(nowSec / cfg.windowSeconds);
  return {
    key: `${STAGING_FAILURE_KEY_PREFIX}${client}:${windowIndex}`,
    retryAfterSeconds: Math.max(1, (windowIndex + 1) * cfg.windowSeconds - nowSec),
  };
}

/**
 * Read-only check of a client's staging failure budget for the current
 * window. Denies once `limit` failures have been recorded. A store read error
 * fails open: the staging handlers still demand a 256-bit bearer, so the
 * throttle only bounds the D1 cost of guessing, it is not the access control.
 */
export async function checkFailureBudget(
  store: RateLimitStore,
  client: string,
  cfg: FailureBudgetConfig,
  nowMs: number,
): Promise<RateLimitDecision> {
  const { key, retryAfterSeconds } = failureWindow(client, cfg, nowMs);
  let raw: string | null;
  try {
    raw = await store.get(key);
  } catch {
    return { allowed: true, retryAfterSeconds: 0 };
  }
  const count = raw ? Number.parseInt(raw, 10) : 0;
  if (Number.isFinite(count) && count >= cfg.limit) {
    return { allowed: false, retryAfterSeconds };
  }
  return { allowed: true, retryAfterSeconds: 0 };
}

/**
 * Record one failure against a client's staging budget (read-increment-write;
 * approximate under KV's eventual consistency, like {@link checkRateLimit}).
 * Never rejects: store errors are swallowed so a KV hiccup cannot turn a 403
 * into a 500.
 */
export async function recordFailure(
  store: RateLimitStore,
  client: string,
  cfg: FailureBudgetConfig,
  nowMs: number,
): Promise<void> {
  const { key } = failureWindow(client, cfg, nowMs);
  try {
    const raw = await store.get(key);
    const count = raw ? Number.parseInt(raw, 10) : 0;
    await store.put(key, String((Number.isFinite(count) ? count : 0) + 1), {
      expirationTtl: cfg.windowSeconds + 60,
    });
  } catch {
    // Best effort.
  }
}

/**
 * Failure-budget throttle around a `/staging/*` handler (F-13). Each request
 * first reads the client's failure counter and is refused with 429 — before
 * the handler, and therefore before any D1 read — once the budget is spent.
 * Only `403` outcomes (missing bearer, unknown token, wrong handle) count as
 * failures; successful requests never write KV, so legitimate downloads cost
 * one KV read and stay clear of KV's per-key write limit. The failure write
 * goes through `waitUntil` when given, otherwise it is awaited.
 */
export async function enforceStagingThrottle(
  request: Request,
  store: RateLimitStore,
  cfg: FailureBudgetConfig,
  nowMs: number,
  handler: (request: Request) => Promise<Response>,
  waitUntil?: (promise: Promise<unknown>) => void,
): Promise<Response> {
  const client = clientIdentity(request);
  const decision = await checkFailureBudget(store, client, cfg, nowMs);
  if (!decision.allowed) {
    return tooManyRequestsResponse(decision.retryAfterSeconds);
  }
  const response = await handler(request);
  if (response.status === 403) {
    const write = recordFailure(store, client, cfg, nowMs);
    if (waitUntil) waitUntil(write);
    else await write;
  }
  return response;
}
