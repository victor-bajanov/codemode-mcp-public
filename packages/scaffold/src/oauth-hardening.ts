/**
 * Hardening for the public OAuth endpoints — the library-owned
 * `POST /register` and `POST /token`, which `@cloudflare/workers-oauth-provider`
 * serves without rate limiting or cache-control headers, and the scaffold's
 * browser legs `/authorize` and `/callback` — plus the failure-budget throttle
 * in front of the public `/staging/*` endpoints ({@link enforceStagingThrottle}).
 *
 * Controls applied by {@link enforceOAuthHardening} at the worker `fetch`
 * boundary before/after delegating to the OAuth provider:
 *
 *  1. Rate limiting — a fixed-window counter keyed by (endpoint, client IP)
 *     backed by the already-bound OAUTH_KV, one bucket per endpoint. Closes
 *     the "unlimited open client registration" and "unthrottled token
 *     probing" findings, and (A-3, 2026-11 review) the unthrottled browser
 *     legs: every anonymous `/authorize` approval wrote KV and every
 *     `/callback` spent an upstream token request. KV is only eventually
 *     consistent and the read-then-write is not atomic, so the count is
 *     approximate — acceptable for coarse abuse throttling, where the goal is
 *     to deny sustained bursts, not to meter exactly. A denied request costs
 *     one KV read and no write.
 *
 *  2. Cache-Control — RFC 6749 §5.1 mandates `Cache-Control: no-store` and
 *     `Pragma: no-cache` on responses that carry tokens/credentials. The
 *     library omits them; we add them to every `/register` and `/token`
 *     response so a caching intermediary can never retain a client secret or
 *     token. The browser legs' responses pass through unchanged (the handler
 *     sets its own headers).
 *
 *  3. Redirect-URI rule (F-2) — `POST /register` refuses `http://` redirect
 *     URIs whose host is not loopback, so a registered client can only receive
 *     authorisation codes over TLS or on the operator's own machine.
 *
 *  4. Body caps (A-3) — every hardened request body is read with a streaming
 *     cap ({@link readBodyCapped}: 1 MiB for `/register`, 16 KiB for the
 *     `/authorize` and `/token` forms) and refused 413 before the library,
 *     which buffers bodies whole, sees it.
 *
 *  5. Client-record TTL (A-5) — the library writes `client:<id>` with no
 *     expiry. A successful `/register` re-puts it with the "unused" TTL and
 *     every successful `/token` with the "active" TTL
 *     ({@link refreshClientTtl}), so abandoned registrations drain by
 *     themselves and no scheduled sweep reads KV.
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

/** Per-endpoint configuration for the hardened OAuth endpoints. */
export interface HardeningConfig {
  register: RateLimitConfig;
  token: RateLimitConfig;
  authorize: RateLimitConfig;
  callback: RateLimitConfig;
  /**
   * KV TTLs put on the library's `client:<id>` record (A-5):
   * `registeredSeconds` after a successful `/register`, `activeSeconds` after
   * every successful `/token`.
   */
  clientTtl: { registeredSeconds: number; activeSeconds: number };
}

export type HardenedEndpoint = "register" | "token" | "authorize" | "callback";

/**
 * The request's pathname, percent-decoded the way it is routed: Hono decodes
 * `%xx` before matching `/authorize` and `/callback`, so `/%61uthorize`
 * reaches the consent handler and must count against the same bucket and body
 * cap (A-3). Returns null when the path holds a malformed escape
 * ({@link enforceOAuthHardening} refuses those with 400). A path without `%`
 * is returned as is.
 */
export function decodedPathname(request: Request): string | null {
  const { pathname } = new URL(request.url);
  if (!pathname.includes("%")) return pathname;
  try {
    return decodeURIComponent(pathname);
  } catch {
    return null;
  }
}

/**
 * Returns which hardened endpoint a request targets, or null if it is not one:
 * `POST /register`, `POST /token`, `GET`/`HEAD`/`POST /authorize` and
 * `GET`/`HEAD /callback` (HEAD costs the handler the same work as its GET).
 * The pathname is compared after percent-decoding ({@link decodedPathname});
 * a path that does not decode is not classified. Other methods on these
 * paths, GET reads of `/register/<id>` and the MCP API route are untouched.
 */
export function classifyHardenedRequest(request: Request): HardenedEndpoint | null {
  const pathname = decodedPathname(request);
  return pathname === null ? null : classifyDecoded(pathname, request.method);
}

/** {@link classifyHardenedRequest} on an already-decoded pathname. */
function classifyDecoded(pathname: string, method: string): HardenedEndpoint | null {
  if (method === "POST") {
    if (pathname === "/register") return "register";
    if (pathname === "/token") return "token";
  }
  if (pathname === "/authorize" && (method === "GET" || method === "HEAD" || method === "POST")) {
    return "authorize";
  }
  if (pathname === "/callback" && (method === "GET" || method === "HEAD")) return "callback";
  return null;
}

/** 400 for a request path holding a malformed percent-escape (no-store JSON). */
export function malformedPathResponse(): Response {
  return oauthErrorResponse(400, "invalid_request", "Malformed request path");
}

/** A no-store JSON `{ error, error_description }` response (RFC 6749 §5.2 shape). */
function oauthErrorResponse(
  status: number,
  error: string,
  description: string,
  headers: Record<string, string> = {},
): Response {
  return withNoStore(
    new Response(JSON.stringify({ error, error_description: description }), {
      status,
      headers: { "content-type": "application/json", ...headers },
    }),
  );
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

/** Body cap for `POST /register` (every DCR body accepted before still fits). */
export const MAX_REGISTRATION_BODY_BYTES = 1024 * 1024;

/**
 * Body cap for the `POST /authorize` and `POST /token` forms: a consent token
 * is 1–2 KB, an authorisation code a few hundred bytes, a PKCE verifier at
 * most 128 characters; 16 KiB is ten times the largest legitimate form.
 */
export const MAX_FORM_BODY_BYTES = 16 * 1024;

export type CappedBody =
  | { ok: true; text: string; bytes: Uint8Array }
  | { ok: false };

/**
 * Read a request body with a streaming cap (A-3). A `Content-Length` that
 * parses and exceeds `maxBytes` is refused without touching the body;
 * otherwise the body is read chunk by chunk and the read is cancelled the
 * moment the running total passes `maxBytes`, so at most the cap plus one
 * chunk is ever pulled. Returns the bytes and their UTF-8 text, or
 * `{ ok: false }` when over the cap. A missing body reads as empty.
 *
 * Consumes `request.body`; {@link enforceOAuthHardening} hands the handler a
 * copy of the request rebuilt from the returned bytes.
 */
export async function readBodyCapped(request: Request, maxBytes: number): Promise<CappedBody> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && /^\s*\d+\s*$/.test(declared) && Number(declared) > maxBytes) {
    return { ok: false };
  }
  if (request.body === null) return { ok: true, text: "", bytes: new Uint8Array(0) };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      // Not awaited: the cancel settles with the underlying source, and the
      // caller only needs the read to stop.
      reader.cancel().catch(() => {});
      return { ok: false };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(bytes), bytes };
}

/** 413 for a hardened request whose body is over its cap (no-store JSON). */
export function payloadTooLargeResponse(): Response {
  return oauthErrorResponse(413, "invalid_request", "Request body too large");
}

/**
 * Enforce the redirect-URI rule on a `POST /register` body (F-2): every string
 * in `redirect_uris` that is an `http://` URL must name a loopback host
 * (`localhost`, `127.0.0.1`, `[::1]`). Returns a no-store 400
 * `invalid_redirect_uri` response on a violation, otherwise `null`.
 *
 * `https://` URIs (claude.ai) and loopback `http://` URIs (Claude Code, MCP
 * Inspector) pass unchanged; custom schemes, unparseable URIs and non-JSON
 * bodies are left to the library's own validation. Takes the body text the
 * caller already read under the registration cap.
 */
export function validateRegistrationRedirectUris(text: string): Response | null {
  let body: unknown;
  try {
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
      return oauthErrorResponse(
        400,
        "invalid_redirect_uri",
        "http:// redirect URIs are only accepted for loopback hosts; use https",
      );
    }
  }
  return null;
}

/** KV key prefix of the library's client records. */
const CLIENT_KEY_PREFIX = "client:";

/**
 * Re-put the library's `client:<id>` record verbatim with a KV TTL (A-5).
 * Returns false when there is no record (KV read-after-write can miss in
 * production: the record then keeps whatever TTL it had, and the next
 * activity sets one). Best effort: an error is logged without the id and
 * reported as false; it never fails the response.
 */
export async function refreshClientTtl(
  store: RateLimitStore,
  clientId: string,
  ttlSeconds: number,
): Promise<boolean> {
  try {
    const key = `${CLIENT_KEY_PREFIX}${clientId}`;
    const record = await store.get(key);
    if (record === null) return false;
    await store.put(key, record, { expirationTtl: ttlSeconds });
    return true;
  } catch (err) {
    console.error(`oauth client ttl refresh failed: ${err instanceof Error ? err.message : "error"}`);
    return false;
  }
}

/** The `client_id` of a `/register` response body, or null. */
function registeredClientId(responseText: string): string | null {
  try {
    const id = (JSON.parse(responseText) as { client_id?: unknown }).client_id;
    return typeof id === "string" && id.length > 0 ? id : null;
  } catch {
    return null;
  }
}

/**
 * Whether the request's Content-Type essence (lower-cased, before the first
 * `;`, trimmed) is exactly `application/x-www-form-urlencoded` (A-5).
 */
function isUrlEncodedForm(request: Request): boolean {
  const type = request.headers.get("Content-Type");
  if (type === null) return false;
  return type.split(";", 1)[0]!.trim().toLowerCase() === "application/x-www-form-urlencoded";
}

/** Whether a `/token` form is a code exchange or a refresh (A-5). */
function isRenewingGrant(formText: string): boolean {
  try {
    const grant = new URLSearchParams(formText).get("grant_type");
    return grant === "authorization_code" || grant === "refresh_token";
  } catch {
    return false;
  }
}

/**
 * The `client_id` a `/token` request authenticated as, parsed the way the
 * library parses it: the Basic `Authorization` header when present
 * (percent-decoded), otherwise the form's `client_id`.
 */
function tokenRequestClientId(request: Request, formText: string): string | null {
  try {
    const auth = request.headers.get("Authorization");
    if (auth && auth.startsWith("Basic ")) {
      const [id] = atob(auth.substring(6)).split(":", 2);
      const decoded = decodeURIComponent(id ?? "");
      return decoded.length > 0 ? decoded : null;
    }
    const id = new URLSearchParams(formText).get("client_id");
    return id && id.length > 0 ? id : null;
  } catch {
    return null;
  }
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
  return oauthErrorResponse(
    429,
    "rate_limited",
    "Too many requests. Retry after the indicated delay.",
    { "Retry-After": String(retryAfterSeconds) },
  );
}

/** Body cap per hardened endpoint; `null` for requests that carry no body. */
function bodyCapFor(endpoint: HardenedEndpoint, method: string): number | null {
  if (endpoint === "register") return MAX_REGISTRATION_BODY_BYTES;
  if (endpoint === "token") return MAX_FORM_BODY_BYTES;
  if (endpoint === "authorize" && method === "POST") return MAX_FORM_BODY_BYTES;
  return null;
}

/**
 * Apply rate limiting, body caps, no-store and the client-record TTL around
 * the OAuth provider handler. Non-hardened requests pass straight through.
 * For a hardened request, in order:
 *
 *  - rate limit (429 before the handler, using the endpoint's own bucket);
 *  - body cap (413 before the handler; see {@link readBodyCapped}). The body
 *    is read once, under the cap, and the handler receives a copy of the
 *    request rebuilt from those bytes (same method, URL and headers), so
 *    nothing is tee'd or buffered twice;
 *  - `POST /register`: the redirect-URI rule (400 before the handler; see
 *    {@link validateRegistrationRedirectUris});
 *  - the handler;
 *  - `/register` and `/token` responses get no-store headers; a successful
 *    `/register` sets the new client's record to `clientTtl.registeredSeconds`
 *    and a 200 `/token` renews it to `clientTtl.activeSeconds`
 *    ({@link refreshClientTtl}) — for `grant_type` `authorization_code` or
 *    `refresh_token` only, not a revocation. `/authorize` and `/callback`
 *    responses pass through unchanged.
 *
 * A request whose path holds a malformed percent-escape is refused 400 before
 * anything else ({@link decodedPathname}).
 */
export async function enforceOAuthHardening(
  request: Request,
  store: RateLimitStore,
  cfg: HardeningConfig,
  nowMs: number,
  handler: (request: Request) => Promise<Response>,
): Promise<Response> {
  // A path that does not percent-decode is refused rather than passed through
  // unclassified (Hono would route a partly decoded form of it).
  const pathname = decodedPathname(request);
  if (pathname === null) return malformedPathResponse();
  const endpoint = classifyDecoded(pathname, request.method);
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

  let forward = request;
  let bodyText = "";
  const cap = bodyCapFor(endpoint, request.method);
  if (cap !== null && request.body !== null) {
    const read = await readBodyCapped(request, cap);
    if (!read.ok) return payloadTooLargeResponse();
    bodyText = read.text;
    forward = new Request(request, { body: read.bytes });
  }

  if (endpoint === "authorize" || endpoint === "callback") return handler(forward);

  if (endpoint === "register") {
    const refusal = validateRegistrationRedirectUris(bodyText);
    if (refusal) return refusal;
  }

  const response = await handler(forward);

  if (endpoint === "register" && response.ok) {
    // The body is consumed to read client_id, so rebuild the response from
    // its text before returning.
    const text = await response.text();
    const clientId = registeredClientId(text);
    if (clientId) await refreshClientTtl(store, clientId, cfg.clientTtl.registeredSeconds);
    return withNoStore(
      new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      }),
    );
  }

  // Only a code exchange or a refresh is client activity: the library answers
  // a revocation (`token=` and no grant_type) with 200 even for a junk token,
  // so renewing on it would let anyone keep a public client alive.
  // The form is read with URLSearchParams, so renew only when the body is
  // exactly what that parser sees: the library accepts any Content-Type that
  // *includes* the urlencoded type and parses it with formData(), so a
  // multipart body could otherwise name one client here and another there.
  if (
    endpoint === "token" &&
    response.status === 200 &&
    isUrlEncodedForm(request) &&
    isRenewingGrant(bodyText)
  ) {
    const clientId = tokenRequestClientId(request, bodyText);
    if (clientId) await refreshClientTtl(store, clientId, cfg.clientTtl.activeSeconds);
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
