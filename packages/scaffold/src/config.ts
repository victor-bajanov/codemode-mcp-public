/**
 * Typed env-flag accessors and boot-time secret assertion for scaffold.
 *
 * All helpers accept narrow structural env shapes so callers (and tests)
 * don't have to construct a full `ProviderEnv` to use them.
 */

import {
  DEFAULT_COMPOSE_MAX_BYTES,
  DEFAULT_FETCH_MAX_USES,
  DEFAULT_GETFILE_MAX_BYTES,
  DEFAULT_MAX_CONCURRENT_TRANSFERS,
  DEFAULT_TRANSFER_TIMEOUT_MS,
  type StagingConfig,
} from "./staging/types";
import type { HardeningConfig } from "./oauth-hardening";
import { MCP_REFRESH_TOKEN_TTL_SECONDS } from "./oauth-provider-options";

export function allowPiiInLogs(env: { ALLOW_PII_IN_LOGS?: string }): boolean {
  return env.ALLOW_PII_IN_LOGS === "true";
}

export function debugElicit(env: { DEBUG_ELICIT?: string }): boolean {
  return env.DEBUG_ELICIT === "true";
}

export function debugLog(
  env: { DEBUG_ELICIT?: string; ALLOW_PII_IN_LOGS?: string },
  marker: string,
  payload: Record<string, unknown>,
  opts?: { containsPii?: boolean },
): void {
  if (!debugElicit(env)) return;
  if (opts?.containsPii && !allowPiiInLogs(env)) {
    console.log(
      `DEBUG-ELICIT ${marker} <REDACTED: ALLOW_PII_IN_LOGS=false required to log this site>`,
    );
    return;
  }
  let s: string;
  try {
    s = JSON.stringify({ stage: marker, ts: new Date().toISOString(), ...payload });
  } catch {
    s = `<DEBUG-ELICIT serialization failed at ${marker}>`;
  }
  console.log(`DEBUG-ELICIT ${s}`);
}

export interface ScaffoldSecrets {
  COOKIE_ENCRYPTION_KEY?: string;
}

/**
 * Boot-time check that `COOKIE_ENCRYPTION_KEY` is present and at least 32
 * characters. The key signs the `/authorize` consent form tokens
 * (`oauth-consent.ts`, F-20), so a missing key would otherwise surface as an
 * opaque failure halfway through the consent flow; asserting it at the top of
 * every `fetch` fails the first request after a misconfigured deploy with an
 * actionable message instead. Rotating the key only voids consents in flight.
 */
export function assertSecrets(env: ScaffoldSecrets): void {
  const key = env.COOKIE_ENCRYPTION_KEY;
  if (typeof key !== "string" || key.length < 32) {
    throw new Error(
      "COOKIE_ENCRYPTION_KEY is missing or too short (require >=32 chars). " +
        "Set with: wrangler secret put COOKIE_ENCRYPTION_KEY",
    );
  }
}

// --- Staging attachments ---

const DEFAULT_UPLOAD_TTL_SECONDS = 300;
const DEFAULT_FETCH_TTL_SECONDS = 3600;
const DEFAULT_MAX_BYTES = 50 * 1024 * 1024;

/** Parse a positive-integer env var, falling back when unset/empty. */
function parsePositiveIntVar(
  env: Record<string, unknown>,
  name: string,
  fallback: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
    throw new Error(`${name}: must be a positive integer, got ${String(raw)}`);
  }
  return n;
}

export function readStagingConfig(env: Record<string, unknown>): StagingConfig {
  return {
    uploadTtlSeconds: parsePositiveIntVar(env, "STAGING_UPLOAD_TTL_SECONDS", DEFAULT_UPLOAD_TTL_SECONDS),
    fetchTtlSeconds: parsePositiveIntVar(env, "STAGING_FETCH_TTL_SECONDS", DEFAULT_FETCH_TTL_SECONDS),
    maxBytes: parsePositiveIntVar(env, "STAGING_MAX_BYTES", DEFAULT_MAX_BYTES),
    getFileMaxBytes: parsePositiveIntVar(env, "STAGING_GETFILE_MAX_BYTES", DEFAULT_GETFILE_MAX_BYTES),
    composeMaxBytes: parsePositiveIntVar(env, "STAGING_COMPOSE_MAX_BYTES", DEFAULT_COMPOSE_MAX_BYTES),
    maxConcurrentTransfers: parsePositiveIntVar(
      env,
      "STAGING_MAX_CONCURRENT_TRANSFERS",
      DEFAULT_MAX_CONCURRENT_TRANSFERS,
    ),
    transferTimeoutMs: parsePositiveIntVar(env, "STAGING_TRANSFER_TIMEOUT_MS", DEFAULT_TRANSFER_TIMEOUT_MS),
    fetchMaxUses: parsePositiveIntVar(env, "STAGING_FETCH_MAX_USES", DEFAULT_FETCH_MAX_USES),
  };
}

// --- /staging/* failure-budget throttle ---

// Failed `/staging/*` requests (403: missing bearer, unknown token or wrong
// handle) permitted per client per window before the endpoints answer 429
// without touching D1. Generous enough that a confused-but-legitimate client
// never trips it; tight enough to make bearer guessing pointless.
const DEFAULT_STAGING_FAILURE_RATE_LIMIT = 30;
const DEFAULT_STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS = 300;

/**
 * Read the `/staging/*` failure-budget knobs (F-13):
 * `STAGING_FAILURE_RATE_LIMIT` failures per
 * `STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS` per client (default 30/300 s).
 * Each var is optional; invalid values throw like the other positive-integer
 * vars.
 */
export function readStagingThrottleConfig(
  env: Record<string, unknown>,
): { limit: number; windowSeconds: number } {
  return {
    limit: parsePositiveIntVar(env, "STAGING_FAILURE_RATE_LIMIT", DEFAULT_STAGING_FAILURE_RATE_LIMIT),
    windowSeconds: parsePositiveIntVar(
      env,
      "STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS",
      DEFAULT_STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS,
    ),
  };
}

// --- OAuth endpoint hardening (rate limiting) ---

// Dynamic client registration (POST /register) is the higher-value abuse
// target: each accepted request mints a permanent client record, so the limit
// is deliberately aggressive (1 registration per 5 minutes per IP by default).
// Token exchange (POST /token) is a normal, repeatable part of every auth flow,
// so it gets a looser default (20 per minute per IP).
const DEFAULT_OAUTH_REGISTER_RATE_LIMIT = 1;
const DEFAULT_OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS = 300;
const DEFAULT_OAUTH_TOKEN_RATE_LIMIT = 20;
const DEFAULT_OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS = 60;
// The browser legs (A-3, 2026-11 review), public since Cloudflare Access was
// removed. One sign-in is one GET + one POST /authorize and one /callback, so
// 30 / 300 s allows 15 sign-ins per five minutes from one address. /callback
// is the tighter bucket because each one costs an upstream token request
// signed with the deployment's client secret.
const DEFAULT_OAUTH_AUTHORIZE_RATE_LIMIT = 30;
const DEFAULT_OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS = 300;
const DEFAULT_OAUTH_CALLBACK_RATE_LIMIT = 10;
const DEFAULT_OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS = 300;

export interface OAuthRateLimitConfig {
  limit: number;
  windowSeconds: number;
}

/** Per-endpoint rate-limit knobs for the four hardened OAuth endpoints. */
export interface OAuthRateLimits {
  register: OAuthRateLimitConfig;
  token: OAuthRateLimitConfig;
  authorize: OAuthRateLimitConfig;
  callback: OAuthRateLimitConfig;
}

/**
 * Read the rate-limit knobs applied to the OAuth endpoints, each configured
 * independently so the aggressive DCR clamp does not throttle normal token
 * exchange or the browser legs:
 *
 *   POST /register — `OAUTH_REGISTER_RATE_LIMIT` requests per
 *     `OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 1/300s).
 *   POST /token    — `OAUTH_TOKEN_RATE_LIMIT` requests per
 *     `OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 20/60s).
 *   GET/HEAD/POST /authorize — `OAUTH_AUTHORIZE_RATE_LIMIT` requests per
 *     `OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 30/300s).
 *   GET/HEAD /callback — `OAUTH_CALLBACK_RATE_LIMIT` requests per
 *     `OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 10/300s).
 *
 * Each var is optional; unset falls back to the default above.
 */
export function readOAuthRateLimitConfig(env: Record<string, unknown>): OAuthRateLimits {
  return {
    register: {
      limit: parsePositiveIntVar(env, "OAUTH_REGISTER_RATE_LIMIT", DEFAULT_OAUTH_REGISTER_RATE_LIMIT),
      windowSeconds: parsePositiveIntVar(
        env,
        "OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS,
      ),
    },
    token: {
      limit: parsePositiveIntVar(env, "OAUTH_TOKEN_RATE_LIMIT", DEFAULT_OAUTH_TOKEN_RATE_LIMIT),
      windowSeconds: parsePositiveIntVar(
        env,
        "OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS,
      ),
    },
    authorize: {
      limit: parsePositiveIntVar(env, "OAUTH_AUTHORIZE_RATE_LIMIT", DEFAULT_OAUTH_AUTHORIZE_RATE_LIMIT),
      windowSeconds: parsePositiveIntVar(
        env,
        "OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS,
      ),
    },
    callback: {
      limit: parsePositiveIntVar(env, "OAUTH_CALLBACK_RATE_LIMIT", DEFAULT_OAUTH_CALLBACK_RATE_LIMIT),
      windowSeconds: parsePositiveIntVar(
        env,
        "OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS,
      ),
    },
  };
}

// --- OAuth client-record lifetime ---

// The library's `client:<id>` record carries a KV TTL that the hardening
// wrapper sets (A-5, 2026-11 review; there is no sweep). A registration that
// is never used expires after this long; a successful `/token` call renews
// the record to the grant's lifetime plus this long again. 30 days by default.
const DEFAULT_OAUTH_CLIENT_TTL_SECONDS = 30 * 24 * 60 * 60; // 2_592_000
// Workers KV refuses an expirationTtl under 60 s; a smaller value would make
// every TTL renewal throw (caught and logged), so it is raised to 60.
const KV_MIN_EXPIRATION_TTL_SECONDS = 60;

/**
 * Read `OAUTH_CLIENT_TTL_SECONDS` (default 30 days): how long an unused
 * registration lives, and the grace a client keeps after its grant's
 * lifetime; values under 60 are raised to 60 (KV's minimum TTL). See
 * {@link readOAuthHardeningConfig}.
 */
export function readOAuthClientTtlSeconds(env: Record<string, unknown>): number {
  return Math.max(
    KV_MIN_EXPIRATION_TTL_SECONDS,
    parsePositiveIntVar(env, "OAUTH_CLIENT_TTL_SECONDS", DEFAULT_OAUTH_CLIENT_TTL_SECONDS),
  );
}

/**
 * The full configuration `enforceOAuthHardening` runs with: the four rate
 * limits ({@link readOAuthRateLimitConfig}) and the client-record TTLs —
 * `registeredSeconds` (set on a successful `/register`) is
 * `OAUTH_CLIENT_TTL_SECONDS`; `activeSeconds` (set on every successful
 * `/token`) is the grant lifetime (`MCP_REFRESH_TOKEN_TTL_SECONDS`, 90 days)
 * plus `OAUTH_CLIENT_TTL_SECONDS`, 120 days by default. A grant's last refresh
 * is at most 90 days after authorisation, so a client in use is never
 * forgotten while its grant lives, and keeps 30 days to re-authorise after.
 */
export function readOAuthHardeningConfig(env: Record<string, unknown>): HardeningConfig {
  const ttl = readOAuthClientTtlSeconds(env);
  return {
    ...readOAuthRateLimitConfig(env),
    clientTtl: {
      registeredSeconds: ttl,
      activeSeconds: MCP_REFRESH_TOKEN_TTL_SECONDS + ttl,
    },
  };
}

// --- Per-deployment backend endpoint overrides ---

/**
 * The four upstream URLs a provider talks to: the API base and the three OAuth
 * endpoints. Resolved from the static provider config, with optional per-env
 * overrides applied on top.
 */
export interface ResolvedEndpoints {
  apiBaseUrl: string;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string | undefined;
}

/** Wrangler `vars` keys a named env may set to repoint a worker at an isolated
 *  backend. Field name → override var name. */
const ENDPOINT_OVERRIDE_VARS = {
  apiBaseUrl: "API_BASE_URL_OVERRIDE",
  authorizeUrl: "OAUTH_AUTHORIZE_URL_OVERRIDE",
  tokenUrl: "OAUTH_TOKEN_URL_OVERRIDE",
  userInfoUrl: "OAUTH_USERINFO_URL_OVERRIDE",
} as const;

function overrideStr(env: Record<string, unknown>, name: string): string | undefined {
  const v = env[name];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/**
 * Resolve the upstream API + OAuth endpoints for a worker, applying optional
 * per-deployment overrides.
 *
 * The provider literal hardcodes prod URLs. A named wrangler env (e.g. `dev`)
 * repoints the worker at an isolated backend by setting the override vars in
 * its `[env.<name>].vars` block — without forking the provider config. Each
 * unset var falls back to the static provider value, so prod (which sets none)
 * and providers that never override (gmail/xero, whose backends are identical
 * across envs) are unaffected.
 */
export function resolveEndpoints(
  provider: {
    apiBaseUrl: string;
    oauth: { authorizeUrl: string; tokenUrl: string; userInfoUrl?: string };
  },
  env: Record<string, unknown>,
): ResolvedEndpoints {
  return {
    apiBaseUrl: overrideStr(env, ENDPOINT_OVERRIDE_VARS.apiBaseUrl) ?? provider.apiBaseUrl,
    authorizeUrl: overrideStr(env, ENDPOINT_OVERRIDE_VARS.authorizeUrl) ?? provider.oauth.authorizeUrl,
    tokenUrl: overrideStr(env, ENDPOINT_OVERRIDE_VARS.tokenUrl) ?? provider.oauth.tokenUrl,
    userInfoUrl: overrideStr(env, ENDPOINT_OVERRIDE_VARS.userInfoUrl) ?? provider.oauth.userInfoUrl,
  };
}
