/**
 * Typed env-flag accessors and boot-time secret assertion for scaffold.
 *
 * All helpers accept narrow structural env shapes so callers (and tests)
 * don't have to construct a full `ProviderEnv` to use them.
 */

import type { StagingConfig } from "./staging/types";

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

export interface OAuthRateLimitConfig {
  limit: number;
  windowSeconds: number;
}

/** Per-endpoint rate-limit knobs for the two hardened OAuth endpoints. */
export interface OAuthRateLimits {
  register: OAuthRateLimitConfig;
  token: OAuthRateLimitConfig;
}

/**
 * Read the rate-limit knobs applied to the two library-owned OAuth endpoints,
 * configured independently so the aggressive DCR clamp does not throttle normal
 * token exchange:
 *
 *   POST /register — `OAUTH_REGISTER_RATE_LIMIT` requests per
 *     `OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 1/300s).
 *   POST /token    — `OAUTH_TOKEN_RATE_LIMIT` requests per
 *     `OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 20/60s).
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
  };
}

// --- OAuth inactive-client sweep ---

// A dynamically-registered client that never completed an authorization (no
// `grant:*`) and has aged past this threshold is reaped by the scheduled sweep.
// 30 days by default — comfortably longer than any real authorization flow, so
// only abandoned/attacker registrations are collected.
const DEFAULT_OAUTH_CLIENT_TTL_SECONDS = 30 * 24 * 60 * 60; // 2_592_000

/**
 * Read the inactive-client TTL (seconds) governing the OAuth client sweep.
 * `OAUTH_CLIENT_TTL_SECONDS`, default 30 days. An ungranted `client:*` older
 * than this is eligible for reaping (see `oauth-client-sweep.ts`).
 */
export function readOAuthClientTtlSeconds(env: Record<string, unknown>): number {
  return parsePositiveIntVar(env, "OAUTH_CLIENT_TTL_SECONDS", DEFAULT_OAUTH_CLIENT_TTL_SECONDS);
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
