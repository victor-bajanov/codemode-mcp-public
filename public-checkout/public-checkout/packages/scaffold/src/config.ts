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

export function readStagingConfig(env: Record<string, unknown>): StagingConfig {
  const parseIntVar = (name: string, fallback: number): number => {
    const raw = env[name];
    if (raw === undefined || raw === null || raw === "") return fallback;
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
      throw new Error(`${name}: must be a positive integer, got ${String(raw)}`);
    }
    return n;
  };
  return {
    uploadTtlSeconds: parseIntVar("STAGING_UPLOAD_TTL_SECONDS", DEFAULT_UPLOAD_TTL_SECONDS),
    fetchTtlSeconds: parseIntVar("STAGING_FETCH_TTL_SECONDS", DEFAULT_FETCH_TTL_SECONDS),
    maxBytes: parseIntVar("STAGING_MAX_BYTES", DEFAULT_MAX_BYTES),
  };
}
