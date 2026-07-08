/**
 * Scheduled sweep that bounds unbounded `client:*` growth in OAUTH_KV.
 *
 * `@cloudflare/workers-oauth-provider` stores every dynamically-registered
 * client under `client:<id>` with no expiration, so registrations are
 * permanent. The `/register` rate limiter caps the *rate* of registration but
 * not the *total* — a patient attacker can still accumulate pre-positioned
 * phishing clients over time (AUTH-VULN-01 residual). This sweep reaps the
 * adversarial tail while never touching a live integration.
 *
 * Reap rule — a `client:<id>` is deleted only when ALL hold:
 *   1. No `grant:*` references it. A real Claude.ai client that completed
 *      authorization has a matching `grant:<userId>:<grantId>` whose value
 *      carries `clientId`; an abandoned/attacker registration that never
 *      finished the flow has none.
 *   2. It carries a scaffold `clientreg:<id>` registration stamp (written at the
 *      `/register` boundary — see `oauth-hardening.ts`). Clients with no stamp
 *      are left alone: we never reap a client we cannot age, which also means a
 *      just-registered client whose stamp write is still propagating is safe.
 *   3. The stamp is older than the configured inactive-client TTL. Fresh
 *      ungranted clients (mid-authorization) are within the window and kept.
 *
 * Both `client:<id>` and its `clientreg:<id>` stamp are removed on reap.
 */

/** Minimal KV surface the sweep needs; structurally satisfied by KVNamespace. */
export interface ClientSweepKv {
  list(options: {
    prefix: string;
    cursor?: string;
  }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string }>;
  get(key: string): Promise<string | null>;
  delete(key: string): Promise<void>;
}

export interface ClientSweepConfig {
  /** Ungranted clients older than this (seconds) are eligible for reaping. */
  clientTtlSeconds: number;
  /** Current time in ms (injectable for tests). */
  nowMs: number;
  /** When true, compute the reap set and counts but delete nothing. */
  dryRun?: boolean;
}

export interface ClientSweepResult {
  /** Total `client:*` keys scanned. */
  scannedClients: number;
  /** Distinct clientIds referenced by some `grant:*` (kept, never reaped). */
  grantedClients: number;
  /** Ungranted clients that carried a stamp (aging candidates). */
  stampedClients: number;
  /** Clients actually reaped (or, in dryRun, that would have been). */
  reapedClients: number;
}

const CLIENT_PREFIX = "client:";
const GRANT_PREFIX = "grant:";
const STAMP_PREFIX = "clientreg:";

/** Collect every key name under a prefix, following pagination cursors. */
async function listAllKeys(kv: ClientSweepKv, prefix: string): Promise<string[]> {
  const names: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list(cursor ? { prefix, cursor } : { prefix });
    for (const k of page.keys) names.push(k.name);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return names;
}

/** Parse a numeric `registeredAt` from a stamp value, or null if unusable. */
function registeredAtFromStamp(raw: string | null): number | null {
  if (!raw) return null;
  try {
    const at = (JSON.parse(raw) as { registeredAt?: unknown }).registeredAt;
    return typeof at === "number" && Number.isFinite(at) ? at : null;
  } catch {
    return null;
  }
}

export async function runClientSweep(
  kv: ClientSweepKv,
  cfg: ClientSweepConfig,
): Promise<ClientSweepResult> {
  // 1. Build the set of clientIds that have completed an authorization.
  const grantKeys = await listAllKeys(kv, GRANT_PREFIX);
  const granted = new Set<string>();
  for (const gk of grantKeys) {
    const raw = await kv.get(gk);
    if (!raw) continue;
    try {
      const clientId = (JSON.parse(raw) as { clientId?: unknown }).clientId;
      if (typeof clientId === "string" && clientId.length > 0) granted.add(clientId);
    } catch {
      /* malformed grant value — ignore, err toward keeping clients */
    }
  }

  // 2. Reap ungranted, stamped, aged clients.
  const clientKeys = await listAllKeys(kv, CLIENT_PREFIX);
  const ttlMs = cfg.clientTtlSeconds * 1000;
  let stampedClients = 0;
  let reapedClients = 0;
  for (const ck of clientKeys) {
    const clientId = ck.slice(CLIENT_PREFIX.length);
    if (granted.has(clientId)) continue;
    const registeredAt = registeredAtFromStamp(await kv.get(`${STAMP_PREFIX}${clientId}`));
    if (registeredAt === null) continue; // unstamped/legacy — never reap
    stampedClients += 1;
    if (cfg.nowMs - registeredAt <= ttlMs) continue; // still within TTL — keep
    if (!cfg.dryRun) {
      await kv.delete(ck);
      await kv.delete(`${STAMP_PREFIX}${clientId}`);
    }
    reapedClients += 1;
  }

  return {
    scannedClients: clientKeys.length,
    grantedClients: granted.size,
    stampedClients,
    reapedClients,
  };
}
