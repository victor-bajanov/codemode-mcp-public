// The token broker's per-grant KV slot: key shape, TTL and the sign-in seed.
// Shared by the broker (token-broker.ts) and /callback (oauth-handler.ts) so
// the two can't drift on where a grant's slot lives or how long it lasts. No
// `cloudflare:workers` import: the OAuth handler runs in the plain worker.

import { encryptSlot, type SealedSlot } from "./encrypt-slot";
import { hashRefreshToken, type GrantSlot } from "./refresh";

/** Prefix of every grant slot key, in KV and in the broker's DO storage. */
export const KV_KEY_PREFIX = "token-slot:";

/** Per-grant slots are rewritten (and the TTL refreshed) on every rotation;
 *  a slot left behind by a grant that is never used again ages out. */
export const SLOT_TTL_SECONDS = 180 * 24 * 60 * 60;

/** `token-slot:<userId>:<sha256(refreshToken)>`: one slot per grant, where
 *  `refreshToken` is the grant's original (props) refresh token. */
export async function grantSlotKey(userId: string, refreshToken: string): Promise<string> {
  return `${KV_KEY_PREFIX}${userId}:${await hashRefreshToken(refreshToken)}`;
}

/** The pre-F-5 single slot per user, read only to migrate it. */
export function legacySlotKey(userId: string): string {
  return `${KV_KEY_PREFIX}${userId}`;
}

/** Write an already-sealed slot to the grant's KV key with the slot TTL.
 *  KV errors propagate. */
export async function putSealedGrantSlot(kv: KVNamespace, key: string, sealed: SealedSlot): Promise<void> {
  await kv.put(key, JSON.stringify(sealed), { expirationTtl: SLOT_TTL_SECONDS });
}

/** Seal `slot` under the grant's original refresh token and write it to the
 *  grant's KV key with the slot TTL (the sign-in seed's write path). KV and
 *  crypto errors propagate. */
export async function writeGrantSlot(
  kv: KVNamespace,
  userId: string,
  refreshToken: string,
  slot: GrantSlot,
): Promise<void> {
  const sealed = await encryptSlot(refreshToken, slot);
  await putSealedGrantSlot(kv, await grantSlotKey(userId, refreshToken), sealed);
}

export interface SeedGrantSlotArgs {
  /** The principal the broker is addressed by (see principal.ts). */
  userId: string;
  /** The code exchange's refresh token, which becomes props.refreshToken. */
  refreshToken: string;
  /** The code exchange's access token and lifetime, as the upstream sent them. */
  accessToken: unknown;
  expiresIn: unknown;
  /** Epoch ms. */
  now: number;
}

/** Write a new grant's slot with the code-exchange access token, so the
 *  broker's first call is a cache hit instead of a refresh. Returns false
 *  (writing nothing) when the access token or its lifetime is unusable; the
 *  broker then refreshes as it would for an unseeded grant. Overwrites an
 *  existing KV slot: a new refresh token means a new key, so that only
 *  happens when a static provider re-issues the same refresh token. The
 *  broker's Durable Object storage is the authority, though: while storage
 *  still holds that key the seed is ignored and the old access token is
 *  served until it expires (so, for example, a scope-upgrade re-consent
 *  only takes effect at the next refresh). KV and crypto errors propagate. */
export async function seedGrantSlot(kv: KVNamespace, args: SeedGrantSlotArgs): Promise<boolean> {
  const { accessToken, expiresIn } = args;
  if (typeof accessToken !== "string" || accessToken === "") return false;
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) return false;
  const slot: GrantSlot = {
    seedKey: await hashRefreshToken(args.refreshToken),
    currentRefreshToken: args.refreshToken,
    accessToken,
    accessExpiresAt: args.now + expiresIn * 1000,
    lastUsedAt: args.now,
  };
  await writeGrantSlot(kv, args.userId, args.refreshToken, slot);
  return true;
}
