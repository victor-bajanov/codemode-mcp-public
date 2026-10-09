import { DurableObject } from "cloudflare:workers";
import type { ApiProvider } from "./api-provider";
import { resolveEndpoints } from "./config";
import {
  getOrRefreshAccessToken,
  hashRefreshToken,
  type GrantSlot,
  type RefreshTokenStorage,
} from "./refresh";
import { encryptSlot, decryptSlot, type SealedSlot } from "./encrypt-slot";

const KV_KEY_PREFIX = "token-slot:";

/** Per-grant slots are rewritten (and the TTL refreshed) on every rotation;
 *  a slot left behind by a grant that is never used again ages out. */
const SLOT_TTL_SECONDS = 180 * 24 * 60 * 60;

/** Thrown (before any upstream call) when a rotating provider's per-grant
 *  slot cannot be decrypted. Reseeding from the grant's original refresh
 *  token would only present a token the upstream has already rotated away. */
const REAUTH_REQUIRED_MESSAGE =
  "Upstream connection needs re-authorisation: this grant's stored token could not be read. " +
  "Reconnect this MCP server to sign in again.";

export interface TokenBrokerArgs {
  /** OAuth subject (props.userId from the provider's audit.principalIdAccessor).
   *  Used as the DO instance name (via idFromName) and as the first part of
   *  the KV slot key `token-slot:<userId>:<sha256(refreshToken)>`. */
  userId: string;
  /** The current value of props.refreshToken from OAuthProvider's encrypted
   *  grant. Used as the AES-KW wrapping token for the slot and (hashed) as
   *  the second part of the slot key, so each grant of one user has its own
   *  slot. Stable for the lifetime of a grant; changes only on user
   *  re-authentication. */
  refreshToken: string;
}

export interface TokenBrokerStub {
  getOrRefreshAccessToken(args: TokenBrokerArgs): Promise<string>;
}

interface BrokerEnv extends Record<string, unknown> {
  OAUTH_KV: KVNamespace;
}

/** Build the provider-specific TokenBrokerDO class. One instance per
 *  `userId` (via `env.TOKEN_BROKER.idFromName(userId)`) serialises all
 *  refresh-token rotation through the DO input gate. */
export function createTokenBrokerDO<
  P extends Record<string, unknown>,
  Env extends BrokerEnv,
>(provider: ApiProvider<P, Env>) {
  return class TokenBrokerDO extends DurableObject<Env> implements TokenBrokerStub {
    async getOrRefreshAccessToken(args: TokenBrokerArgs): Promise<string> {
      const rotation = provider.tokenRotation ?? "static";
      // One slot per grant: two MCP clients of the same user hold different
      // original refresh tokens, so they no longer overwrite each other's
      // rotated chain (F-5). The DO itself stays per `userId`.
      const seedKey = await hashRefreshToken(args.refreshToken);
      const kvKey = `${KV_KEY_PREFIX}${args.userId}:${seedKey}`;
      const legacyKey = `${KV_KEY_PREFIX}${args.userId}`;
      const raw = await this.env.OAUTH_KV.get(kvKey, { type: "json" }) as SealedSlot | null;

      let slot: GrantSlot | undefined;
      let migrated = false;
      if (raw) {
        slot = await decryptSlot<GrantSlot>(args.refreshToken, raw);
        // The key is derived from this grant's token, so `undefined` here
        // means the blob is corrupt. On a rotating provider the original
        // token is already spent; fail with a re-authorisation error rather
        // than reseeding a dead token. A static provider's token never
        // changes, so a cache miss and reseed is harmless.
        if (!slot && rotation === "rotating") {
          throw new Error(REAUTH_REQUIRED_MESSAGE);
        }
      } else {
        // Migration from the pre-F-5 single `token-slot:<userId>` slot. Adopt
        // it only if it is sealed under this grant's token; otherwise it
        // belongs to another grant, which migrates it on its own next call.
        const legacy = await this.env.OAUTH_KV.get(legacyKey, { type: "json" }) as SealedSlot | null;
        if (legacy) {
          slot = await decryptSlot<GrantSlot>(args.refreshToken, legacy);
          migrated = slot !== undefined;
        }
      }

      // In-memory storage shim: the underlying pure function reads/writes a
      // single key; we capture writes so we can encrypt + persist them
      // afterwards. Reads return the slot we already decrypted (if any).
      let nextSlot: GrantSlot | undefined = slot;
      const storage: RefreshTokenStorage = {
        async get<T>(_key: string): Promise<T | undefined> {
          return nextSlot as T | undefined;
        },
        async put<T>(_key: string, value: T): Promise<void> {
          nextSlot = value as GrantSlot;
        },
      };

      // Capture BEFORE the call: refresh.ts mutates the slot in place
      // (`slot.currentRefreshToken = json.refresh_token`), so reading this
      // field after the call would always see the post-rotation value and
      // the persistence gate below would never fire on a rotation.
      const prevRefreshToken = slot?.currentRefreshToken;

      const accessToken = await getOrRefreshAccessToken({
        storage,
        rotation,
        refreshToken: args.refreshToken,
        clientId: this.env[provider.oauth.clientIdSecretName] as unknown as string,
        clientSecret: this.env[provider.oauth.clientSecretSecretName] as unknown as string,
        tokenUrl: resolveEndpoints(provider, this.env as unknown as Record<string, unknown>).tokenUrl,
      });

      // Persist when the slot has gained or rotated its refresh token, or
      // was just adopted from the legacy key. `lastUsedAt`-only updates from
      // cache hits are intentionally suppressed (it's an LRU hint, not
      // security state) to avoid a KV write per request. An identity check
      // (`nextSlot !== slot`) would be wrong here: refresh.ts mutates the
      // existing slot in place, so the reference stays equal even after a
      // rotation. Every write refreshes the TTL, so a rotating chain in use
      // keeps renewing it while an orphaned per-grant slot ages out.
      if (nextSlot && (migrated || nextSlot.currentRefreshToken !== prevRefreshToken)) {
        const sealed = await encryptSlot(args.refreshToken, nextSlot);
        await this.env.OAUTH_KV.put(kvKey, JSON.stringify(sealed), { expirationTtl: SLOT_TTL_SECONDS });
        // Only after the per-grant copy is safely written.
        if (migrated) await this.env.OAUTH_KV.delete(legacyKey);
      }

      return accessToken;
    }
  };
}
