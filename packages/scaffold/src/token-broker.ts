import { DurableObject } from "cloudflare:workers";
import type { ApiProvider } from "./api-provider";
import { getOrRefreshAccessToken, type GrantSlot, type RefreshTokenStorage } from "./refresh";
import { encryptSlot, decryptSlot, type SealedSlot } from "./encrypt-slot";

const KV_KEY_PREFIX = "token-slot:";

export interface TokenBrokerArgs {
  /** OAuth subject (props.userId from the provider's audit.principalIdAccessor).
   *  Used both as the DO instance name (via idFromName) and the KV slot key. */
  userId: string;
  /** The current value of props.refreshToken from OAuthProvider's encrypted
   *  grant. Used as the AES-KW wrapping token for the slot. Stable for the
   *  lifetime of a grant; changes only on user re-authentication. */
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
      const kvKey = `${KV_KEY_PREFIX}${args.userId}`;
      const raw = await this.env.OAUTH_KV.get(kvKey, { type: "json" }) as SealedSlot | null;

      let slot: GrantSlot | undefined;
      if (raw) {
        slot = await decryptSlot<GrantSlot>(args.refreshToken, raw);
        // `undefined` means the wrapping token changed (re-auth) or the blob
        // is corrupt — treat as cache miss and let the refresh path reseed.
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
        rotation: provider.tokenRotation ?? "static",
        refreshToken: args.refreshToken,
        clientId: this.env[provider.oauth.clientIdSecretName] as unknown as string,
        clientSecret: this.env[provider.oauth.clientSecretSecretName] as unknown as string,
        tokenUrl: provider.oauth.tokenUrl,
      });

      // Persist when the slot has gained or rotated its refresh token.
      // `lastUsedAt`-only updates from cache hits are intentionally
      // suppressed (it's an LRU hint, not security state) to avoid a KV
      // write per request. An identity check (`nextSlot !== slot`) would
      // be wrong here: refresh.ts mutates the existing slot in place, so
      // the reference stays equal even after a rotation.
      if (nextSlot && nextSlot.currentRefreshToken !== prevRefreshToken) {
        const sealed = await encryptSlot(args.refreshToken, nextSlot);
        await this.env.OAUTH_KV.put(kvKey, JSON.stringify(sealed));
      }

      return accessToken;
    }
  };
}
