import { DurableObject } from "cloudflare:workers";
import type { ApiProvider, TokenRotation } from "./api-provider";
import { resolveEndpoints } from "./config";
import {
  getOrRefreshAccessToken,
  REFRESH_HARD_CAP_MS,
  REFRESH_TIMEOUT_MS,
  RefreshFailedError,
  type GrantSlot,
  type RefreshTokenStorage,
} from "./refresh";
import { decryptSlot, encryptSlot, type SealedSlot } from "./encrypt-slot";
import {
  grantSlotKey,
  KV_KEY_PREFIX,
  legacySlotKey,
  putSealedGrantSlot,
  SLOT_TTL_SECONDS,
} from "./grant-slot";

/** Thrown (before any upstream call) when a rotating provider's per-grant
 *  slot cannot be decrypted. Reseeding from the grant's original refresh
 *  token would only present a token the upstream has already rotated away. */
const REAUTH_REQUIRED_MESSAGE =
  "Upstream connection needs re-authorisation: this grant's stored token could not be read. " +
  "Reconnect this MCP server to sign in again.";

/** Thrown when a refreshed slot cannot be sealed for storage. The call fails
 *  rather than hand out a token whose rotated chain was never recorded. */
const SAVE_FAILED_MESSAGE =
  "Upstream token could not be saved. Retry the call; if it keeps failing, reconnect this MCP server.";

const SLOT_TTL_MS = SLOT_TTL_SECONDS * 1000;

/** When the prune alarm finds an expired slot whose grant is mid-refresh, it
 *  leaves it and looks again this much later. */
const PRUNE_RETRY_MS = 60_000;

/** Most keys one Durable Object `storage.delete` call accepts. */
const DELETE_BATCH = 128;

/** One grant's slot in the broker's Durable Object storage, under the same
 *  key as its KV copy. `sealed` is exactly what KV holds (sealed under the
 *  grant's original refresh token), so a storage dump alone exposes no live
 *  token. `writtenAt` (epoch ms) drives pruning; it is not secret. */
interface StoredSlot {
  sealed: SealedSlot;
  writtenAt: number;
}

export interface TokenBrokerArgs {
  /** OAuth subject (props.userId from the provider's audit.principalIdAccessor).
   *  Used as the DO instance name (via idFromName) and as the first part of
   *  the slot key `token-slot:<userId>:<sha256(refreshToken)>`. */
  userId: string;
  /** The current value of props.refreshToken from OAuthProvider's encrypted
   *  grant. Used as the AES-KW wrapping token for the slot and (hashed) as
   *  the second part of the slot key, so each grant of one user has its own
   *  slot. Stable for the lifetime of a grant; changes only on user
   *  re-authentication. */
  refreshToken: string;
}

/** The broker's refresh deadlines. Both are injectable for tests. */
export interface TokenBrokerDeadlines {
  /** Static providers: when the refresh POST is aborted. Rotating
   *  providers: how long a call waits for its grant's flight. Either way the
   *  call fails with `Refresh timed out after <ms> ms`. Defaults to
   *  {@link REFRESH_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Rotating providers only: when each refresh POST of a flight is aborted.
   *  Defaults to {@link REFRESH_HARD_CAP_MS}. */
  hardCapMs?: number;
}

export interface TokenBrokerStub {
  getOrRefreshAccessToken(args: TokenBrokerArgs): Promise<string>;
}

interface BrokerEnv extends Record<string, unknown> {
  OAUTH_KV: KVNamespace;
}

/** Where `#run` found the grant's slot. */
type SlotSource = "storage" | "kv" | "legacy" | "none";

interface ReadSlot {
  slot: GrantSlot | undefined;
  source: SlotSource;
}

/** Build the provider-specific TokenBrokerDO class. One instance per
 *  `userId` (via `env.TOKEN_BROKER.idFromName(userId)`) owns every refresh for
 *  that user's grants.
 *
 *  The DO's own storage (`ctx.storage`) is the authority for each grant's
 *  slot: it is strongly consistent and survives eviction, so a new instance
 *  always reads the latest rotated refresh token. KV can't be: a broker read
 *  primes the colo's KV cache, which a later write doesn't invalidate, so
 *  after an eviction KV can hand back the pre-rotation slot for up to its
 *  cache TTL. KV is read only on a storage miss: that is how the `/callback`
 *  seed (written to KV, outside the DO) and slots written before storage
 *  became the authority reach the DO. Each is adopted into storage on first
 *  use. KV still gets a best-effort copy on every rotation. KV is also read
 *  once, after the upstream rejects a storage slot's refresh token
 *  (`invalid_grant`), to pick up a chain a rolled-back KV-only broker
 *  rotated: the KV chain is adopted only if the upstream then accepts its
 *  token (or its access token is still valid).
 *
 *  The DO input gate does NOT serialise refreshes: it only holds new events
 *  while the DO awaits its own storage, and this class also awaits KV and the
 *  upstream fetch, during which other calls run. Instead each grant gets a
 *  single in-flight refresh (`#inflight`): concurrent callers for one grant
 *  share one upstream request and its result, while different grants proceed
 *  independently.
 *
 *  Refreshes have deadlines, so a token endpoint that never answers can't
 *  hold a grant's flight open. A static provider's POST is aborted at
 *  `timeoutMs` (REFRESH_TIMEOUT_MS, 30 s). A rotating provider's can't be:
 *  its refresh token is single-use, and an abort after the upstream has
 *  committed a rotation would lose the new chain. So its callers stop
 *  waiting at `timeoutMs` (a soft deadline, per call), while the flight runs
 *  on, still registered in `#inflight`, until its POST answers or reaches
 *  `hardCapMs` (REFRESH_HARD_CAP_MS, 5 min). A late answer is persisted like
 *  any other, and a call in the late window joins the flight rather than
 *  present the token the upstream is spending.
 *
 *  Storage stays bounded: the DO alarm deletes a slot not written for
 *  SLOT_TTL_SECONDS (the KV TTL). An active grant is written at least once
 *  per access-token lifetime, so that means "not used for the slot TTL". */
export function createTokenBrokerDO<
  P extends Record<string, unknown>,
  Env extends BrokerEnv,
>(provider: ApiProvider<P, Env>, deadlines: TokenBrokerDeadlines = {}) {
  const rotation: TokenRotation = provider.tokenRotation ?? "static";
  const timeoutMs = deadlines.timeoutMs ?? REFRESH_TIMEOUT_MS;
  // Every POST of a rotating flight gets the full cap, the rollback-recovery
  // retry included: aborting either one can lose a rotation, and the retry
  // starts only after the first POST has settled, so a flight is still
  // bounded (at two caps).
  const postTimeoutMs = rotation === "rotating" ? (deadlines.hardCapMs ?? REFRESH_HARD_CAP_MS) : timeoutMs;

  return class TokenBrokerDO extends DurableObject<Env> implements TokenBrokerStub {
    /** The running read → refresh → persist sequence per grant slot key.
     *  Private fields are not part of the DO's RPC surface. */
    #inflight = new Map<string, Promise<string>>();

    async getOrRefreshAccessToken(args: TokenBrokerArgs): Promise<string> {
      // One slot per grant: two MCP clients of the same user hold different
      // original refresh tokens, so they no longer overwrite each other's
      // rotated chain (F-5). The DO itself stays per `userId`.
      const key = await grantSlotKey(args.userId, args.refreshToken);
      // No `await` between the check and the set: a second caller for this
      // grant must see the first one's flight. Errors are never cached; the
      // entry is removed when the flight settles either way, never when a
      // caller stops waiting.
      let flight = this.#inflight.get(key);
      if (!flight) {
        flight = this.#run(args, key).finally(() => {
          this.#inflight.delete(key);
        });
        this.#inflight.set(key, flight);
        // An outbound fetch holds off the object's eviction (up to 15 min),
        // and so does a waitUntil promise from compatibility date 2026-10-01
        // (the apps are on an earlier date; see SECURITY.md §6), so a flight
        // outliving its callers can still persist. The waiters get the
        // flight's error; the runtime gets none to report.
        this.ctx.waitUntil(flight.then(() => undefined, () => undefined));
      }
      return rotation === "rotating" ? waitAtMost(flight, timeoutMs) : flight;
    }

    /** Delete slots not written for a slot TTL, then re-arm for the oldest
     *  survivor. A slot whose grant is mid-refresh is left for a later pass:
     *  its flight read it before this alarm ran and will rewrite it. */
    async alarm(): Promise<void> {
      const now = Date.now();
      const entries = await this.ctx.storage.list<StoredSlot>({ prefix: KV_KEY_PREFIX });
      const expired: string[] = [];
      let next = Infinity;
      for (const [key, value] of entries) {
        const writtenAt = typeof value?.writtenAt === "number" ? value.writtenAt : 0;
        const expiresAt = writtenAt + SLOT_TTL_MS;
        if (expiresAt > now) next = Math.min(next, expiresAt);
        else expired.push(key);
      }
      // Deleted in batches (the runtime takes at most DELETE_BATCH keys per
      // call). A flight can start while an earlier batch is awaited, so each
      // batch re-checks `#inflight` with no `await` between the check and its
      // delete: the flights checked are the flights running when that delete
      // is issued. A call still awaiting its slot key has not joined
      // `#inflight` yet; if its slot is pruned it takes the storage-miss
      // path, which is the intended "unused for a slot TTL" outcome.
      for (let i = 0; i < expired.length; i += DELETE_BATCH) {
        const batch: string[] = [];
        for (const key of expired.slice(i, i + DELETE_BATCH)) {
          if (this.#inflight.has(key)) next = Math.min(next, now + PRUNE_RETRY_MS);
          else batch.push(key);
        }
        if (batch.length > 0) await this.ctx.storage.delete(batch);
      }
      if (next !== Infinity) await this.ctx.storage.setAlarm(next);
    }

    async #run(args: TokenBrokerArgs, key: string): Promise<string> {
      const legacyKey = legacySlotKey(args.userId);
      const read = await this.#readSlot(args, key, legacyKey, rotation);
      // Captured before the call: refresh.ts mutates the slot in place.
      const rejectedRefreshToken = read.slot?.currentRefreshToken;
      try {
        return await this.#refreshAndPersist(args, key, legacyKey, rotation, read);
      } catch (err) {
        // A rollback to a KV-only broker rotates the chain in KV only, so on
        // redeploy storage can hold a token the upstream has spent. Only that
        // case is recovered: a rotating grant whose storage slot the upstream
        // just rejected. Every other failure (timeouts, 5xx, other codes,
        // persist failures, slots that came from KV, which was just read)
        // propagates unchanged.
        if (
          rotation !== "rotating"
          || read.source !== "storage"
          || !(err instanceof RefreshFailedError)
          || err.code !== "invalid_grant"
        ) throw err;
        const recovered = await this.#readKvForRecovery(args, key, rejectedRefreshToken);
        if (!recovered) throw err;
        // No token material and no error object in the log.
        console.warn(`${provider.displayName} token slot recovered from KV`);
        // One retry, with no recovery of its own: if the upstream rejects
        // the KV chain too, that error propagates and nothing is written.
        return this.#refreshAndPersist(args, key, legacyKey, rotation, { slot: recovered, source: "kv" });
      }
    }

    /** Refresh (or serve from cache) the slot `#readSlot` found, then persist
     *  the result to storage and mirror a changed chain to KV. */
    async #refreshAndPersist(
      args: TokenBrokerArgs,
      key: string,
      legacyKey: string,
      rotation: TokenRotation,
      { slot, source }: ReadSlot,
    ): Promise<string> {
      // In-memory storage shim: the underlying pure function reads/writes a
      // single key; we capture writes so we can seal + persist them
      // afterwards. Reads return the slot we already decrypted (if any).
      let nextSlot: GrantSlot | undefined = slot;
      const shim: RefreshTokenStorage = {
        async get<T>(_key: string): Promise<T | undefined> {
          return nextSlot as T | undefined;
        },
        async put<T>(_key: string, value: T): Promise<void> {
          nextSlot = value as GrantSlot;
        },
      };

      // Capture BEFORE the call: refresh.ts mutates the slot in place
      // (`slot.currentRefreshToken = json.refresh_token`), so reading these
      // fields after the call would always see the post-refresh values.
      const prevRefreshToken = slot?.currentRefreshToken;
      const prevAccessToken = slot?.accessToken;
      const prevExpiresAt = slot?.accessExpiresAt;

      const accessToken = await getOrRefreshAccessToken({
        storage: shim,
        rotation,
        refreshToken: args.refreshToken,
        clientId: this.env[provider.oauth.clientIdSecretName] as unknown as string,
        clientSecret: this.env[provider.oauth.clientSecretSecretName] as unknown as string,
        tokenUrl: resolveEndpoints(provider, this.env as unknown as Record<string, unknown>).tokenUrl,
        timeoutMs: postTimeoutMs,
      });
      if (!nextSlot) return accessToken;

      // The slot gained or rotated its refresh token (always true for a
      // grant with no slot before this call).
      const chainChanged = nextSlot.currentRefreshToken !== prevRefreshToken;
      const refreshed = chainChanged
        || nextSlot.accessToken !== prevAccessToken
        || nextSlot.accessExpiresAt !== prevExpiresAt;
      // Storage is written when the slot came from anywhere else (an
      // adoption) or a refresh changed it. A cache hit only bumps
      // `lastUsedAt`, an LRU hint, and is not written: no storage write per
      // request.
      if (source === "storage" && !refreshed) return accessToken;

      // The chain must be durably recorded before the token is handed out:
      // after a rotation the upstream has already spent the old refresh
      // token. A seal or storage failure fails the call (a failed storage
      // write also resets the DO via its output gate). Logs carry no token
      // material and no error object.
      let sealed: SealedSlot;
      try {
        sealed = await encryptSlot(args.refreshToken, nextSlot);
      } catch {
        console.error(`${provider.displayName} token slot seal failed`);
        throw new Error(SAVE_FAILED_MESSAGE);
      }

      // The KV copy is written first, best effort. It is written when the
      // chain changed or a legacy slot was adopted (renewing its TTL), so a
      // rollback to a KV-only broker finds the live chain; a slot adopted
      // from KV with no change is already there. Writing it before storage
      // means a storage write that fails (or a reset) after an upstream
      // rotation doesn't lose the new chain: storage keeps the spent token,
      // and the next call recovers the chain from KV after the upstream
      // rejects it. KV can therefore lead storage by one rotation; that is
      // safe because recovery adopts KV only once the upstream accepts its
      // token or its access token is still valid, and reads are unchanged
      // (KV is never preferred over storage).
      // A failure is logged and not retried.
      if (chainChanged || source === "legacy") {
        try {
          await putSealedGrantSlot(this.env.OAUTH_KV, key, sealed);
        } catch {
          console.error(`${provider.displayName} token slot KV write failed`);
        }
      }
      const now = Date.now();
      await this.ctx.storage.put<StoredSlot>(key, { sealed, writtenAt: now });
      await this.#armPrune(now);

      // The legacy slot is now in storage, which this grant reads first, so
      // it has nothing left to give: delete it whatever happened to the KV
      // copy. Best effort and not retried: a leftover legacy slot is inert
      // (no other grant can decrypt it, and this one never reads it again).
      if (source === "legacy") {
        try {
          await this.env.OAUTH_KV.delete(legacyKey);
        } catch {
          console.error(`${provider.displayName} legacy token slot delete failed`);
        }
      }
      return accessToken;
    }

    /** Arm the prune alarm one slot TTL after this write, unless an alarm is
     *  already set (it is then no later: every alarm is an earlier write's
     *  `writtenAt` plus the TTL, or a prune retry). */
    async #armPrune(writtenAt: number): Promise<void> {
      if ((await this.ctx.storage.getAlarm()) === null) {
        await this.ctx.storage.setAlarm(writtenAt + SLOT_TTL_MS);
      }
    }

    /** Read the grant's slot: DO storage first, then (on a storage miss
     *  only) the per-grant KV key, then the pre-F-5 legacy KV key. */
    async #readSlot(
      args: TokenBrokerArgs,
      key: string,
      legacyKey: string,
      rotation: TokenRotation,
    ): Promise<ReadSlot> {
      const stored = await this.ctx.storage.get<StoredSlot>(key);
      if (stored) {
        // The key is derived from this grant's token, so `undefined` here
        // means the record is corrupt. Storage is the authority: never fall
        // back to KV here, whose cache can serve a pre-rotation slot. KV is
        // consulted against a storage slot only by `#run`, after the
        // upstream has rejected this slot's refresh token.
        const slot = await decryptSlot<GrantSlot>(args.refreshToken, stored.sealed);
        if (!slot && rotation === "rotating") throw new Error(REAUTH_REQUIRED_MESSAGE);
        return { slot, source: slot ? "storage" : "none" };
      }
      return this.#readKvSlot(args, key, legacyKey, rotation);
    }

    /** The grant's KV slot, if it holds a refresh token other than the one
     *  the upstream just rejected; otherwise `undefined`. Reads only the
     *  per-grant key: the legacy key was adopted and deleted when this grant
     *  first reached storage. A blob that doesn't decrypt under this grant's
     *  token, or carries no refresh token, is `undefined` too: recovery never
     *  presents another grant's chain. So is a failed KV read, so the caller
     *  sees the upstream's `invalid_grant`, not a KV error. */
    async #readKvForRecovery(
      args: TokenBrokerArgs,
      key: string,
      rejectedRefreshToken: string | undefined,
    ): Promise<GrantSlot | undefined> {
      let raw: SealedSlot | null;
      try {
        raw = await this.env.OAUTH_KV.get(key, { type: "json" }) as SealedSlot | null;
      } catch {
        return undefined;
      }
      if (!raw) return undefined;
      const slot = await decryptSlot<GrantSlot>(args.refreshToken, raw);
      if (
        !slot
        || typeof slot.currentRefreshToken !== "string"
        || slot.currentRefreshToken === rejectedRefreshToken
      ) return undefined;
      return slot;
    }

    /** Read and decrypt the grant's slot from KV, falling back to the
     *  pre-F-5 legacy key (adopted only if sealed under this grant). */
    async #readKvSlot(
      args: TokenBrokerArgs,
      key: string,
      legacyKey: string,
      rotation: TokenRotation,
    ): Promise<ReadSlot> {
      const raw = await this.env.OAUTH_KV.get(key, { type: "json" }) as SealedSlot | null;
      if (raw) {
        const slot = await decryptSlot<GrantSlot>(args.refreshToken, raw);
        // Corrupt blob. On a rotating provider the original token is already
        // spent; fail with a re-authorisation error rather than reseeding a
        // dead token. A static provider's token never changes, so a cache
        // miss and reseed is harmless.
        if (!slot && rotation === "rotating") {
          throw new Error(REAUTH_REQUIRED_MESSAGE);
        }
        return { slot, source: slot ? "kv" : "none" };
      }
      // Migration from the pre-F-5 single `token-slot:<userId>` slot. Adopt
      // it only if it is sealed under this grant's token; otherwise it
      // belongs to another grant, which migrates it on its own next call.
      const legacy = await this.env.OAUTH_KV.get(legacyKey, { type: "json" }) as SealedSlot | null;
      if (!legacy) return { slot: undefined, source: "none" };
      const slot = await decryptSlot<GrantSlot>(args.refreshToken, legacy);
      return { slot, source: slot ? "legacy" : "none" };
    }
  };
}

/** `flight`'s outcome, or `Refresh timed out after <ms> ms` if it hasn't
 *  settled within `ms`. The flight itself runs on either way. */
function waitAtMost<T>(flight: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Refresh timed out after ${ms} ms`)), ms);
    flight.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err: unknown) => { clearTimeout(timer); reject(err); },
    );
  });
}
