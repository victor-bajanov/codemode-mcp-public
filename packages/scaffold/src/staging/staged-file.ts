// Staged-file primitives on the v2 (blockwise) at-rest format.
//
// Writers: a `BlockSource` yields plaintext in BLOCK_BYTES blocks; each block
// is sealed (block-format.ts) and written into a fixed-length sink that R2
// consumes as a stream, so no path ever holds the whole file as one buffer
// when its length is known up front.
//
// Readers: `createStagedFileOpener` resolves a `{ file_handle, token }`
// reference against D1 only; R2 is touched when the caller asks for the
// blocks, and every block is authenticated before it is handed on.
//
// Error messages never contain a token, a handle or file content.

import { GCM_TAG_BYTES, type StagingConfig, type StagingRow } from "./types";
import type { PutFileCapabilityDeps, PutFileResult } from "./putfile-capability";
import {
  BLOCK_BYTES,
  ENC_VERSION_V2,
  blockCount,
  blockPlainLength,
  ciphertextLength,
  decryptBlock,
  encryptBlock,
} from "./block-format";
import { decodeBase64Into, decodedLength, type Base64Alphabet } from "./codec";
import { deriveV2Key, sha256Bearer } from "./crypto";
import { insertClaimed, lookupByHash, markCorrupt } from "./repo";
import { createFixedLengthSink } from "./sinks";
import { tryAcquireUnknownLengthSlot } from "./unknown-length-slot";
import {
  decodeHandleBytes,
  decodeTokenSecret,
  mintFileHandle,
  mintToken,
  newR2Key,
  timingSafeEqualStrings,
} from "./tokens";

export interface StagedRef { file_handle: string; token: string }
export interface StagedFileMeta { byteLength: number; contentType: string; filename: string | null }
export interface OpenStagedFile {
  meta: StagedFileMeta;
  readBlocks(onBlock: (plain: Uint8Array, index: number) => Promise<void>): Promise<void>;
}
export type OpenStagedResult =
  | { ok: true; file: OpenStagedFile }
  | { ok: false; status: 400 | 403 | 409 | 410 | 500; message: string };

export interface StagedFileOpenerDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  now?: () => number;
}

/**
 * Plaintext in order, as BLOCK_BYTES-sized blocks except the last (an empty
 * input yields no block). `byteLength` is known up front or `null`. `read`
 * resolves with the total byte count and may be called once.
 */
export interface BlockSource {
  byteLength: number | null;
  read(onBlock: (plain: Uint8Array) => Promise<void>): Promise<number>;
}

/** The input passed the size cap. Maps to 413. */
export class StagingTooLarge extends Error {
  constructor(message = "payload too large") {
    super(message);
    this.name = "StagingTooLarge";
  }
}

/** A stream body ended short of, or ran past, its declared length. */
export class StagingBodyLengthMismatch extends Error {
  constructor(message = "body length does not match the declared length") {
    super(message);
    this.name = "StagingBodyLengthMismatch";
  }
}

/** The isolate's one unknown-length slot is taken. Maps to 503. */
export class StagingBusy extends Error {
  constructor(message = "busy: retry shortly, or send Content-Length") {
    super(message);
    this.name = "StagingBusy";
  }
}

/** The block source itself failed (e.g. the upstream body dropped). */
export class StagingSourceError extends Error {
  constructor(message = "upstream body read failed") {
    super(message);
    this.name = "StagingSourceError";
  }
}

/** A bounded stream read ran out of time; the reader was cancelled. */
export class StagingTimeout extends StagingSourceError {
  constructor(message = "body read timed out") {
    super(message);
    this.name = "StagingTimeout";
  }
}

/** Malformed input (bad base64). Maps to 400. */
export class StagingBadInput extends Error {
  constructor(message = "bad base64") {
    super(message);
    this.name = "StagingBadInput";
  }
}

function singleUse(): () => void {
  let used = false;
  return () => {
    if (used) throw new Error("block source already consumed");
    used = true;
  };
}

export function blockSourceFromBytes(bytes: Uint8Array): BlockSource {
  const claim = singleUse();
  return {
    byteLength: bytes.byteLength,
    async read(onBlock) {
      claim();
      for (let off = 0; off < bytes.byteLength; off += BLOCK_BYTES) {
        await onBlock(bytes.subarray(off, Math.min(bytes.byteLength, off + BLOCK_BYTES)));
      }
      return bytes.byteLength;
    },
  };
}

export function blockSourceFromStream(
  body: ReadableStream<Uint8Array>,
  contentLength: number | null,
  maxBytes: number,
  opts: { timeoutMs?: number } = {},
): BlockSource {
  const claim = singleUse();
  return {
    byteLength: contentLength,
    async read(onBlock) {
      claim();
      const reader = body.getReader();
      // Optional absolute bound on the whole read: on expiry the reader is
      // cancelled (a pending read then resolves `done`), and the flag turns
      // that into a StagingTimeout rather than a clean, truncated end.
      let timedOut = false;
      const timer =
        opts.timeoutMs === undefined
          ? undefined
          : setTimeout(() => {
              timedOut = true;
              reader.cancel(new StagingTimeout()).catch(() => {});
            }, opts.timeoutMs);
      try {
        return await readChunks();
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }

      async function readChunks(): Promise<number> {
        const fail = async (err: Error): Promise<never> => {
          try {
            await reader.cancel(err);
          } catch {
            /* ignore */
          }
          throw err;
        };
        if (contentLength !== null && contentLength > maxBytes) return fail(new StagingTooLarge());
        // Each block is a fresh buffer: consumers (the unknown-length writer)
        // may keep it.
        let block = new Uint8Array(BLOCK_BYTES);
        let fill = 0;
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (timedOut) throw new StagingTimeout();
          if (done) break;
          total += value.byteLength;
          if (total > maxBytes) return fail(new StagingTooLarge());
          if (contentLength !== null && total > contentLength) return fail(new StagingBodyLengthMismatch());
          let off = 0;
          while (off < value.byteLength) {
            const take = Math.min(BLOCK_BYTES - fill, value.byteLength - off);
            block.set(value.subarray(off, off + take), fill);
            fill += take;
            off += take;
            if (fill === BLOCK_BYTES) {
              await onBlock(block);
              block = new Uint8Array(BLOCK_BYTES);
              fill = 0;
            }
          }
        }
        if (timedOut) throw new StagingTimeout();
        if (contentLength !== null && total !== contentLength) throw new StagingBodyLengthMismatch();
        if (fill > 0) await onBlock(block.subarray(0, fill));
        return total;
      }
    },
  };
}

export function blockSourceFromBase64(
  src: string,
  start: number,
  end: number,
  alphabet: Base64Alphabet,
): BlockSource {
  const claim = singleUse();
  const has = (ch: string): boolean => {
    const i = src.indexOf(ch, start);
    return i !== -1 && i < end;
  };
  // Tolerate standard base64 where base64url was declared when unambiguous
  // (upstreams are not always consistent); a mix of both alphabets is refused.
  let mixedAlphabets = false;
  if (alphabet === "url" && (has("+") || has("/"))) {
    if (has("-") || has("_")) mixedAlphabets = true;
    else alphabet = "std";
  }
  const badInput = (): StagingBadInput =>
    has("\n") || has("\r") || has(" ") || has("\t")
      ? new StagingBadInput("bad base64: remove line breaks and whitespace")
      : new StagingBadInput(mixedAlphabets ? "bad base64: mixes the standard and URL-safe alphabets" : "bad base64");
  let byteLength: number | null;
  try {
    byteLength = mixedAlphabets ? null : decodedLength(src, start, end, alphabet);
  } catch {
    byteLength = null; // reported as StagingBadInput by read()
  }
  // One 4-char quantum decodes to 3 bytes; a block boundary (1 MiB ≢ 0 mod 3)
  // can fall inside a quantum, so the straddling quantum goes through `tmp`.
  const tmp = new Uint8Array(3);
  const decode = (s: number, e: number, dst: Uint8Array, at: number, want: number): void => {
    let w: number;
    try {
      w = decodeBase64Into(src, s, e, dst, at, alphabet);
    } catch {
      throw badInput();
    }
    // A short write means padding before the end of the string.
    if (w !== want) throw badInput();
  };
  return {
    // An undeterminable length means the input is malformed. Report it as a
    // (known) zero length so writers take the known-length path and `read`
    // fails with 400 — never the shared unknown-length slot (which would
    // answer 503 while busy).
    byteLength: byteLength ?? 0,
    async read(onBlock) {
      claim();
      if (byteLength === null) throw badInput();
      const len = byteLength;
      const quantumEnd = (q: number) => Math.min(end, start + q * 4 + 4);
      const quantumBytes = (q: number) => Math.min(3, len - q * 3);
      for (let b0 = 0; b0 < len; b0 += BLOCK_BYTES) {
        const b1 = Math.min(len, b0 + BLOCK_BYTES);
        const block = new Uint8Array(b1 - b0);
        let p = b0;
        while (p < b1) {
          const q = Math.floor(p / 3);
          if (p % 3 !== 0 || b1 - p < 3) {
            // Partial quantum at a block edge or at the end of the data.
            const qb = quantumBytes(q);
            decode(start + q * 4, quantumEnd(q), tmp, 0, qb);
            const from = p - q * 3;
            const take = Math.min(qb - from, b1 - p);
            block.set(tmp.subarray(from, from + take), p - b0);
            p += take;
          } else {
            const quanta = Math.floor((b1 - p) / 3);
            const lastQ = q + quanta - 1;
            const want = (quanta - 1) * 3 + quantumBytes(lastQ);
            decode(start + q * 4, quantumEnd(lastQ), block, p - b0, want);
            p += want;
          }
        }
        await onBlock(block);
      }
      return len;
    },
  };
}

/**
 * Seal every block of `src` under (key, ivBase, handle) and write the
 * ciphertext to R2 at `r2Key` through a fixed-length sink. Returns the
 * plaintext length. With an unknown length the plaintext blocks are held until
 * the source ends (the AAD binds the total length, so nothing can be sealed
 * earlier), then sealed and released one at a time.
 *
 * On any failure the sink is aborted (so R2 never commits a short object) and
 * the error is rethrown.
 */
export async function encryptBlocksToR2(
  r2: R2Bucket,
  r2Key: string,
  key: CryptoKey,
  ivBase: Uint8Array,
  fileHandle: string,
  src: BlockSource,
): Promise<number> {
  if (src.byteLength !== null) return sealToR2(r2, r2Key, key, ivBase, fileHandle, src);
  const release = tryAcquireUnknownLengthSlot();
  if (!release) throw new StagingBusy();
  try {
    const held: Uint8Array[] = [];
    await readSource(src, async (b) => {
      held.push(b);
    });
    let total = 0;
    for (const b of held) total += b.byteLength;
    return await sealToR2(r2, r2Key, key, ivBase, fileHandle, {
      byteLength: total,
      async read(onBlock) {
        while (held.length > 0) await onBlock(held.shift()!);
        return total;
      },
    });
  } finally {
    release();
  }
}

// Errors from our own block callback (encrypt, sink → R2) are tagged so they
// can be told apart from the source's own failures (a dropped upstream body).
class CallbackFailure {
  constructor(readonly error: unknown) {}
}

async function readSource(src: BlockSource, onBlock: (plain: Uint8Array) => Promise<void>): Promise<number> {
  try {
    return await src.read(async (plain) => {
      try {
        await onBlock(plain);
      } catch (err) {
        throw new CallbackFailure(err);
      }
    });
  } catch (err) {
    if (err instanceof CallbackFailure) throw err.error;
    if (
      err instanceof StagingTooLarge ||
      err instanceof StagingBodyLengthMismatch ||
      err instanceof StagingBadInput ||
      err instanceof StagingSourceError
    ) {
      throw err;
    }
    throw new StagingSourceError();
  }
}

async function sealToR2(
  r2: R2Bucket,
  r2Key: string,
  key: CryptoKey,
  ivBase: Uint8Array,
  fileHandle: string,
  source: BlockSource,
): Promise<number> {
  const len = source.byteLength!;
  const n = blockCount(len);
  const sink = createFixedLengthSink(ciphertextLength(len));
  const put = r2.put(r2Key, sink.readable);
  // If R2 fails first, abort the sink so a blocked write wakes up.
  const putFailed = put.then(
    () => null,
    async (e: unknown) => {
      await sink.abort(e);
      return e;
    },
  );
  try {
    let index = 0;
    const got = await readSource(source, async (plain) => {
      await sink.write(await encryptBlock(key, ivBase, fileHandle, index++, n, len, plain));
    });
    if (got !== len) throw new StagingBodyLengthMismatch();
    if (index === 0) await sink.write(await encryptBlock(key, ivBase, fileHandle, 0, 1, 0, new Uint8Array(0)));
    await sink.close();
  } catch (err) {
    await sink.abort(err);
    await putFailed;
    throw err;
  }
  const putErr = await putFailed;
  if (putErr !== null) throw putErr;
  return len;
}

/**
 * Mint a fresh token + handle, encrypt `src` block by block into R2, and
 * insert the row already claimed (enc_version 2). Never throws.
 */
export async function stageFromBlocks(
  deps: PutFileCapabilityDeps,
  src: BlockSource,
  contentType: string,
  filename: string | null,
): Promise<PutFileResult> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  if (src.byteLength !== null && src.byteLength > deps.config.maxBytes) {
    return { ok: false, status: 413, message: "payload too large" };
  }
  let token: string;
  let file_handle: string;
  let key: CryptoKey;
  let token_hash: Uint8Array;
  const ivBase = new Uint8Array(8);
  try {
    token = mintToken();
    file_handle = mintFileHandle();
    crypto.getRandomValues(ivBase);
    key = await deriveV2Key(token, file_handle);
    token_hash = await sha256Bearer(token);
  } catch {
    return { ok: false, status: 500, message: "crypto failure" };
  }
  const r2_key = newR2Key();
  let byteLen: number;
  try {
    byteLen = await encryptBlocksToR2(deps.STAGING_R2, r2_key, key, ivBase, file_handle, src);
  } catch (err) {
    await deleteQuietly(deps.STAGING_R2, r2_key);
    if (err instanceof StagingTooLarge) return { ok: false, status: 413, message: "payload too large" };
    if (err instanceof StagingBadInput) return { ok: false, status: 400, message: err.message };
    if (err instanceof StagingBodyLengthMismatch) {
      return { ok: false, status: 502, message: "body length does not match the declared length" };
    }
    if (err instanceof StagingBusy) return { ok: false, status: 503, message: err.message };
    if (err instanceof StagingSourceError) return { ok: false, status: 502, message: err.message };
    return { ok: false, status: 500, message: "r2 write failed" };
  }
  if (byteLen > deps.config.maxBytes) {
    await deleteQuietly(deps.STAGING_R2, r2_key);
    return { ok: false, status: 413, message: "payload too large" };
  }

  const created_at = now();
  const expires_at = created_at + deps.config.fetchTtlSeconds;
  try {
    await insertClaimed(deps.STAGING_D1, {
      token_hash,
      file_handle,
      r2_key,
      iv: ivBase,
      content_type: contentType,
      byte_len: byteLen,
      filename,
      created_at,
      claimed_at: created_at,
      expires_at,
      enc_version: ENC_VERSION_V2,
    });
  } catch {
    await deleteQuietly(deps.STAGING_R2, r2_key);
    return { ok: false, status: 500, message: "d1 insert failed" };
  }
  const origin = deps.uploadOrigin.replace(/\/$/, "");
  return {
    ok: true,
    file_handle,
    token,
    fetch_url: `${origin}/staging/fetch/${file_handle}`,
    expires_at,
    byte_length: byteLen,
  };
}

/** Best-effort delete; R2 lifecycle is the backstop. */
export async function deleteQuietly(r2: R2Bucket, key: string): Promise<void> {
  try {
    await r2.delete(key);
  } catch {
    /* R2 lifecycle is the backstop */
  }
}

/** A read failed after the row resolved. `status` is 410 (corrupt) or 500. */
export class StagedFileReadError extends Error {
  readonly status: 410 | 500;
  constructor(status: 410 | 500, message: string) {
    super(message);
    this.name = "StagedFileReadError";
    this.status = status;
  }
}

/** Prefix and decoded-length check only; no I/O. */
export function isPlausibleStagedRef(v: unknown): v is StagedRef {
  if (v === null || typeof v !== "object") return false;
  const { file_handle, token } = v as Record<string, unknown>;
  if (typeof file_handle !== "string" || typeof token !== "string") return false;
  try {
    decodeHandleBytes(file_handle);
    decodeTokenSecret(token);
    return true;
  } catch {
    return false;
  }
}

/**
 * The opener's file, plus `begin()`: fetch the R2 object and check its size
 * without delivering any block, so `/staging/fetch` can answer 410 before it
 * commits to a 200. `readBlocks` calls `begin()` itself when needed.
 */
export interface OpenedStagedFile extends OpenStagedFile {
  begin(): Promise<void>;
}

export type OpenStagedInternalResult =
  | { ok: true; file: OpenedStagedFile }
  | { ok: false; status: 400 | 403 | 409 | 410 | 500; message: string };

const MSG_NOT_FOUND = "file not found or not yours";
const MSG_CORRUPT = "stored file is corrupt";
const MSG_LEGACY = "stored in a legacy format; re-stage the file";

export async function openStagedFile(deps: StagedFileOpenerDeps, ref: StagedRef): Promise<OpenStagedInternalResult> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  if (!isPlausibleStagedRef(ref)) return { ok: false, status: 400, message: "malformed file reference" };
  let token_hash: Uint8Array;
  let row: StagingRow | null;
  try {
    token_hash = await sha256Bearer(ref.token);
    row = await lookupByHash(deps.STAGING_D1, token_hash);
  } catch {
    return { ok: false, status: 500, message: "staging lookup failed" };
  }
  if (!row || !timingSafeEqualStrings(row.file_handle, ref.file_handle)) {
    return { ok: false, status: 403, message: MSG_NOT_FOUND };
  }
  if (row.state === "pending") return { ok: false, status: 409, message: "upload incomplete" };
  if (row.state === "corrupt") return { ok: false, status: 410, message: MSG_CORRUPT };
  if (row.expires_at <= now()) return { ok: false, status: 410, message: "expired" };
  // Only the v2 blockwise format is readable. enc_version 1 (the retired
  // one-shot format, also every pre-0002 row) is refused before any R2 read.
  if (row.enc_version !== ENC_VERSION_V2) return { ok: false, status: 410, message: MSG_LEGACY };
  if (!row.r2_key || !row.iv || row.byte_len === null) {
    return { ok: false, status: 500, message: "staging row incomplete" };
  }
  const byteLen = row.byte_len;
  const r2Key = row.r2_key;
  const iv = row.iv;
  const d1 = deps.STAGING_D1;
  const r2 = deps.STAGING_R2;

  const corrupt = async (): Promise<never> => {
    try {
      await markCorrupt(d1, token_hash);
    } catch {
      /* the 410 still stands */
    }
    throw new StagedFileReadError(410, MSG_CORRUPT);
  };

  let obj: { size: number; body: ReadableStream<Uint8Array> } | null = null;
  let begun: Promise<void> | null = null;
  const begin = (): Promise<void> => {
    begun ??= (async () => {
      let got: typeof obj;
      try {
        got = (await r2.get(r2Key)) as typeof obj;
      } catch {
        throw new StagedFileReadError(500, "staging read failed");
      }
      if (!got) throw new StagedFileReadError(500, "staged object missing");
      const expected = ciphertextLength(byteLen);
      if (got.size !== expected) await corrupt();
      obj = got;
    })();
    return begun;
  };

  let used = false;
  const file: OpenedStagedFile = {
    meta: {
      byteLength: byteLen,
      contentType: row.content_type ?? "application/octet-stream",
      filename: row.filename,
    },
    begin,
    async readBlocks(onBlock) {
      if (used) throw new Error("readBlocks may only be called once");
      used = true;
      await begin();
      const o = obj!;
      let key: CryptoKey;
      try {
        key = await deriveV2Key(ref.token, ref.file_handle);
      } catch {
        throw new StagedFileReadError(500, "key derivation failed");
      }
      const n = blockCount(byteLen);
      const reader = o.body.getReader();
      const buf = new Uint8Array(BLOCK_BYTES + GCM_TAG_BYTES);
      // Bytes read from R2 but not yet consumed into `buf`.
      let pending: Uint8Array = new Uint8Array(0);
      const fill = async (want: number): Promise<boolean> => {
        let have = 0;
        while (have < want) {
          if (pending.byteLength === 0) {
            const { done, value } = await reader.read();
            if (done) return false;
            pending = value;
            continue;
          }
          const take = Math.min(want - have, pending.byteLength);
          buf.set(pending.subarray(0, take), have);
          pending = pending.subarray(take);
          have += take;
        }
        return true;
      };
      let ok = false;
      try {
        for (let i = 0; i < n; i++) {
          const cLen = blockPlainLength(byteLen, i) + GCM_TAG_BYTES;
          let complete: boolean;
          try {
            complete = await fill(cLen);
          } catch {
            throw new StagedFileReadError(500, "staging read failed");
          }
          // The size was verified in begin(); a stream that then ends early is
          // a transport failure, not evidence the stored object is corrupt.
          if (!complete) throw new StagedFileReadError(500, "staging read failed");
          let plain: Uint8Array;
          try {
            plain = await decryptBlock(key, iv, ref.file_handle, i, n, byteLen, buf.subarray(0, cLen));
          } catch {
            return await corrupt();
          }
          await onBlock(plain, i);
        }
        ok = true;
      } finally {
        if (!ok) {
          try {
            await reader.cancel();
          } catch {
            /* ignore */
          }
        }
      }
    },
  };
  return { ok: true, file };
}

export function createStagedFileOpener(deps: StagedFileOpenerDeps): (ref: StagedRef) => Promise<OpenStagedResult> {
  return (ref) => openStagedFile(deps, ref);
}
