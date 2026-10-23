import { DEFAULT_TRANSFER_TIMEOUT_MS, type StagingConfig } from "./types";
import { atomicClaim, lookupByHash } from "./repo";
import { sha256Bearer, deriveV2Key } from "./crypto";
import { ENC_VERSION_V2 } from "./block-format";
import {
  StagingBodyLengthMismatch,
  StagingBusy,
  StagingSourceError,
  StagingTimeout,
  StagingTooLarge,
  blockSourceFromStream,
  deleteQuietly,
  encryptBlocksToR2,
} from "./staged-file";
import { newR2Key } from "./tokens";

export interface UploadDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  now?: () => number;
}

const CONTENT_LENGTH_RE = /^\d{1,15}$/;

function parseBearer(req: Request): string | null {
  const h = req.headers.get("Authorization") ?? req.headers.get("authorization");
  if (!h) return null;
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return null;
  const v = m[1]!.trim();
  return v.startsWith("stg_") ? v : null;
}

export async function handleUpload(req: Request, deps: UploadDeps): Promise<Response> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const bearer = parseBearer(req);
  if (!bearer) return new Response("forbidden", { status: 403 });

  // Pre-validate Content-Length: plain decimal digits only (no exponent,
  // sign, hex, whitespace or fraction), before any D1 lookup.
  const declared = req.headers.get("Content-Length");
  let declaredLen: number | null = null;
  if (declared !== null) {
    if (!CONTENT_LENGTH_RE.test(declared)) return new Response("bad content-length", { status: 400 });
    declaredLen = Number(declared);
    if (declaredLen > deps.config.maxBytes) return new Response("payload too large", { status: 413 });
  }

  const token_hash = await sha256Bearer(bearer);
  const row = await lookupByHash(deps.STAGING_D1, token_hash);
  if (!row) return new Response("forbidden", { status: 403 });
  if (row.state === "claimed" || row.state === "corrupt") {
    return new Response("conflict", { status: 409 });
  }
  if (row.expires_at <= now()) {
    return new Response("gone", { status: 410 });
  }

  // Content-Type hint check.
  const ct = req.headers.get("Content-Type") ?? "application/octet-stream";
  if (row.content_type_hint && row.content_type_hint !== ct) {
    return new Response("content-type mismatch", { status: 400 });
  }

  return storeAndClaim(req, deps, bearer, token_hash, row.file_handle, ct, declaredLen, now);
}

async function storeAndClaim(
  req: Request,
  deps: UploadDeps,
  bearer: string,
  token_hash: Uint8Array,
  fileHandle: string,
  ct: string,
  declaredLen: number | null,
  now: () => number,
): Promise<Response> {
  // Encrypt block by block as the body arrives (v2 format), enforcing
  // maxBytes while streaming (F-13): a body with no (or a lying)
  // Content-Length is cancelled as soon as it passes maxBytes. With a declared
  // length the ciphertext streams straight into R2; without one the plaintext
  // blocks are held until the body ends (the AAD binds the total length).
  const body = req.body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() });
  const ivBase = crypto.getRandomValues(new Uint8Array(8));
  const r2_key = newR2Key();
  let byteLen: number;
  try {
    const key = await deriveV2Key(bearer, fileHandle);
    byteLen = await encryptBlocksToR2(
      deps.STAGING_R2,
      r2_key,
      key,
      ivBase,
      fileHandle,
      // Only unknown-length uploads hold the shared slot, so only they are
      // bounded: a stalled one would otherwise starve every unknown-length
      // returnAs:"stage" on the isolate. Known-length uploads stream and are
      // left unbounded so slow links can still send large files.
      blockSourceFromStream(
        body,
        declaredLen,
        deps.config.maxBytes,
        declaredLen === null
          ? { timeoutMs: deps.config.transferTimeoutMs ?? DEFAULT_TRANSFER_TIMEOUT_MS }
          : {},
      ),
    );
  } catch (err) {
    // Without Content-Length the plaintext is held until the body ends, so
    // such uploads share one isolate-wide slot (unknown-length-slot.ts); a
    // second one is turned away before its body is read or any R2 write.
    if (err instanceof StagingBusy) {
      return new Response(err.message, { status: 503, headers: { "Retry-After": "1" } });
    }
    await deleteQuietly(deps.STAGING_R2, r2_key);
    // The client stopped sending within transferTimeoutMs: 408 Request
    // Timeout is exactly "the server gave up waiting for the request body".
    if (err instanceof StagingTimeout) return new Response("upload timed out", { status: 408 });
    if (err instanceof StagingTooLarge) return new Response("payload too large", { status: 413 });
    if (err instanceof StagingSourceError) return new Response("body read failed", { status: 400 });
    if (err instanceof StagingBodyLengthMismatch) {
      return new Response("body length does not match Content-Length", { status: 400 });
    }
    return new Response("internal", { status: 500 });
  }

  const claimed_at = now();
  const claimed = await atomicClaim(deps.STAGING_D1, {
    token_hash,
    iv: ivBase,
    content_type: ct,
    byte_len: byteLen,
    r2_key,
    claimed_at,
    new_expires_at: claimed_at + deps.config.fetchTtlSeconds,
    now: claimed_at,
    enc_version: ENC_VERSION_V2,
  });
  if (!claimed) {
    // Lost the race or row vanished. Clean up the R2 object we just wrote.
    await deps.STAGING_R2.delete(r2_key);
    return new Response("conflict", { status: 409 });
  }
  return new Response(null, { status: 204 });
}

