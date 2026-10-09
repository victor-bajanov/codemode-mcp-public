import type { StagingConfig } from "./types";
import { atomicClaim, lookupByHash } from "./repo";
import { sha256Bearer, encryptForStorage } from "./crypto";
import { newR2Key } from "./tokens";

export interface UploadDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  now?: () => number;
}

function parseBearer(req: Request): string | null {
  const h = req.headers.get("Authorization") ?? req.headers.get("authorization");
  if (!h) return null;
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return null;
  const v = m[1]!.trim();
  return v.startsWith("stg_") ? v : null;
}

/**
 * Read `req`'s body into one buffer, or return `null` (after cancelling the
 * stream) once more than `maxBytes` have arrived. A missing body is a
 * zero-byte upload.
 */
async function readBodyCapped(req: Request, maxBytes: number): Promise<Uint8Array | null> {
  const reader = req.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

export async function handleUpload(req: Request, deps: UploadDeps): Promise<Response> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const bearer = parseBearer(req);
  if (!bearer) return new Response("forbidden", { status: 403 });

  // Pre-validate Content-Length.
  const declared = req.headers.get("Content-Length");
  if (declared !== null) {
    const n = Number(declared);
    if (!Number.isFinite(n) || n < 0) return new Response("bad content-length", { status: 400 });
    if (n > deps.config.maxBytes) return new Response("payload too large", { status: 413 });
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

  // Read body, enforcing max while streaming (F-13): a body with no (or a
  // lying) Content-Length is cancelled as soon as it passes maxBytes instead
  // of being buffered in full first.
  const buf = await readBodyCapped(req, deps.config.maxBytes);
  if (!buf) {
    return new Response("payload too large", { status: 413 });
  }

  const { ciphertext, iv } = await encryptForStorage(bearer, row.file_handle, buf);
  const r2_key = newR2Key();
  await deps.STAGING_R2.put(r2_key, ciphertext);

  const claimed_at = now();
  const claimed = await atomicClaim(deps.STAGING_D1, {
    token_hash, iv,
    content_type: ct,
    byte_len: buf.byteLength,
    r2_key,
    claimed_at,
    new_expires_at: claimed_at + deps.config.fetchTtlSeconds,
    now: claimed_at,
  });
  if (!claimed) {
    // Lost the race or row vanished. Clean up the R2 object we just wrote.
    await deps.STAGING_R2.delete(r2_key);
    return new Response("conflict", { status: 409 });
  }
  return new Response(null, { status: 204 });
}
