import type { StagingConfig } from "./types";
import { mintToken, mintFileHandle, newR2Key } from "./tokens";
import { sha256Bearer, encryptForStorage } from "./crypto";
import { insertClaimed } from "./repo";

export interface PutFileCapabilityDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  uploadOrigin: string;
  /** Test seam. */
  now?: () => number;
}

export type PutFileResult =
  | {
      ok: true;
      file_handle: string;
      token: string;
      fetch_url: string;
      expires_at: number;
      byte_length: number;
    }
  | { ok: false; status: number; message: string };

function decodeBase64(s: string): Uint8Array | null {
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * Host-side function called by the codemode child Worker via
 * `__stagingHost.putFile(bytesBase64, contentType, filename?)`.
 *
 * Behaviour (see docs/superpowers/specs/2026-05-19-symmetric-file-download-design.md):
 *
 *   - Validates input types (no exceptions cross the sandbox boundary).
 *   - Decodes base64 → Uint8Array; rejects malformed input as status 400.
 *   - Enforces `config.maxBytes` post-decode (status 413). Zero-byte payloads are valid.
 *   - Mints token + file_handle; derives AES-GCM key via the shared HKDF chain
 *     in crypto.ts; AAD is bound to the file_handle.
 *   - Writes ciphertext to R2; on failure returns 500.
 *   - INSERTs the row directly in `state='claimed'` (no race window — putFile
 *     owns the bytes from the start); on D1 failure best-effort deletes the
 *     just-written R2 object and returns 500.
 *   - Returns `{ ok: true, file_handle, token, fetch_url, expires_at, byte_length }`.
 *
 * The host never persists the token. The content key is re-derived on each
 * `/staging/fetch/*` call.
 */
export function createPutFileCapability(deps: PutFileCapabilityDeps) {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const origin = deps.uploadOrigin.replace(/\/$/, "");
  return async function putFile(
    bytesBase64: string,
    contentType: string,
    filename: string | null,
  ): Promise<PutFileResult> {
    if (typeof bytesBase64 !== "string") {
      return { ok: false, status: 400, message: "bytesBase64 must be a string" };
    }
    if (typeof contentType !== "string") {
      return { ok: false, status: 400, message: "contentType must be a string" };
    }
    if (filename !== null && typeof filename !== "string") {
      return { ok: false, status: 400, message: "filename must be a string or null" };
    }
    const bytes = decodeBase64(bytesBase64);
    if (!bytes) {
      return { ok: false, status: 400, message: "bad base64" };
    }
    if (bytes.byteLength > deps.config.maxBytes) {
      return { ok: false, status: 413, message: "payload too large" };
    }

    let token: string;
    let file_handle: string;
    let ciphertext: Uint8Array;
    let iv: Uint8Array;
    let r2_key: string;
    let token_hash: Uint8Array;
    try {
      token = mintToken();
      file_handle = mintFileHandle();
      const enc = await encryptForStorage(token, file_handle, bytes);
      ciphertext = enc.ciphertext;
      iv = enc.iv;
      r2_key = newR2Key();
      token_hash = await sha256Bearer(token);
    } catch {
      // Token mint / WebCrypto failure — theoretical on the Workers runtime,
      // but the contract is "no exceptions cross the sandbox boundary".
      return { ok: false, status: 500, message: "crypto failure" };
    }

    try {
      await deps.STAGING_R2.put(r2_key, ciphertext);
    } catch {
      return { ok: false, status: 500, message: "r2 write failed" };
    }

    const created_at = now();
    const expires_at = created_at + deps.config.fetchTtlSeconds;
    try {
      await insertClaimed(deps.STAGING_D1, {
        token_hash,
        file_handle,
        r2_key,
        iv,
        content_type: contentType,
        byte_len: bytes.byteLength,
        filename,
        created_at,
        claimed_at: created_at,
        expires_at,
      });
    } catch {
      // Best-effort clean-up of the orphan ciphertext (R2 lifecycle is the
      // backstop). Swallow failure here — the original error is what we want
      // surfaced to the sandbox.
      try {
        await deps.STAGING_R2.delete(r2_key);
      } catch {
        /* ignore */
      }
      return { ok: false, status: 500, message: "d1 insert failed" };
    }

    return {
      ok: true,
      file_handle,
      token,
      fetch_url: `${origin}/staging/fetch/${file_handle}`,
      expires_at,
      byte_length: bytes.byteLength,
    };
  };
}
