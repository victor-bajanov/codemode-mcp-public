import type { StagingConfig } from "./types";
import { blockSourceFromBase64, stageFromBlocks } from "./staged-file";
import { withTransferGate, type TransferGateDeps } from "./gate-dep";

export type PutFileCapabilityDeps = PutFileStoreDeps & TransferGateDeps;

export interface PutFileStoreDeps {
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

/**
 * Host-side function called by the codemode child Worker via
 * `__stagingHost.putFile(bytesBase64, contentType, filename?)`.
 *
 * Behaviour (see docs/superpowers/specs/2026-05-19-symmetric-file-download-design.md):
 *
 *   - Validates input types (no exceptions cross the sandbox boundary).
 *   - Rejects a base64 string too long to decode within `config.maxBytes`
 *     (status 413) BEFORE decoding it, so an over-cap payload costs no decode
 *     CPU or buffer memory (F-24); malformed over-cap input is therefore a
 *     413, not a 400.
 *   - Holds a transfer-gate slot for the write when a gate is supplied (D8);
 *     a refused slot is a 429.
 *   - Decodes the base64 strictly, block by block, straight into the v2
 *     encrypter (`stageFromBlocks`); malformed input is a 400. Re-checks
 *     `config.maxBytes` against the exact decoded length (413) — the bound
 *     above is deliberately loose. Zero-byte payloads are valid.
 *   - Mints token + file_handle; derives the v2 content key via the shared
 *     HKDF chain; every 1 MiB block is sealed with position-bound AAD.
 *   - Streams the ciphertext into R2; on failure returns 500.
 *   - INSERTs the row directly in `state='claimed'` (no race window — putFile
 *     owns the bytes from the start); on D1 failure best-effort deletes the
 *     just-written R2 object and returns 500.
 *   - Returns `{ ok: true, file_handle, token, fetch_url, expires_at, byte_length }`.
 *
 * The host never persists the token. The content key is re-derived on each
 * `/staging/fetch/*` call.
 */
export function createPutFileCapability(deps: PutFileCapabilityDeps) {
  return async function putFile(
    bytesBase64: string,
    contentType: string,
    filename: string | null,
    /** Host-internal (stageFromUpstreamJson): decode base64url without a
     *  converted copy. The sandbox wrapper forwards only the first three
     *  arguments; either alphabet is equally safe. */
    alphabet: "std" | "url" = "std",
  ): Promise<PutFileResult> {
    if (typeof bytesBase64 !== "string") {
      return { ok: false, status: 400, message: "bytesBase64 must be a string" };
    }
    if (typeof contentType !== "string") {
      return { ok: false, status: 400, message: "contentType must be a string" };
    }
    // Printable ASCII only, ≤255 chars: the value becomes a stored row field
    // and, later, a Content-Type header and a multipart part default.
    if (contentType.length > 255 || /[^\x20-\x7e]/.test(contentType)) {
      return { ok: false, status: 400, message: "contentType must be printable ASCII, at most 255 characters" };
    }
    if (filename !== null && typeof filename !== "string") {
      return { ok: false, status: 400, message: "filename must be a string or null" };
    }
    // Length bound before decoding (F-24): n bytes encode to ceil(n/3)*4
    // base64 chars. The +4 slack tolerates stray padding; the post-decode
    // check below stays the exact one.
    if (bytesBase64.length > Math.ceil(deps.config.maxBytes / 3) * 4 + 4) {
      return { ok: false, status: 413, message: "payload too large" };
    }
    // Decoded block by block straight into the encrypter (no atob, no
    // whole-file plaintext); malformed input is a 400, over-cap a 413.
    const gated = await withTransferGate(deps, () =>
      stageFromBlocks(
        deps,
        blockSourceFromBase64(bytesBase64, 0, bytesBase64.length, alphabet === "url" ? "url" : "std"),
        contentType,
        filename,
      ),
    );
    return gated.ok ? gated.value : gated;
  };
}
