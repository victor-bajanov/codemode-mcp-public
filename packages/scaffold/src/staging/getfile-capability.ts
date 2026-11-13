import { stagingAuditEntry, type AuditSink } from "../audit.js";
import { DEFAULT_GETFILE_MAX_BYTES, type StagingConfig } from "./types";
import { Base64Encoder } from "./codec";
import { openStagedFile } from "./staged-file";
import { sanitiseRowFilename } from "./sanitise-filename";
import { withTransferGate, type TransferGateDeps } from "./gate-dep";

export type GetFileCapabilityDeps = GetFileStoreDeps & TransferGateDeps;

export interface GetFileStoreDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  /** E-1: the caller's principal; only its own rows are readable. */
  owner: string;
  /** E-1: one `staging.read` line per call when given. */
  audit?: AuditSink;
  /** Test seam: override the clock. */
  now?: () => number;
}

export interface SandboxFileBody {
  contentType: string;
  byteLength: number;
  filename: string | null;
  bytesBase64: string; // wire-safe; the child re-wraps as Uint8Array
}

export type GetFileResult =
  | ({ ok: true } & SandboxFileBody)
  | { ok: false; status: number; message: string };

/**
 * Host-side function called by the codemode child Worker via
 * `__stagingHost.getFile(handle, token)`.
 *
 * Its job is *processing* small files in sandbox code (parse a CSV, read a
 * PDF's text). Sending a staged file upstream does not need the bytes in the
 * sandbox: `codemode.request({ composed })` and `multipart[].staged` have the
 * host assemble the body. So rows above `STAGING_GETFILE_MAX_BYTES` (default
 * 8 MiB) are refused from D1 metadata alone, before any R2 read, and the
 * whole read holds a transfer-gate slot when a gate is supplied (D8).
 *
 * Wire form (host → child):
 *   { ok: true, contentType, byteLength, filename, bytesBase64 }
 *   | { ok: false, status, message }
 *
 * The base64 text is produced block by block (codec.ts) and joined once per
 * block; there is no per-byte string building.
 */
export function createGetFileCapability(deps: GetFileCapabilityDeps) {
  const read = readOnce(deps);
  return async function getFile(handle: string, token: string): Promise<GetFileResult> {
    const { result, fileRef, byteLength } = await read(handle, token);
    // E-1: one line per call; `fileRef`/`byteLength` only once the reference resolved to the
    // caller's own row.
    deps.audit?.(
      stagingAuditEntry({
        method: "HOST",
        path: "__stagingHost.getFile",
        operationId: "staging.read",
        allowed: result.ok,
        event: "read",
        fileRef,
        byteLength,
        status: result.ok ? 200 : result.status,
      }),
    );
    return result;
  };
}

function readOnce(deps: GetFileCapabilityDeps) {
  const maxBytes = deps.config.getFileMaxBytes ?? DEFAULT_GETFILE_MAX_BYTES;
  return async function read(
    handle: string,
    token: string,
  ): Promise<{ result: GetFileResult; fileRef?: string; byteLength?: number }> {
    if (typeof handle !== "string" || typeof token !== "string") {
      return { result: { ok: false, status: 400, message: "handle and token must be strings" } };
    }
    const opened = await openStagedFile(deps, { file_handle: handle, token });
    if (!opened.ok) return { result: opened };
    const { meta } = opened.file;
    const known = { fileRef: meta.fileRef, byteLength: meta.byteLength };
    if (meta.byteLength > maxBytes) {
      return {
        ...known,
        result: {
          ok: false,
          status: 413,
          message:
            `file is ${meta.byteLength} bytes; getFile returns at most ${maxBytes}. ` +
            "To send a staged file upstream, pass { file_handle, token } in codemode.request's " +
            "`composed` segments or a `multipart[].staged` part instead of reading the bytes.",
        },
      };
    }
    const gated = await withTransferGate(deps, async (): Promise<GetFileResult> => {
      const encoder = new Base64Encoder("plain");
      const decoder = new TextDecoder("latin1");
      const parts: string[] = [];
      const emit = async (ascii: Uint8Array) => {
        parts.push(decoder.decode(ascii));
      };
      try {
        await opened.file.readBlocks((plain) => encoder.push(plain, emit));
        await encoder.finish(emit);
      } catch (err) {
        const status = (err as { status?: unknown }).status;
        return {
          ok: false,
          status: status === 410 ? 410 : 500,
          message: status === 410 ? "stored file is corrupt" : "staging read failed",
        };
      }
      return {
        ok: true,
        contentType: meta.contentType,
        byteLength: meta.byteLength,
        filename: sanitiseRowFilename(meta.filename),
        bytesBase64: parts.join(""),
      };
    });
    return { ...known, result: gated.ok ? gated.value : gated };
  };
}
