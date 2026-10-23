export const TOKEN_PREFIX = "stg_";
export const HANDLE_PREFIX = "fh_";
export const TOKEN_SECRET_BYTES = 32;
export const HANDLE_BYTES = 16;
export const IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;
export { BLOCK_BYTES, HKDF_INFO_V2, ENC_VERSION_V2 } from "./block-format";

/** At-rest format: 1 = retired one-shot AES-GCM (refused on read with 410); 2 = blockwise. */
export type EncVersion = 1 | 2;

export type StagingState = "pending" | "claimed" | "corrupt";

export interface StagingRow {
  token_hash: Uint8Array;          // 32-byte SHA-256(token-string)
  file_handle: string;             // "fh_<base64url>"
  state: StagingState;
  r2_key: string | null;
  iv: Uint8Array | null;           // 12 bytes when claimed
  content_type_hint: string | null;
  content_type: string | null;
  expected_byte_len: number | null;
  byte_len: number | null;
  filename: string | null;
  created_at: number;              // unix seconds
  claimed_at: number | null;
  expires_at: number;              // unix seconds
  enc_version: EncVersion;         // 1 when the column is absent (pre-0002 rows); only 2 is readable
}

export interface RegisterInput {
  content_type?: string;
  expected_byte_len?: number;
  filename?: string;
}

export interface RegisterOutput {
  token: string;                   // "stg_<base64url>"
  file_handle: string;             // "fh_<base64url>"
  upload_url: string;
  max_bytes: number;
  upload_ttl_seconds: number;
  fetch_ttl_seconds: number;
}

export interface StagingConfig {
  uploadTtlSeconds: number;
  fetchTtlSeconds: number;
  maxBytes: number;
  // Staged-transfer v2 knobs. Optional so hand-built configs (tests, older
  // callers) keep compiling; readers fall back to the DEFAULT_* constants.
  /** `getFile` refuses rows larger than this. */
  getFileMaxBytes?: number;
  /** Exact assembled length cap for `composed` / staged multipart bodies. */
  composeMaxBytes?: number;
  /** Isolate-wide concurrent staged transfers. */
  maxConcurrentTransfers?: number;
  /** Absolute per-transfer timeout. */
  transferTimeoutMs?: number;
}

export const DEFAULT_GETFILE_MAX_BYTES = 8_388_608; // 8 MiB
export const DEFAULT_COMPOSE_MAX_BYTES = 75_497_472; // 72 MiB
export const DEFAULT_MAX_CONCURRENT_TRANSFERS = 2;
export const DEFAULT_TRANSFER_TIMEOUT_MS = 60_000;

export interface StagingBindings {
  STAGING_R2: R2Bucket;
  STAGING_D1: D1Database;
}
