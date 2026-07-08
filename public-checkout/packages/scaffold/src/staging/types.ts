export const TOKEN_PREFIX = "stg_";
export const HANDLE_PREFIX = "fh_";
export const HKDF_INFO = "codemode/staging/v1";
export const TOKEN_SECRET_BYTES = 32;
export const HANDLE_BYTES = 16;
export const IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;

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
}

export interface StagingBindings {
  STAGING_R2: R2Bucket;
  STAGING_D1: D1Database;
}
