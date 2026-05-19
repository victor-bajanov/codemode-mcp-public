import type { StagingRow } from "./types";

export interface InsertPendingInput {
  token_hash: Uint8Array;
  file_handle: string;
  content_type_hint: string | null;
  expected_byte_len: number | null;
  filename: string | null;
  created_at: number;
  expires_at: number;
}

export interface AtomicClaimInput {
  token_hash: Uint8Array;
  iv: Uint8Array;
  content_type: string;
  byte_len: number;
  r2_key: string;
  claimed_at: number;
  new_expires_at: number;
  now: number;
}

export async function insertPending(d1: D1Database, input: InsertPendingInput): Promise<void> {
  await d1
    .prepare(
      `INSERT INTO staging
       (token_hash, file_handle, state, content_type_hint, expected_byte_len, filename, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.token_hash,
      input.file_handle,
      "pending",
      input.content_type_hint,
      input.expected_byte_len,
      input.filename,
      input.created_at,
      input.expires_at,
    )
    .run();
}

export async function atomicClaim(
  d1: D1Database,
  input: AtomicClaimInput,
): Promise<{ file_handle: string } | null> {
  const result = await d1
    .prepare(
      `UPDATE staging SET state='claimed', iv=?, content_type=?, byte_len=?, r2_key=?, claimed_at=?, expires_at=?
       WHERE token_hash=? AND state='pending' AND expires_at>?
       RETURNING file_handle`,
    )
    .bind(
      input.iv,
      input.content_type,
      input.byte_len,
      input.r2_key,
      input.claimed_at,
      input.new_expires_at,
      input.token_hash,
      input.now,
    )
    .first<{ file_handle: string }>();
  return result ?? null;
}

export interface InsertClaimedInput {
  token_hash: Uint8Array;
  file_handle: string;
  r2_key: string;
  iv: Uint8Array;
  content_type: string;
  byte_len: number;
  filename: string | null;
  created_at: number;
  claimed_at: number;
  expires_at: number;
}

export async function insertClaimed(d1: D1Database, input: InsertClaimedInput): Promise<void> {
  await d1
    .prepare(
      `INSERT INTO staging
       (token_hash, file_handle, state, r2_key, iv, content_type_hint, content_type,
        expected_byte_len, byte_len, filename, created_at, claimed_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.token_hash,
      input.file_handle,
      "claimed",
      input.r2_key,
      input.iv,
      null,
      input.content_type,
      null,
      input.byte_len,
      input.filename,
      input.created_at,
      input.claimed_at,
      input.expires_at,
    )
    .run();
}

// D1's BLOB return type isn't consistent: under some compat configurations it
// hands BLOB columns back as a plain `Array<number>` rather than a `Uint8Array`
// or `ArrayBuffer`. WebCrypto's AES-GCM rejects the Array form
// ("Incorrect type for the 'iv' field … not of type 'JsBufferSource'"), and
// equality checks against bound Uint8Array values get awkward. Normalize at
// the boundary so callers always see `Uint8Array`.
function toUint8Array(v: unknown): Uint8Array | null {
  if (v == null) return null;
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) {
    const view = v as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  if (Array.isArray(v)) return new Uint8Array(v as number[]);
  return null;
}

export async function lookupByHash(d1: D1Database, token_hash: Uint8Array): Promise<StagingRow | null> {
  const raw = await d1
    .prepare(`SELECT * FROM staging WHERE token_hash=?`)
    .bind(token_hash)
    .first<Record<string, unknown>>();
  if (!raw) return null;
  return {
    token_hash: toUint8Array(raw.token_hash) ?? new Uint8Array(),
    file_handle: raw.file_handle as string,
    state: raw.state as StagingRow["state"],
    r2_key: (raw.r2_key as string | null) ?? null,
    iv: toUint8Array(raw.iv),
    content_type_hint: (raw.content_type_hint as string | null) ?? null,
    content_type: (raw.content_type as string | null) ?? null,
    expected_byte_len: (raw.expected_byte_len as number | null) ?? null,
    byte_len: (raw.byte_len as number | null) ?? null,
    filename: (raw.filename as string | null) ?? null,
    created_at: raw.created_at as number,
    claimed_at: (raw.claimed_at as number | null) ?? null,
    expires_at: raw.expires_at as number,
  };
}

export async function markCorrupt(d1: D1Database, token_hash: Uint8Array): Promise<void> {
  await d1
    .prepare(`UPDATE staging SET state='corrupt' WHERE token_hash=?`)
    .bind(token_hash)
    .run();
}

export async function listExpired(
  d1: D1Database,
  cutoff: number,
): Promise<{ token_hash: Uint8Array; r2_key: string | null }[]> {
  const { results } = await d1
    .prepare(`SELECT token_hash, r2_key FROM staging WHERE expires_at < ?`)
    .bind(cutoff)
    .all<{ token_hash: unknown; r2_key: string | null }>();
  return results.map((r) => ({
    token_hash: toUint8Array(r.token_hash) ?? new Uint8Array(),
    r2_key: r.r2_key ?? null,
  }));
}

export async function deleteByHash(d1: D1Database, token_hash: Uint8Array): Promise<void> {
  await d1.prepare(`DELETE FROM staging WHERE token_hash=?`).bind(token_hash).run();
}
