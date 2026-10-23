// Writes a legacy v1 (one-shot AES-GCM) staged row + object, for the
// legacy-refusal tests. Production neither writes nor reads this format.
import { deriveContentKey, sha256Bearer } from "../../crypto";
import { insertClaimed } from "../../repo";
import { decodeHandleBytes, decodeTokenSecret, mintFileHandle, mintToken, newR2Key } from "../../tokens";
import type { FakeD1 } from "./fake-d1";
import type { FakeR2 } from "./fake-r2";

/** HKDF info of the retired v1 format. Production derives only v2 keys. */
export const HKDF_INFO = "codemode/staging/v1";

/** Legacy v1 one-shot encryption (the production write path is gone). */
export async function encryptV1(
  token: string,
  handle: string,
  plain: Uint8Array,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const key = await deriveContentKey(decodeTokenSecret(token), decodeHandleBytes(handle), HKDF_INFO);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(handle) }, key, plain),
  );
  return { ciphertext, iv };
}

export async function seedV1Row(
  d1: FakeD1,
  r2: FakeR2,
  plain: Uint8Array,
  opts: { now: number; contentType?: string; filename?: string | null; ttl?: number },
): Promise<{ token: string; handle: string; r2_key: string }> {
  const token = mintToken();
  const handle = mintFileHandle();
  const { ciphertext: ct, iv } = await encryptV1(token, handle, plain);
  const r2_key = newR2Key();
  r2.store.set(r2_key, ct);
  await insertClaimed(d1 as unknown as D1Database, {
    token_hash: await sha256Bearer(token),
    file_handle: handle,
    r2_key,
    iv,
    content_type: opts.contentType ?? "application/octet-stream",
    byte_len: plain.byteLength,
    filename: opts.filename ?? null,
    created_at: opts.now,
    claimed_at: opts.now,
    expires_at: opts.now + (opts.ttl ?? 3600),
    enc_version: 1,
  });
  return { token, handle, r2_key };
}
