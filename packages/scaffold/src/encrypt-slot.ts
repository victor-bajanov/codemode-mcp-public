// AES-GCM data encryption + AES-KW key wrapping, with the wrapping key
// HMAC-SHA256-derived from the caller-supplied token string. Mirrors the
// scheme used by @cloudflare/workers-oauth-provider (encryptProps +
// wrapKeyWithToken) — same primitives, independent implementation so we
// don't depend on non-public exports.
//
// Threat model: a KV dump alone reveals nothing. To decrypt a slot the
// attacker must also have the user's wrapping token (the original Xero
// refresh token in props), which itself only lives encrypted-at-rest in
// OAuthProvider's encryptedProps inside OAUTH_KV.

const WRAPPING_KEY_HMAC_KEY = new Uint8Array([
  0x53, 0x70, 0xa3, 0x18, 0xc1, 0x4f, 0xe7, 0x0b,
  0x82, 0x99, 0x2d, 0x6e, 0xb7, 0x44, 0x09, 0xfc,
  0x1a, 0xd5, 0x83, 0x26, 0x77, 0x0e, 0xbb, 0x91,
  0x52, 0x40, 0xcd, 0x1f, 0x88, 0xab, 0x6c, 0x35,
]);

export interface SealedSlot {
  /** AES-GCM ciphertext of the JSON payload, base64. IV is fixed (zero)
   *  because the data key is fresh-per-write — see encryptSlot below. */
  encryptedData: string;
  /** AES-KW-wrapped data key, base64. Unwrap requires a wrapping key
   *  derived from the same token string used at encrypt time. */
  wrappedKey: string;
}

async function deriveWrappingKey(tokenStr: string): Promise<CryptoKey> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    WRAPPING_KEY_HMAC_KEY,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const hmacResult = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new TextEncoder().encode(tokenStr),
  );
  return crypto.subtle.importKey(
    "raw",
    hmacResult,
    { name: "AES-KW" },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

function bytesToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

export async function encryptSlot(tokenStr: string, value: unknown): Promise<SealedSlot> {
  // generateKey's lib type is CryptoKey | CryptoKeyPair (it covers RSA too);
  // for AES-GCM the runtime always returns a single CryptoKey.
  const dataKey = (await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  )) as CryptoKey;
  // Fixed-zero IV is safe here because dataKey is freshly generated for every
  // encrypt call — the (key, IV) pair is never reused. Same convention as
  // workers-oauth-provider/encryptProps.
  const iv = new Uint8Array(12);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dataKey,
    plaintext,
  );
  const wrappingKey = await deriveWrappingKey(tokenStr);
  const wrapped = await crypto.subtle.wrapKey("raw", dataKey, wrappingKey, { name: "AES-KW" });
  return {
    encryptedData: bytesToBase64(ciphertext),
    wrappedKey: bytesToBase64(wrapped),
  };
}

export async function decryptSlot<T>(
  tokenStr: string,
  sealed: SealedSlot,
): Promise<T | undefined> {
  let dataKey: CryptoKey;
  try {
    const wrappingKey = await deriveWrappingKey(tokenStr);
    dataKey = await crypto.subtle.unwrapKey(
      "raw",
      base64ToBytes(sealed.wrappedKey),
      wrappingKey,
      { name: "AES-KW" },
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
  } catch {
    return undefined;
  }
  try {
    const iv = new Uint8Array(12);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      dataKey,
      base64ToBytes(sealed.encryptedData),
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    return undefined;
  }
}
