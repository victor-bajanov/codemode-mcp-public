import { HKDF_INFO, IV_BYTES } from "./types";
import { decodeTokenSecret, decodeHandleBytes } from "./tokens";

const TEXT_ENCODER = new TextEncoder();

export async function sha256Bearer(bearer: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", TEXT_ENCODER.encode(bearer));
  return new Uint8Array(digest);
}

export async function deriveContentKey(
  tokenSecret: Uint8Array,
  handleBytes: Uint8Array,
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    "raw",
    tokenSecret,
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: handleBytes,
      info: TEXT_ENCODER.encode(HKDF_INFO),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptForStorage(
  token: string,
  fileHandle: string,
  plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const tokenSecret = decodeTokenSecret(token);
  const handleBytes = decodeHandleBytes(fileHandle);
  const key = await deriveContentKey(tokenSecret, handleBytes);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const aad = TEXT_ENCODER.encode(fileHandle);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    plaintext,
  );
  return { ciphertext: new Uint8Array(ct), iv };
}

export async function decryptFromStorage(
  token: string,
  fileHandle: string,
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const tokenSecret = decodeTokenSecret(token);
  const handleBytes = decodeHandleBytes(fileHandle);
  const key = await deriveContentKey(tokenSecret, handleBytes);
  const aad = TEXT_ENCODER.encode(fileHandle);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    ciphertext,
  );
  return new Uint8Array(pt);
}
