import { HKDF_INFO_V2 } from "./block-format";
import { decodeTokenSecret, decodeHandleBytes } from "./tokens";

const TEXT_ENCODER = new TextEncoder();

export async function sha256Bearer(bearer: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", TEXT_ENCODER.encode(bearer));
  return new Uint8Array(digest);
}

export async function deriveContentKey(
  tokenSecret: Uint8Array,
  handleBytes: Uint8Array,
  info: string,
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
      info: TEXT_ENCODER.encode(info),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** The v2 (blockwise) content key for a token/handle pair. */
export async function deriveV2Key(token: string, fileHandle: string): Promise<CryptoKey> {
  return deriveContentKey(decodeTokenSecret(token), decodeHandleBytes(fileHandle), HKDF_INFO_V2);
}

/**
 * Audit correlation id for a staged file (E-1): the first 6 bytes of SHA-256(handle) as 12
 * lower-case hex chars. Joins a file's register/store/read/download lines without logging the
 * handle or token.
 */
export async function fileRefOf(file_handle: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", TEXT_ENCODER.encode(file_handle)));
  return Array.from(digest.subarray(0, 6), (b) => b.toString(16).padStart(2, "0")).join("");
}
