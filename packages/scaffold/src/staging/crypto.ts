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
