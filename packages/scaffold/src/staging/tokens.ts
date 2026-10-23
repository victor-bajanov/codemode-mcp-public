import {
  TOKEN_PREFIX,
  HANDLE_PREFIX,
  TOKEN_SECRET_BYTES,
  HANDLE_BYTES,
} from "./types";
import { decodeBase64Into, decodedLength } from "./codec";

const URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Unpadded base64url of a short random value (tokens and handles only).
function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.byteLength; i += 3) {
    const n = Math.min(3, bytes.byteLength - i);
    const v = (bytes[i]! << 16) | ((n > 1 ? bytes[i + 1]! : 0) << 8) | (n > 2 ? bytes[i + 2]! : 0);
    s += URL_CHARS[v >>> 18]! + URL_CHARS[(v >>> 12) & 63]!;
    if (n > 1) s += URL_CHARS[(v >>> 6) & 63]!;
    if (n > 2) s += URL_CHARS[v & 63]!;
  }
  return s;
}

// Strict unpadded base64url: no whitespace, no padding, url alphabet only.
function b64urlDecode(s: string): Uint8Array {
  if (s.includes("=")) throw new Error("invalid base64url");
  const out = new Uint8Array(decodedLength(s, 0, s.length, "url"));
  decodeBase64Into(s, 0, s.length, out, 0, "url");
  return out;
}

/** Constant-time (for equal lengths) string comparison. */
export function timingSafeEqualStrings(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomBytes(n: number): Uint8Array {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

export function mintToken(): string {
  return TOKEN_PREFIX + b64urlEncode(randomBytes(TOKEN_SECRET_BYTES));
}

export function mintFileHandle(): string {
  return HANDLE_PREFIX + b64urlEncode(randomBytes(HANDLE_BYTES));
}

export function decodeTokenSecret(token: string): Uint8Array {
  if (!token.startsWith(TOKEN_PREFIX)) {
    throw new Error("token: missing prefix");
  }
  const body = b64urlDecode(token.slice(TOKEN_PREFIX.length));
  if (body.byteLength !== TOKEN_SECRET_BYTES) {
    throw new Error(`token: expected ${TOKEN_SECRET_BYTES} bytes, got ${body.byteLength}`);
  }
  return body;
}

export function decodeHandleBytes(handle: string): Uint8Array {
  if (!handle.startsWith(HANDLE_PREFIX)) {
    throw new Error("handle: missing prefix");
  }
  const body = b64urlDecode(handle.slice(HANDLE_PREFIX.length));
  if (body.byteLength !== HANDLE_BYTES) {
    throw new Error(`handle: expected ${HANDLE_BYTES} bytes, got ${body.byteLength}`);
  }
  return body;
}

export function newR2Key(): string {
  // Random opaque key; not derived from token or handle.
  const a = randomBytes(16);
  return "stg/" + Array.from(a).map((x) => x.toString(16).padStart(2, "0")).join("");
}
