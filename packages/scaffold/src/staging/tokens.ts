import {
  TOKEN_PREFIX,
  HANDLE_PREFIX,
  TOKEN_SECRET_BYTES,
  HANDLE_BYTES,
} from "./types";

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
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
