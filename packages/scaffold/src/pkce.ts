// packages/scaffold/src/pkce.ts
//
// PKCE (Proof Key for Code Exchange, RFC 7636) helpers for the
// authorization-code OAuth flow used by the scaffold.
//
// `generateCodeVerifier()` returns a 43-char base64url string (32 random
// bytes, base64url-encoded with no padding). `sha256Base64Url(s)` returns
// the SHA-256 of `s` as a base64url string (no padding) — used to derive
// the `code_challenge` value for the `S256` method.

export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function sha256Base64Url(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return base64UrlEncode(new Uint8Array(buf));
}

function base64UrlEncode(bytes: Uint8Array): string {
  const s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
