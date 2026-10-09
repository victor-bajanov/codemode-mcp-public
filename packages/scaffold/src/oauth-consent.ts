/**
 * Consent interstitial helpers for `GET`/`POST /authorize` (F-2, F-15, F-20).
 *
 * `GET /authorize` no longer redirects straight to the upstream IdP. It renders
 * a consent page naming the MCP client, the redirect URI (host emphasised) and
 * the scopes, carrying a short-lived form token signed with HMAC-SHA256 under
 * `COOKIE_ENCRYPTION_KEY`. The token is bound to a per-flow `__Host-`
 * `SameSite=Strict` cookie, so a cross-site auto-submitted form (which carries
 * no Strict cookie) is refused, and it is single-use via a KV marker. Only an
 * explicit operator approval (`POST /authorize`) starts the upstream leg.
 *
 * Everything here is a pure helper (no KV, no routing) so it can be unit tested
 * in isolation; the flow itself lives in `oauth-handler.ts`.
 */

import type { AuthRequest } from "@cloudflare/workers-oauth-provider";

/** Lifetime of a consent form token and its cookie, in seconds. */
export const CONSENT_TTL_SEC = 300;
/** Per-flow consent cookie (`SameSite=Strict`), suffixed with the token id. */
export const CONSENT_COOKIE_PREFIX = "__Host-cm-consent-";
/** Per-flow browser-binding cookie (`SameSite=Lax`), suffixed with the state. */
export const AUTH_COOKIE_PREFIX = "__Host-cm-auth-";
/** KV marker recording that a consent token id has been used. */
export const CONSENT_USED_KV_PREFIX = "consent-used:";

/** Domain-separation prefix mixed into every consent-token MAC. */
const MAC_CONTEXT = "codemode-consent-v1.";

export interface ConsentTokenPayload {
  v: 1;
  /** Random id naming the consent cookie and the single-use KV marker. */
  id: string;
  /** Random value that must equal the consent cookie's value. */
  nonce: string;
  /** Expiry, epoch seconds. */
  exp: number;
  /** The parsed MCP authorisation request being consented to. */
  req: AuthRequest;
}

// --- encoding ---

function base64UrlFromBytes(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url (no padding); throws on characters outside the alphabet. */
function bytesFromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- signing key + token ---

/**
 * Import `COOKIE_ENCRYPTION_KEY` as a non-extractable HMAC-SHA256 key. Throws
 * when the key is missing or shorter than 32 characters (the same floor
 * `assertSecrets` enforces at the worker boundary).
 */
export async function consentKey(env: { COOKIE_ENCRYPTION_KEY?: unknown }): Promise<CryptoKey> {
  const raw = env.COOKIE_ENCRYPTION_KEY;
  if (typeof raw !== "string" || raw.length < 32) {
    throw new Error("COOKIE_ENCRYPTION_KEY is missing or too short (require >=32 chars)");
  }
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(raw),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** `base64url(JSON) + "." + base64url(HMAC(context + base64url(JSON)))`. */
export async function signConsentToken(
  key: CryptoKey,
  payload: ConsentTokenPayload,
): Promise<string> {
  const body = base64UrlFromBytes(new TextEncoder().encode(JSON.stringify(payload)));
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(MAC_CONTEXT + body));
  return `${body}.${base64UrlFromBytes(new Uint8Array(mac))}`;
}

function isAuthRequestShape(v: unknown): v is AuthRequest {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r.clientId === "string" &&
    typeof r.redirectUri === "string" &&
    typeof r.responseType === "string" &&
    typeof r.state === "string" &&
    Array.isArray(r.scope) &&
    r.scope.every((s) => typeof s === "string")
  );
}

/**
 * Verify a consent token and return its payload, or `null` when it is
 * malformed, carries a bad signature, has the wrong version or has expired.
 * Never throws on attacker-supplied input.
 */
export async function verifyConsentToken(
  key: CryptoKey,
  token: string,
  nowSec: number,
): Promise<ConsentTokenPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const [body, sig] = parts as [string, string];
    if (!body || !sig) return null;
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      bytesFromBase64Url(sig),
      new TextEncoder().encode(MAC_CONTEXT + body),
    );
    if (!ok) return null;
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytesFromBase64Url(body)));
    if (typeof parsed !== "object" || parsed === null) return null;
    const p = parsed as Record<string, unknown>;
    if (p.v !== 1) return null;
    if (typeof p.id !== "string" || typeof p.nonce !== "string") return null;
    if (typeof p.exp !== "number" || !Number.isFinite(p.exp)) return null;
    if (nowSec >= p.exp) return null;
    if (!isAuthRequestShape(p.req)) return null;
    return parsed as ConsentTokenPayload;
  } catch {
    return null;
  }
}

// --- cookies ---

/** Read one cookie value from the request's `Cookie` header, or `null`. */
export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

/** `Set-Cookie` value for a `__Host-`-compatible cookie (always `Path=/; Secure; HttpOnly`). */
export function setCookie(
  name: string,
  value: string,
  opts: { maxAge: number; sameSite: "Strict" | "Lax" },
): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${opts.sameSite}; Max-Age=${opts.maxAge}`;
}

/** `Set-Cookie` value that deletes `name`. */
export function clearCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

// --- random values ---

/** 16 random bytes, hex. Names the consent cookie and the single-use marker. */
export function randomId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** 32 random bytes, base64url. Cookie values for consent and browser binding. */
export function randomNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlFromBytes(bytes);
}

// --- consent page ---

/** Redirect hosts the page does not warn about: Claude over https, loopback
 *  over http or https. */
const CLAUDE_REDIRECT_HOSTS = new Set(["claude.ai", "claude.com"]);
const LOOPBACK_REDIRECT_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** True when `redirectUri` parses as `https:` to a Claude host, or `http:` or
 *  `https:` to a loopback host. The scheme matters: `evil://claude.ai/cb` has
 *  hostname `claude.ai` but is handed to whatever app claims `evil:`. */
export function isKnownRedirectHost(redirectUri: string): boolean {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return false;
  }
  if (url.protocol === "https:" && CLAUDE_REDIRECT_HOSTS.has(url.hostname)) return true;
  return (url.protocol === "http:" || url.protocol === "https:") && LOOPBACK_REDIRECT_HOSTS.has(url.hostname);
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** The redirect URI as HTML with its host in bold (plain escaped text if unparseable). */
function renderRedirectUri(redirectUri: string): string {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return escapeHtml(redirectUri);
  }
  const href = url.href;
  const slashes = href.indexOf("//");
  if (!url.host || slashes < 0) return escapeHtml(href);
  // Skip any userinfo (`https://claude.ai@attacker.example/`) so the bold part
  // is the host the browser will actually contact.
  const authority = href.slice(slashes + 2);
  const at = url.username || url.password ? authority.indexOf("@") + 1 : 0;
  const hostStart = slashes + 2 + at;
  if (!href.startsWith(url.host, hostStart)) return escapeHtml(href);
  const hostEnd = hostStart + url.host.length;
  return (
    escapeHtml(href.slice(0, hostStart)) +
    `<strong>${escapeHtml(url.host)}</strong>` +
    escapeHtml(href.slice(hostEnd))
  );
}

function renderScopeList(scopes: readonly string[]): string {
  if (scopes.length === 0) return "<em>none</em>";
  return `<ul class="scopes">${scopes.map((s) => `<li><code>${escapeHtml(s)}</code></li>`).join("")}</ul>`;
}

/**
 * The codemode "Gate" mark: many operations meet one reviewed gate and only
 * `search` and `execute` come out. The accent is Optical's brand blue. Kept
 * inline because the page CSP (`default-src 'none'`) refuses external images.
 */
const LOGO_SVG =
  '<svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40" role="img" aria-label="codemode">' +
  '<path d="M3 6h4M3 12h4M3 18h4" stroke="currentColor" stroke-width="3" stroke-linecap="round" opacity=".55"/>' +
  '<path d="M12 3.5v17" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>' +
  '<path d="M17 9h4.5M17 15h4.5" stroke="#0A66FF" stroke-width="3" stroke-linecap="round"/>' +
  "</svg>";

export interface ConsentPageArgs {
  providerName: string;
  clientName: string | undefined;
  redirectUri: string;
  upstreamScopes: readonly string[];
  token: string;
  knownRedirectHost: boolean;
}

/**
 * Minimal consent page. Every interpolated value is HTML-escaped. The form
 * posts back to `/authorize` so the Cloudflare Access application that gates
 * `GET /authorize` also gates the approval.
 */
export function renderConsentPage(args: ConsentPageArgs): string {
  const provider = escapeHtml(args.providerName);
  const client = args.clientName
    ? escapeHtml(args.clientName)
    : "<em>an application that did not give a name</em>";
  let host = "";
  try {
    host = new URL(args.redirectUri).host;
  } catch {
    host = args.redirectUri;
  }
  const warning = args.knownRedirectHost
    ? ""
    : `<p class="warn" role="alert"><strong>Warning:</strong> this application will receive ` +
      `access to your ${provider} account through <strong>${escapeHtml(host)}</strong>, which ` +
      `is not a known MCP client. Only approve if you started this connection yourself and ` +
      `recognise that host.</p>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorise access to ${provider}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:36rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a;background:#fff}
.uri{word-break:break-all;font-family:ui-monospace,monospace;background:#f4f4f4;padding:.5rem;border-radius:4px}
.warn{background:#fff4e5;border:1px solid #e08a00;padding:.75rem;border-radius:4px}
.logo{display:block;margin-bottom:.5rem}
.scopes{padding-left:1.25rem;word-break:break-all}
button{font-size:1rem;padding:.5rem 1.25rem;margin-right:.5rem;cursor:pointer}
</style>
</head>
<body>
${LOGO_SVG}
<h1>Authorise access to ${provider}</h1>
<p>${client} is asking to use this ${provider} connector on your behalf.</p>
<p>After you approve and sign in to ${provider}, access will be sent to:</p>
<p class="uri">${renderRedirectUri(args.redirectUri)}</p>
${warning}
<p>${provider} scopes:</p>
${renderScopeList(args.upstreamScopes)}
<form method="post" action="/authorize">
<input type="hidden" name="consent_token" value="${escapeHtml(args.token)}">
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>`;
}

/**
 * Response headers for the consent page: never cached, never framed
 * (clickjacking), no referrer. Deliberately NO CSP `form-action`: Chrome
 * applies it to the redirect that follows the form submission, which would
 * block the 303 to the upstream IdP.
 */
export function consentPageHeaders(setCookieValue: string): Headers {
  const h = new Headers();
  h.set("content-type", "text/html; charset=utf-8");
  h.set("cache-control", "no-store");
  h.set(
    "content-security-policy",
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  );
  h.set("x-frame-options", "DENY");
  h.set("referrer-policy", "no-referrer");
  h.append("set-cookie", setCookieValue);
  return h;
}
