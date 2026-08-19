import type { StagingConfig } from "./types";
import { lookupByHash, markCorrupt } from "./repo";
import { sha256Bearer, decryptFromStorage } from "./crypto";

export interface FetchDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  now?: () => number;
}

function parseBearer(req: Request): string | null {
  const h = req.headers.get("Authorization") ?? req.headers.get("authorization");
  if (!h) return null;
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return null;
  const v = m[1]!.trim();
  return v.startsWith("stg_") ? v : null;
}

function extractHandle(req: Request): string | null {
  const url = new URL(req.url);
  // Expect path: /staging/fetch/<file_handle>
  const m = url.pathname.match(/\/staging\/fetch\/([^/]+)$/);
  return m ? m[1]! : null;
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// row.filename originates from caller input; the Headers API throws on CR/LF,
// other control characters, and unpaired surrogates (the latter make
// encodeURIComponent throw a URIError inside rfc5987Encode) — strip all of
// them before using the value in any header.
function sanitizeFilenameForHeader(filename: string): string {
  return filename
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1F\x7F]/g, "")
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "");
}

// The Headers API also throws for any code point above 0xFF (it stores raw
// header values as ByteStrings). X-Filename is a plain, unencoded header, so
// unlike Content-Disposition it has no filename*/RFC 5987 escape hatch for
// those characters — substitute "_" rather than let the whole response 500.
function toByteStringSafeFilename(filename: string): string {
  let out = "";
  for (const ch of filename) {
    out += ch.codePointAt(0)! <= 0xff ? ch : "_";
  }
  return out;
}

function isRfc6266AsciiSafe(value: string): boolean {
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

function escapeQuotedString(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

// encodeURIComponent leaves `!`, `'`, `(`, `)`, `*` unescaped, but RFC 5987
// attr-char excludes them — encode those too.
function rfc5987Encode(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

// Builds an RFC 6266 Content-Disposition value from an already-sanitized
// (control-character-free) filename.
function buildContentDisposition(sanitizedFilename: string): string {
  if (isRfc6266AsciiSafe(sanitizedFilename)) {
    return `attachment; filename="${escapeQuotedString(sanitizedFilename)}"`;
  }
  let asciiFallback = "";
  for (const ch of sanitizedFilename) {
    const code = ch.codePointAt(0)!;
    asciiFallback += code >= 0x20 && code <= 0x7e ? ch : "_";
  }
  const encoded = rfc5987Encode(sanitizedFilename);
  return `attachment; filename="${escapeQuotedString(asciiFallback)}"; filename*=UTF-8''${encoded}`;
}

export async function handleFetch(req: Request, deps: FetchDeps): Promise<Response> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const bearer = parseBearer(req);
  if (!bearer) return new Response("forbidden", { status: 403 });
  const handle = extractHandle(req);
  if (!handle) return new Response("not found", { status: 404 });

  const token_hash = await sha256Bearer(bearer);
  const row = await lookupByHash(deps.STAGING_D1, token_hash);
  if (!row) return new Response("forbidden", { status: 403 });
  if (!timingSafeEqualStrings(row.file_handle, handle)) {
    return new Response("forbidden", { status: 403 });
  }
  if (row.state === "pending") return new Response("conflict", { status: 409 });
  if (row.state === "corrupt") return new Response("gone", { status: 410 });
  if (row.expires_at <= now()) return new Response("gone", { status: 410 });
  if (!row.r2_key || !row.iv) return new Response("internal", { status: 500 });

  const obj = await deps.STAGING_R2.get(row.r2_key);
  if (!obj) return new Response("internal", { status: 500 });
  const ciphertext = new Uint8Array(await obj.arrayBuffer());

  let plaintext: Uint8Array;
  try {
    plaintext = await decryptFromStorage(bearer, row.file_handle, ciphertext, row.iv);
  } catch {
    await markCorrupt(deps.STAGING_D1, token_hash);
    return new Response("gone", { status: 410 });
  }

  const headers = new Headers();
  headers.set("Content-Type", row.content_type ?? "application/octet-stream");
  headers.set("Content-Disposition", "attachment");
  if (row.filename) {
    // Truncate as code points (not UTF-16 units) so a surrogate pair is never
    // split, then only emit filename-bearing headers if anything survives
    // sanitization + truncation (e.g. a control-characters-only filename).
    const sanitizedFilename = [...sanitizeFilenameForHeader(row.filename)].slice(0, 255).join("");
    if (sanitizedFilename.length > 0) {
      headers.set("X-Filename", toByteStringSafeFilename(sanitizedFilename));
      headers.set("Content-Disposition", buildContentDisposition(sanitizedFilename));
    }
  }
  headers.set("Cache-Control", "no-store");
  return new Response(plaintext, { status: 200, headers });
}
