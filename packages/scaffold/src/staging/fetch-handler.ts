import type { StagingConfig } from "./types";
import { StagedFileReadError, openStagedFile } from "./staged-file";
import { createFixedLengthSink } from "./sinks";

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

  const opened = await openStagedFile(deps, { file_handle: handle, token: bearer });
  if (!opened.ok) {
    switch (opened.status) {
      case 400:
      case 403:
        return new Response("forbidden", { status: 403 });
      case 409:
        return new Response("conflict", { status: 409 });
      case 410:
        return new Response("gone", { status: 410 });
      default:
        return new Response("internal", { status: 500 });
    }
  }
  const file = opened.file;
  const byteLen = file.meta.byteLength;

  // Commit to a 200 only once the object's size checks out and the first
  // block has authenticated, so a single-block file that is corrupt is a clean
  // 410. Later blocks stream through a fixed-length sink; a failure there
  // aborts the body (the client sees an error, never a clean short EOF).
  const sink = createFixedLengthSink(byteLen);
  let firstBlock!: () => void;
  const firstBlockReady = new Promise<void>((resolve) => {
    firstBlock = resolve;
  });
  const pump = file
    .readBlocks(async (plain) => {
      firstBlock();
      await sink.write(plain);
    })
    .then(() => sink.close());
  const early = await Promise.race([
    firstBlockReady.then(() => null),
    pump.then(
      () => null,
      (e: unknown) => e ?? new Error("read failed"),
    ),
  ]);
  if (early !== null) {
    await sink.abort(early);
    const status = early instanceof StagedFileReadError ? early.status : 500;
    return new Response(status === 410 ? "gone" : "internal", { status });
  }
  // Errors after the first block abort the sink; the consumer sees them.
  pump.catch((e: unknown) => sink.abort(e));

  const headers = new Headers();
  headers.set("Content-Type", file.meta.contentType);
  headers.set("Content-Disposition", "attachment");
  if (file.meta.filename) {
    // Truncate as code points (not UTF-16 units) so a surrogate pair is never
    // split, then only emit filename-bearing headers if anything survives
    // sanitization + truncation (e.g. a control-characters-only filename).
    const sanitizedFilename = [...sanitizeFilenameForHeader(file.meta.filename)].slice(0, 255).join("");
    if (sanitizedFilename.length > 0) {
      headers.set("X-Filename", toByteStringSafeFilename(sanitizedFilename));
      headers.set("Content-Disposition", buildContentDisposition(sanitizedFilename));
    }
  }
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Length", String(byteLen));
  return new Response(sink.readable, { status: 200, headers });
}
