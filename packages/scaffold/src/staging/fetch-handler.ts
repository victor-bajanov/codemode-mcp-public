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
  if (row.filename) headers.set("X-Filename", row.filename);
  headers.set("Cache-Control", "no-store");
  return new Response(plaintext, { status: 200, headers });
}
