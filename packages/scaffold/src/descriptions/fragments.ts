// Description fragments shared by the execute-addendum builder
// (mcp-agent-factory.ts), the docs builder (./docs.ts), and the compact
// description builders (./compact.ts). Moved verbatim out of
// mcp-agent-factory.ts (Task 1 of the description-budget plan); the factory
// re-exports the public names so existing import sites keep working.

import { SURFACE_REVIEW_MARKER } from "../annotate-spec";

// Always-included envelope contract block. The library's base description
// (openApiMcpServer) declares `request(): Promise<unknown>` and its example
// returns the raw call result, so without this block clients routinely read
// the upstream payload off the envelope's top level instead of `.result`.
export const ENVELOPE_BLOCK =
  "## Response envelope — codemode.request() never resolves to the raw API payload\n\n" +
  "Every codemode.request() call resolves to this envelope (it does NOT throw on non-2xx):\n\n" +
  "  {\n" +
  "    success: boolean,  // true iff upstream status is 2xx\n" +
  "    status: number,    // upstream HTTP status\n" +
  "    result: unknown,   // upstream response body (JSON-parsed when possible) — the API payload is ALWAYS here\n" +
  "    errors: { code: number, message: string }[],  // empty on success\n" +
  "  }\n\n" +
  "Always check `.success` and read the API data from `.result` — fields like messages/items/Invoices live under `.result`, never at the top level:\n\n" +
  "  const r = await codemode.request({ method: \"GET\", path: \"/...\" });\n" +
  "  if (!r.success) throw new Error(`HTTP ${r.status}: ${r.errors[0]?.message}`);\n" +
  "  return r.result;  // return the unwrapped payload, not `r`\n\n";

// Appended to the envelope block only for providers that parse upstream
// rate-limit headers (`ApiProvider.readRateLimit`). Without it the LLM sees the
// extra envelope key with no idea what to do with it, and retries a 429
// immediately — the one behaviour the upstream is asking it not to do.
export const RATE_LIMIT_BLOCK =
  "This server also reports the upstream API's rate-limit state on the envelope:\n\n" +
  "    rateLimit?: {\n" +
  "      problem?: string,             // which limit was hit (429 only), e.g. \"minute\"\n" +
  "      limit?: string,               // human-readable expansion of `problem`\n" +
  "      retryAfterSeconds?: number,   // how long upstream asked you to wait (429 only)\n" +
  "      remaining?: Record<string, number>,  // remaining calls per window, e.g. { day, minute, appMinute }\n" +
  "      message?: string,             // one-line explanation (also prefixed onto errors[0].message)\n" +
  "    }\n\n" +
  "On `status === 429` read `r.rateLimit` and report it — do NOT retry immediately, and never retry in a tight loop. " +
  "If `retryAfterSeconds` is small (a few seconds) you may wait it out once before retrying the SAME call; otherwise stop and tell the user which limit was hit and when to try again. " +
  "`rateLimit.remaining` is present on successful calls too — when a counter approaches 0, batch or stop rather than fanning out more calls.\n\n";

// Splice into the codemode `execute` tool's description when this server has
// staging bindings (STAGING_D1 + STAGING_R2 + STAGING_UPLOAD_ORIGIN). Documents
// the register_file_handle → bytes-out-of-band → __stagingHost.getFile workflow
// plus the three modes for returning large binary payloads from execute().
export const STAGING_BLOCK =
  "\n## Attachments / file uploads — ALWAYS use `register_file_handle` first (upload direction: sending bytes TO the upstream API)\n\n" +
  "When the user wants to attach, upload, or send a file TO the upstream API, " +
  "this workflow is fixed and non-negotiable:\n\n" +
  "  1. Call the `register_file_handle` tool (NOT codemode.request) → get { upload_url, token, file_handle }.\n" +
  "  2. POST the file bytes to upload_url out-of-band, with `Authorization: Bearer <token>` (your runtime/host does this — bytes never enter execute()).\n" +
  "  3. Inside execute(), read the bytes via the sandbox capability:\n" +
  "       const f = await __stagingHost.getFile(file_handle, token);\n" +
  "       // f = { ok: true, contentType, byteLength, filename, bytesBase64 } | { ok: false, status, message }\n" +
  "       // __stagingHost is a sandbox-scope local (NOT on codemode.*, NOT on globalThis).\n" +
  "  4. Forward `f.bytesBase64` to the upstream API per the provider-specific snippet below.\n\n" +
  "Downloading or exporting bytes FROM the upstream API is the opposite direction — skip `register_file_handle` entirely and use one of the three modes documented below instead.\n\n" +
  "Do NOT try to read files from disk, embed bytes literally in code, fetch URLs into Uint8Array, or pass Uint8Array/ArrayBuffer through codemode.request — none of those paths reach the host as binary. A Uint8Array/ArrayBuffer anywhere in codemode.request `body`, `query` or `multipart` (with or without `rawBody`) is rejected by the host with an error. Use `register_file_handle` (above) or `bodyBase64`/`multipart` (below) instead.\n\n" +
  "## Returning large binary payloads from execute() — three modes\n\n" +
  "When upstream responses contain multi-MB binary, DO NOT return the bytes inline (`r.result.data`); they will be truncated to ~64KB by the response budget AND flood your context on the next turn. Use one of the three modes below.\n\n" +
  "**Mode A — JSON envelope with base64 field (e.g. Gmail attachments.get returns `{size, attachmentId, data: <base64url>}` — no MIME type in the envelope at all). Also callable as `__stagingHost.stageFromAttachment` — same function, task-shaped alias:**\n\n" +
  "  const f = await __stagingHost.stageFromUpstreamJson(\n" +
  "    { method: \"GET\", path: \"/<endpoint>\" },\n" +
  "    \"data\",            // field name in the JSON envelope\n" +
  "    \"base64url\",       // \"base64url\" (default, Gmail) or \"base64\"\n" +
  "    filename ?? null,  // staged filename; null lets the host omit it\n" +
  "    contentType ?? null,  // pass the MIME type you already have (e.g. from the parent message part) — the envelope usually has no MIME type at all; Gmail's never does\n" +
  "  );\n" +
  "  if (!f.ok) throw new Error(`stage: ${f.status} ${f.message}`);\n" +
  "  return { file_handle: f.file_handle, token: f.token, fetch_url: f.fetch_url, byte_length: f.byte_length };\n\n" +
  "Host extracts the field server-side (no 64KB cap, no base64url→base64 conversion needed). Content-Type precedence: your `contentType` arg → envelope `result.mimeType` → `application/octet-stream`.\n\n" +
  "**Mode B — Raw upstream body (e.g. Xero `/api.xro/2.0/Invoices/{id}/Attachments/{name}` with `Accept: application/octet-stream`):**\n\n" +
  "  const r = await codemode.request({\n" +
  "    method: \"GET\",\n" +
  "    path: \"/<endpoint>\",\n" +
  "    headers: { Accept: \"application/octet-stream\" },\n" +
  "    returnAs: \"stage\",   // bytes go upstream→R2 server-side; r.result is the file-handle envelope\n" +
  "  });\n" +
  "  if (!r.success) throw new Error(`stage: ${r.status}`);\n" +
  "  return { file_handle: r.result.file_handle, token: r.result.token, fetch_url: r.result.fetch_url, byte_length: r.result.byte_length };\n\n" +
  "On 2xx upstream the bytes are staged automatically; Content-Type and filename are taken from the upstream response headers (Content-Disposition). On non-2xx, the normal error envelope is returned (no staging).\n\n" +
  "**Mode C — Bytes you computed in execute() (fallback when neither A nor B applies):**\n\n" +
  "  const f = await __stagingHost.putFile(bytesAsBase64, contentType, filename ?? null);\n" +
  "  if (!f.ok) throw new Error(`stage: ${f.status} ${f.message}`);\n" +
  "  return { file_handle: f.file_handle, token: f.token, fetch_url: f.fetch_url, byte_length: f.byte_length };\n\n" +
  "Use this only when the bytes originate inside execute() (e.g. you computed them, decompressed something, merged multiple sources). For upstream payloads, prefer Mode A or B — they avoid pulling the bytes through your context entirely.\n\n" +
  "The client (or user) downloads any staged file with:\n" +
  "  curl -H \"Authorization: Bearer <token>\" <fetch_url> -o file.bin\n\n" +
  "That response carries `Content-Type` and `Content-Disposition: attachment`; when the staging recorded a filename, it also carries `X-Filename` and a `filename=` clause.\n\n" +
  "Notes:\n" +
  "- The token is short-lived (default 60 min, matches getFile). After expiry the row is swept and the URL returns 410.\n" +
  "- A later turn in this same conversation can re-pull the bytes via `__stagingHost.getFile(file_handle, token)` if needed.\n\n";

// Always-included codemode.request body-modes block. Documents the JSON / text
// rawBody / bodyBase64 / multipart escape hatches. A Uint8Array/ArrayBuffer in
// `body`, `query` or `multipart` is rejected by the host with an error (with
// or without rawBody; see request-handler.ts); use bodyBase64/multipart.
export const BODY_MODES_BLOCK =
  "## codemode.request body modes (binary / non-JSON)\n\n" +
  "A Uint8Array/ArrayBuffer in codemode.request `body`, `query` or `multipart` is rejected by the host with an error, so use the explicit binary modes below. " +
  "`rawBody: true` only suppresses JSON serialisation of `body` — it does NOT enable Uint8Array/ArrayBuffer passthrough. " +
  "The host-side modes (handled by this server, forwarded verbatim upstream):\n\n" +
  "  • Default (JSON):       `body: {...}` → serialised; Content-Type defaults to application/json.\n" +
  "  • Text body:            `body: \"…\", rawBody: true, contentType: \"…\"` (e.g. application/xml). Do NOT use rawBody with binary.\n" +
  "  • Binary octet-stream:  `bodyBase64: \"<base64>\", contentType: \"…\"` — host decodes base64 before fetching.\n" +
  "  • multipart/form-data:  `multipart: [{ name, filename?, contentType?, value? | bodyBase64? }, …]` — host generates the boundary and Content-Type; do NOT set `contentType` yourself.\n" +
  "  • contentType is forwarded (edge whitespace trimmed) for body / bodyBase64 / rawBody; only `multipart` overrides it.\n" +
  "  • Use exactly one of `body`, `bodyBase64` and `multipart`. On operations that are inspected or need approval, two are refused, and bytes under a JSON content-type (including text/json) must parse: they are judged and sent as that parsed JSON.\n\n";

/**
 * codemode truncates every `search` / `execute` result at this many characters
 * and appends only a footer — the excess is gone, and the model is not told
 * WHICH operations it lost. Mirrors `MAX_TOKENS (6e3) * CHARS_PER_TOKEN (4)` in
 * `@cloudflare/codemode/dist/mcp.js` (see the `const` block at the top of that
 * file). Not imported because codemode does not export it; kept honest by
 * __tests__/codemode-cap-drift.test.ts, which reads the installed bundle and
 * fails if either constant moves.
 */
export const RESPONSE_CHAR_CAP = 24_000;

/** Operations in a spec, flattened. */
function specOperations(
  spec: unknown,
): Array<{ operationId: string; description?: string }> {
  const out: Array<{ operationId: string; description?: string }> = [];
  const paths = (spec as { paths?: Record<string, Record<string, unknown>> })?.paths ?? {};
  for (const item of Object.values(paths)) {
    if (typeof item !== "object" || item === null) continue;
    for (const op of Object.values(item)) {
      const o = op as { operationId?: unknown; description?: unknown };
      if (typeof o?.operationId === "string") {
        out.push({
          operationId: o.operationId,
          ...(typeof o.description === "string" ? { description: o.description } : {}),
        });
      }
    }
  }
  return out;
}

/** How many leading rows fit under the cap, measured the way codemode measures
 *  it: `JSON.stringify(content, null, 2)`, so per-row punctuation and indent
 *  count. */
function fitCount(rows: unknown[]): number {
  let n = 0;
  for (let i = 1; i <= rows.length; i++) {
    if (JSON.stringify(rows.slice(0, i), null, 2).length <= RESPONSE_CHAR_CAP) n = i;
    else break;
  }
  return n;
}

/**
 * Scan-then-drill guidance, with THIS spec's real sizes measured at build time.
 *
 * The numbers are computed, never hardcoded: they differ per provider (Xero 283
 * operations, Gmail 116, optical 33) and would rot as specs are regenerated.
 * Computed once per Durable Object in `init()`, not per request.
 */
export function buildSearchStrategyBlock(annotatedSpec: unknown): string {
  const ops = specOperations(annotatedSpec);
  if (ops.length === 0) return "";
  const idFit = fitCount(ops.map((o) => o.operationId));
  const descFit = fitCount(ops.map((o) => ({ operationId: o.operationId, description: o.description })));

  return (
    "## Searching this spec — scan ids first, then drill\n\n" +
    `Results are truncated at ${RESPONSE_CHAR_CAP} chars (~6,000 tokens): the overflow is dropped and a ` +
    "`--- TRUNCATED ---` footer added that does NOT say what you lost. If you see it, narrow the " +
    "query and re-run.\n\n" +
    `This spec has ${ops.length} operations. operationIds alone fit ${idFit} of ${ops.length} in one ` +
    `call; operationId + description fits only ~${descFit}, so a broad description sweep silently ` +
    "drops the rest. Scan ids, pick the few you need, then fetch their detail:\n\n" +
    "  // 1. every id, one call\n" +
    "  async () => { const s = await codemode.spec();\n" +
    "    return Object.values(s.paths).flatMap(i => Object.values(i).map(o => o.operationId).filter(Boolean)); }\n\n" +
    "  // 2. detail for the ones you picked\n" +
    "  async () => { const s = await codemode.spec(), want = new Set([\"op.one\",\"op.two\"]);\n" +
    "    return Object.entries(s.paths).flatMap(([p,i]) => Object.values(i)\n" +
    "      .filter(o => want.has(o.operationId)).map(o => ({ path: p, description: o.description }))); }\n\n"
  );
}

// Always included, because every provider's spec is annotated by
// `annotateSpecWithSurfaceReview` and therefore every provider's client sees
// `[ACCESS: …]` markers. Without this the convention is only explained where a
// provider happens to hand-write it into its executeHint — and the load-bearing
// half is what ABSENCE means: an unmarked operation is plainly available, which
// is why the large majority of operations carry no marker and cost nothing.
export const ACCESS_CONVENTION_BLOCK =
  `## Operation availability — the \`${SURFACE_REVIEW_MARKER}\` line\n\n` +
  "Not every operation in this spec is callable. Each one that is restricted says so in its " +
  `own \`description\`, after an \`${SURFACE_REVIEW_MARKER}\` line: whether it is denied outright, ` +
  "needs interactive approval (which most clients, Claude.ai included, cannot give — the call " +
  "then just fails), or is allowed but inspected at call time, along with what that inspection " +
  `requires of your request. Where an operation also has a \`summary\`, a short ` +
  "`[ACCESS: …]` tag is appended there too, pointing at the same detail.\n\n" +
  `An operation with NO \`${SURFACE_REVIEW_MARKER}\` line is plainly available — most are. Read the ` +
  "line before planning a call, and prefer reporting an operation as unavailable over calling " +
  "it and hoping.\n\n";

// Provider-agnostic Step-3 fallback for the staging upload workflow. Consumed
// by BOTH the `register_file_handle` tool description (staging/register-tool.ts,
// when the provider sets no attachmentHint) and the docs builder's
// `attachments` section — single source, so the docs section always matches
// the live tool text. Lives here (not in register-tool.ts) because
// register-tool → descriptions/compact → descriptions/docs would otherwise
// close an import cycle back into register-tool.
export const GENERIC_STEP_THREE =
  "Step 3 — forward the bytes to the upstream API in the same execute() call.\n" +
  "  • Binary endpoints (PUT/POST raw bytes): pass `bodyBase64: f.bytesBase64` and set `contentType`; the host decodes before fetching.\n" +
  "  • JSON endpoints that take base64 inline (e.g. an attachment field): place `f.bytesBase64` directly in the JSON body.\n" +
  "  • multipart/form-data endpoints: use `multipart: [{ name, filename, contentType, bodyBase64 }, ...]` (the host generates the boundary; do NOT set contentType yourself for multipart).";
