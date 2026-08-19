import { z } from "zod";
import type { StagingConfig, RegisterInput, RegisterOutput } from "./types";
import { mintToken, mintFileHandle } from "./tokens";
import { sha256Bearer } from "./crypto";
import { insertPending } from "./repo";
import { buildCompactRegisterFileHandleDescription } from "../descriptions/compact";
import { GENERIC_STEP_THREE } from "../descriptions/fragments";

// Re-export from the fragments module (moved there at integration so the docs
// builder shares the same constant without an import cycle).
export { GENERIC_STEP_THREE } from "../descriptions/fragments";

export interface RegisterToolDeps {
  STAGING_D1: D1Database;
  config: StagingConfig;
  uploadOrigin: string;     // e.g., "https://xero.example.com"
  /** Provider-specific Step-3 guidance (see ApiProvider.attachmentHint) — upload
   *  direction only. Spliced verbatim into this tool's description, replacing
   *  the generic fallback. Ignored when `descriptionMode: "compact"` (spec D3:
   *  the compact body never splices provider-specific content; it points at
   *  the `docs` tool's "attachments" section instead). */
  attachmentHint?: string;
  /** "full" (default): today's complete description, byte-identical to
   *  before this field existed. "compact": the ≤900-char budgeted body from
   *  `buildCompactRegisterFileHandleDescription()`, for callers serving this
   *  tool under the description-budget-docs-surface scheme. */
  descriptionMode?: "full" | "compact";
  now?: () => number;
}

export const REGISTER_TOOL_INPUT_SHAPE = {
  content_type: z
    .string()
    .optional()
    .describe(
      "MIME type of the file you intend to upload (optional hint; enforced on upload if provided).",
    ),
  expected_byte_len: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Expected size in bytes (optional hint)."),
  filename: z
    .string()
    .max(255)
    .optional()
    .describe("Original filename (optional, retained as metadata; max 255 characters)."),
} as const;

export interface RegisterTool {
  name: "register_file_handle";
  description: string;
  inputShape: typeof REGISTER_TOOL_INPUT_SHAPE;
  handler(input: RegisterInput): Promise<RegisterOutput>;
}

export function registerFileHandleTool(deps: RegisterToolDeps): RegisterTool {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const stepThree = deps.attachmentHint ?? GENERIC_STEP_THREE;
  const description =
    deps.descriptionMode === "compact"
      ? buildCompactRegisterFileHandleDescription()
      : "USE THIS TO UPLOAD / SEND A FILE **TO** the upstream API. Reserves a single-use upload slot and returns a bearer token + file_handle. " +
        "Required because the sandbox cannot accept Uint8Array/ArrayBuffer over codemode.request (the RPC marshals via JSON.stringify) — staging is the binary channel.\n\n" +
        "Downloading or exporting bytes FROM the upstream API is a different flow that never calls this tool — use the staging download modes (Mode A/B) documented in the `execute` tool description.\n\n" +
        "Step 1 — upload the bytes out-of-band, BEFORE execute() (do this from your own host / curl / etc.):\n" +
        "  POST <upload_url> with header `Authorization: Bearer <token>` and the file bytes as the request body. " +
        "Must happen within upload_ttl_seconds. A 204 response confirms the upload.\n\n" +
        "Step 2 — inside execute(), read the bytes via the __stagingHost sandbox capability:\n" +
        "  const f = await __stagingHost.getFile(file_handle, token);\n" +
        "  // __stagingHost is a sandbox-scope capability (NOT codemode.* and NOT on globalThis).\n" +
        "  // f = { ok: true, contentType, byteLength, filename, bytesBase64 } | { ok: false, status, message }\n" +
        "  // bytesBase64 is standard base64; available for up to fetch_ttl_seconds after upload.\n\n" +
        stepThree;
  return {
    name: "register_file_handle",
    description,
    inputShape: REGISTER_TOOL_INPUT_SHAPE,
    async handler(input: RegisterInput): Promise<RegisterOutput> {
      const token = mintToken();
      const file_handle = mintFileHandle();
      const token_hash = await sha256Bearer(token);
      const created_at = now();
      await insertPending(deps.STAGING_D1, {
        token_hash,
        file_handle,
        content_type_hint: input.content_type ?? null,
        expected_byte_len: input.expected_byte_len ?? null,
        filename: input.filename ?? null,
        created_at,
        expires_at: created_at + deps.config.uploadTtlSeconds,
      });
      return {
        token,
        file_handle,
        upload_url: `${deps.uploadOrigin.replace(/\/$/, "")}/staging/upload`,
        max_bytes: deps.config.maxBytes,
        upload_ttl_seconds: deps.config.uploadTtlSeconds,
        fetch_ttl_seconds: deps.config.fetchTtlSeconds,
      };
    },
  };
}
