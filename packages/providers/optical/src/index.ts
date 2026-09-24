import { type ApiProvider, hintFromSpecInfo } from "@local/scaffold";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import specJson from "./spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { opticalElicitRenderers } from "./elicit-renderers.js";

const spec = specJson as unknown as OpenApiSpec;

// compactHint has no dedicated prose here — it's derived from the same
// spec.info.description that hintFromSpecInfo already surfaces as
// executeHint, clamped into the compact `execute` description's ≤200-char
// slot (description-budget-docs-surface spec D3 item 4). The full text
// remains executeHint, unclamped, feeding the `docs` tool's "provider"
// section.
//
// Word-boundary clamp, not sentence-boundary: this spec's first sentence is
// a 42-char title and its second is 235 chars, so a whole-sentence rule
// degenerated to just the title (review finding) — a truncated-but-real
// summary beats an intact-but-empty one. Markdown emphasis is stripped
// first: `**` / `*` render literally inside a tool description.
function clampAtWordBoundary(text: string, maxChars: number): string {
  const plain = text.replace(/\*+/g, "").replace(/\s+/g, " ").trim();
  if (plain.length <= maxChars) return plain;
  const cut = plain.lastIndexOf(" ", maxChars - 1);
  return `${plain.slice(0, cut > 0 ? cut : maxChars - 1).trimEnd()}…`;
}

const opticalExecuteHint = hintFromSpecInfo(spec);
const opticalCompactHint =
  opticalExecuteHint !== undefined
    ? clampAtWordBoundary(opticalExecuteHint, 200)
    : undefined;

export interface OpticalProps extends Record<string, unknown> {
  refreshToken: string;
  userId: string;
  email?: string;
}

export const opticalProvider: ApiProvider<OpticalProps> = {
  name: "optical",
  displayName: "Optical scheduler",
  oauth: {
    authorizeUrl: "https://scheduler.example.com/oauth/authorize",
    tokenUrl: "https://scheduler.example.com/oauth/token",
    // Must match the optical worker's per-client allowed_scopes exactly: its
    // /oauth/authorize fails loud (error=invalid_scope) on any scope outside the
    // allow-list, and the bare legacy `read`/`write` names are no longer it.
    scopes: ["scheduler:read", "scheduler:write"],
    clientIdSecretName: "OPTICAL_CLIENT_ID",
    clientSecretSecretName: "OPTICAL_CLIENT_SECRET",
    userInfoUrl: "https://scheduler.example.com/oauth/userinfo",
    pkce: "s256",
  },
  spec,
  executeHint: opticalExecuteHint,
  compactHint: opticalCompactHint,
  surfaceReview,
  elicitRenderers: opticalElicitRenderers,
  apiBaseUrl: "https://scheduler.example.com",
  tokenRotation: "rotating",
  audit: {
    principalIdAccessor: (props) => props.userId,
  },
};

export { spec, surfaceReview };
