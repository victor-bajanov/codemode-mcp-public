import type { ElicitRenderer } from "@local/shared";

// No elicit entries in surface-review.ts today — Claude.ai doesn't render
// elicit prompts, so every op is `allow`. Keep this file for parity with
// gmail/xero so future categorisations have a home.
export const opticalElicitRenderers: Partial<Record<string, ElicitRenderer>> = {};
