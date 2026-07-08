// Inspector for `users.settings.sendAs.create`.
//
// Validates that `sendAsEmail` is on the outbound recipient allowlist using
// the shared `isAllowedRecipient` matcher. The body's `smtpMsa` sub-object
// is now inspected via `inspectSmtpMsa` (host-allowlist enforcement).

import type { InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient } from "./allowlist.js";
import { inspectSmtpMsa } from "./smtp-msa.js";

export function inspectSendAsCreate(req: InspectRequest): InspectResult {
  const body = req.body;
  if (typeof body !== "object" || body === null) {
    return { decision: "deny", category: "malformed", reason: "sendas-no-email" };
  }
  const msaResult = inspectSmtpMsa(body);
  if (msaResult) return msaResult;
  const email = (body as Record<string, unknown>)["sendAsEmail"];
  if (typeof email !== "string" || email.length === 0) {
    return { decision: "deny", category: "malformed", reason: "sendas-no-email" };
  }
  if (!isAllowedRecipient(email)) {
    return { decision: "deny", category: "capability_escalation", reason: "external-sendas" };
  }
  return { decision: "allow" };
}
