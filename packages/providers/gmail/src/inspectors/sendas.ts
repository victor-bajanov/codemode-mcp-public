// Inspector for `users.settings.sendAs.create`.
//
// Validates that `sendAsEmail` is on the deployment's outbound recipient
// allowlist (OUTBOUND_RECIPIENT_ALLOWLIST var; missing env/var → empty list,
// so any sendAsEmail denies) using the shared `isAllowedRecipient` matcher.
// The body's `smtpMsa` sub-object is inspected via `inspectSmtpMsa`
// (host-allowlist enforcement).

import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, outboundAllowlistFromEnv } from "./allowlist.js";
import { inspectSmtpMsa } from "./smtp-msa.js";

export function inspectSendAsCreate(req: InspectRequest, env?: InspectEnv): InspectResult {
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
  if (!isAllowedRecipient(email, outboundAllowlistFromEnv(env))) {
    return { decision: "deny", category: "capability_escalation", reason: "external-sendas" };
  }
  return { decision: "allow" };
}
