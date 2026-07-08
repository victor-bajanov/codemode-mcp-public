import type { SurfaceReview } from "@local/shared";
import { inspectFilterCreate } from "./inspectors/filters.js";
import { inspectOutboundMessage } from "./inspectors/outbound.js";
import { inspectSendAsCreate } from "./inspectors/sendas.js";

export const surfaceReview: SurfaceReview = {
  // === Tier 1: allow in slice 1 ===
  "gmail.users.getProfile":                { decision: "allow", category: "standard_read" },
  "gmail.users.labels.list":               { decision: "allow", category: "standard_read" },
  "gmail.users.labels.get":                { decision: "allow", category: "standard_read" },
  "gmail.users.labels.create":             { decision: "allow", category: "standard_write" },
  "gmail.users.labels.update":             { decision: "allow", category: "standard_write" },
  "gmail.users.labels.patch":              { decision: "allow", category: "standard_write" },
  "gmail.users.labels.delete":             { decision: "allow", category: "standard_write" },
  "gmail.users.messages.list":             { decision: "allow", category: "standard_read" },
  "gmail.users.messages.get":              { decision: "allow", category: "standard_read" },
  "gmail.users.messages.modify":           { decision: "allow", category: "standard_write",
                                              reasoning: "Body-level inspection considered and rejected — auto-archive via removeLabelIds: [INBOX] is a common legitimate use case; reviewer should not assume the lack of inspector is an oversight." },
  "gmail.users.messages.batchModify":      { decision: "allow", category: "standard_write",
                                              reasoning: "Body-level inspection considered and rejected — auto-archive via removeLabelIds: [INBOX] is a common legitimate use case; reviewer should not assume the lack of inspector is an oversight." },
  "gmail.users.messages.trash":            { decision: "allow", category: "standard_write" },
  "gmail.users.messages.untrash":          { decision: "allow", category: "standard_write" },
  "gmail.users.threads.list":              { decision: "allow", category: "standard_read" },
  "gmail.users.threads.get":               { decision: "allow", category: "standard_read" },
  "gmail.users.threads.modify":            { decision: "allow", category: "standard_write" },
  "gmail.users.threads.trash":             { decision: "allow", category: "standard_write" },
  "gmail.users.threads.untrash":           { decision: "allow", category: "standard_write" },
  "gmail.users.drafts.list":               { decision: "allow", category: "standard_read" },
  "gmail.users.drafts.get":                { decision: "allow", category: "standard_read" },
  "gmail.users.drafts.create":             { decision: "allow", category: "standard_write" },
  "gmail.users.drafts.update":             { decision: "allow", category: "standard_write" },
  "gmail.users.drafts.delete":             { decision: "allow", category: "standard_write" },

  // === Slice-2 closeout additions ===
  "gmail.users.settings.filters.list":     { decision: "allow", category: "standard_read" },
  "gmail.users.settings.filters.get":      { decision: "allow", category: "standard_read" },
  "gmail.users.messages.attachments.get":  { decision: "allow", category: "standard_read" },

  // === Tier 2: outbound + irreversible. Sends are inspected; remaining elicit ops enforce as deny in slice 1. ===
  "gmail.users.messages.send":             { decision: "allow", inspect: inspectOutboundMessage },
  "gmail.users.drafts.send":               { decision: "allow", category: "standard_write",
                                              reasoning: "Outbound content is filtered upstream at drafts.create/drafts.update time, so send-by-id is safe by construction." },
  "gmail.users.messages.import":           { decision: "elicit", category: "external_data_flow" },
  "gmail.users.messages.delete":           { decision: "elicit", category: "irreversible" },
  "gmail.users.messages.batchDelete":      { decision: "elicit", category: "bulk_destructive",
                                              reasoning: "Bulk irreversible delete; needs human confirmation when elicitation lands" },
  "gmail.users.threads.delete":            { decision: "elicit", category: "irreversible" },

  // === Tier 3: always deny ===
  "gmail.users.settings.delegates.list":           { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Enumerates accounts authorised to send/receive as the user; recon for delegation abuse and out of scope for read-mail / send-mail use cases." },
  "gmail.users.settings.delegates.get":            { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Reads a specific delegation. Same recon concern as delegates.list." },
  "gmail.users.settings.delegates.create":         { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Persistent forwarding survives token revocation" },
  "gmail.users.settings.delegates.delete":         { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Removes persistent account-access delegation; symmetric with delegates.create at Tier-3." },
  "gmail.users.settings.forwardingAddresses.create": { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Configures persistent off-account inbound-mail forwarding; survives token revocation, classic exfiltration channel." },
  "gmail.users.settings.forwardingAddresses.delete": { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Removes persistent forwarding configuration; symmetric with .create at Tier-3." },
  "gmail.users.settings.filters.create":           { decision: "allow", inspect: inspectFilterCreate },
  "gmail.users.settings.filters.delete":           { decision: "deny", category: "persistent_state",
                                                      reasoning: "Removes user-defined filter rules; could undo legitimate spam/security filtering set by the user." },
  "gmail.users.settings.sendAs.create":            { decision: "allow", inspect: inspectSendAsCreate,
    reasoning: "Reference implementation. The gmail.settings.sharing scope is intentionally not requested by default; surface entry exists so the inspector pattern is exercised by tests and operators who want the capability can add the scope to gmailProvider.oauth.scopes and re-deploy. Tier 3 already denies sendAs.update/patch/delete. Body-level: `inspectSmtpMsa` rejects any `smtpMsa` sub-object whose host is not on the empty-by-default `SMTP_MSA_HOST_ALLOWLIST` (in `inspectors/smtp-msa-allowlist.ts`)." },
  "gmail.users.settings.sendAs.update":            { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Modifies persistent send-as identity (display name, signature, reply-to). The create-time inspector enforces user-email identity; an update path circumvents that — simpler/safer to deny." },
  "gmail.users.settings.sendAs.patch":             { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Same surface as sendAs.update, partial-update flavour. Same identity-spoofing concern; deny rather than wire a second inspector." },
  "gmail.users.settings.sendAs.delete":            { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Removes a persistent send-as identity; symmetric with sendAs.create at Tier-3." },
  "gmail.users.settings.sendAs.smimeInfo.insert":  { decision: "deny", category: "capability_escalation",
                                                      reasoning: "Installs an S/MIME signing certificate for a send-as identity; lets the agent send cryptographically-signed mail under the user's name." },

  // any operation NOT listed here is implicitly denied
} as const;
