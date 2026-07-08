import type { SurfaceReview } from "@local/shared";
import { inspectFilterCreate } from "./inspectors/filters.js";
import { inspectOutboundMessage, inspectDraftSend } from "./inspectors/outbound.js";
import { inspectSendAsCreate } from "./inspectors/sendas.js";
import { inspectEventAttendees } from "./inspectors/calendar-attendees.js";

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
  "gmail.users.drafts.create":             { decision: "allow", inspect: inspectOutboundMessage },
  "gmail.users.drafts.update":             { decision: "allow", inspect: inspectOutboundMessage },
  "gmail.users.drafts.delete":             { decision: "allow", category: "standard_write" },

  // === Slice-2 closeout additions ===
  "gmail.users.settings.filters.list":     { decision: "allow", category: "standard_read" },
  "gmail.users.settings.filters.get":      { decision: "allow", category: "standard_read" },
  "gmail.users.messages.attachments.get":  { decision: "allow", category: "standard_read" },

  // === Tier 2: outbound + irreversible. Sends are inspected; remaining elicit ops enforce as deny in slice 1. ===
  "gmail.users.messages.send":             { decision: "allow", inspect: inspectOutboundMessage },
  "gmail.users.drafts.send":               { decision: "allow", inspect: inspectDraftSend,
                                              reasoning: "Recipients are inspected at drafts.create/drafts.update time. A bare send-by-id carries no message and is safe by construction (allow); an update-and-send carries a fresh message whose recipients inspectDraftSend re-inspects against the allowlist." },
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

  // ===========================================================================
  // Google Calendar v3 — "read + event management" surface.
  // Reached on the same www.googleapis.com origin as Gmail (apiBaseUrl), under
  // /calendar/v3/. Sharing (acl.*) and calendar lifecycle are denied; event
  // writes that can email invitations are gated by inspectEventAttendees.
  // ===========================================================================

  // --- Reads ---
  "calendar.calendarList.list":            { decision: "allow", category: "standard_read" },
  "calendar.calendarList.get":             { decision: "allow", category: "standard_read" },
  "calendar.calendars.get":                { decision: "allow", category: "standard_read" },
  "calendar.events.list":                  { decision: "allow", category: "standard_read" },
  "calendar.events.get":                   { decision: "allow", category: "standard_read" },
  "calendar.events.instances":             { decision: "allow", category: "standard_read" },
  "calendar.freebusy.query":               { decision: "allow", category: "standard_read",
                                              reasoning: "POST-shaped read: returns busy intervals for the queried calendars; no state change." },
  "calendar.colors.get":                   { decision: "allow", category: "standard_read" },
  "calendar.settings.get":                 { decision: "allow", category: "standard_read" },
  "calendar.settings.list":                { decision: "allow", category: "standard_read" },

  // --- Event writes (attendee allowlist enforced) ---
  "calendar.events.insert":                { decision: "allow", inspect: inspectEventAttendees },
  "calendar.events.update":                { decision: "allow", inspect: inspectEventAttendees },
  "calendar.events.patch":                 { decision: "allow", inspect: inspectEventAttendees },

  // --- Event writes that can't introduce arbitrary attendees ---
  "calendar.events.move":                  { decision: "allow", category: "standard_write",
                                              reasoning: "Moves an event between the user's own calendars (destination query param); no attendee mutation, so no outbound-invite inspector." },
  "calendar.events.quickAdd":              { decision: "allow", category: "standard_write",
                                              reasoning: "Natural-language `text` query param parsed into title/time; cannot set structured attendees, so no outbound-invite inspector." },

  // --- Elicit: external data in / irreversible ---
  "calendar.events.import":                { decision: "elicit", category: "external_data_flow",
                                              inspect: inspectEventAttendees },
  "calendar.events.delete":                { decision: "elicit", category: "irreversible" },

  // --- Tier 3: always deny ---
  "calendar.acl.list":                     { decision: "deny", category: "capability_escalation",
                                              reasoning: "Enumerates who a calendar is shared with; recon for sharing abuse. Same concern as gmail delegates.list." },
  "calendar.acl.get":                      { decision: "deny", category: "capability_escalation",
                                              reasoning: "Reads a specific sharing rule; same recon concern as acl.list." },
  "calendar.acl.insert":                   { decision: "deny", category: "capability_escalation",
                                              reasoning: "Grants another principal access to a calendar; persistent delegation that survives token revocation — the direct analog to gmail delegates/forwarding.create." },
  "calendar.acl.update":                   { decision: "deny", category: "capability_escalation",
                                              reasoning: "Modifies a persistent calendar-sharing grant; same escalation concern as acl.insert." },
  "calendar.acl.patch":                    { decision: "deny", category: "capability_escalation",
                                              reasoning: "Partial-update flavour of acl.update; same persistent-sharing escalation concern." },
  "calendar.acl.delete":                   { decision: "deny", category: "capability_escalation",
                                              reasoning: "Removes a calendar-sharing grant; symmetric with acl.insert at Tier-3." },
  "calendar.acl.watch":                    { decision: "deny", category: "capability_escalation",
                                              reasoning: "Opens a push-notification channel over the sharing-rule collection; out of scope and exposes the sharing graph." },
  "calendar.calendars.delete":             { decision: "deny", category: "irreversible",
                                              reasoning: "Permanently deletes an entire calendar and all its events; destructive and outside the read+event-management surface." },
  "calendar.calendars.clear":              { decision: "deny", category: "bulk_destructive",
                                              reasoning: "Deletes ALL events on the primary calendar in one call; bulk-irreversible and outside the read+event-management surface." },

  // any operation NOT listed here is implicitly denied (incl. calendars
  // insert/update/patch, calendarList insert/delete/update/patch, all *.watch,
  // and channels.stop)
} as const;
