import type { SurfaceReview } from "@local/shared";

// All operations classified `allow`. Claude.ai (the primary client) does not
// currently render MCP elicitation prompts, so `elicit` entries silently
// become soft-deny from the operator's perspective. Re-categorize destructive
// ops (deleteTask, deleteTemplate, deletePlan) and externally-visible writes
// (commit, which pushes to Google Calendar) as `elicit` once client support
// lands.

export const surfaceReview: SurfaceReview = Object.freeze({
  // Reads
  listTasks:        { decision: "allow", category: "standard_read" },
  getTask:          { decision: "allow", category: "standard_read" },
  listTemplates:    { decision: "allow", category: "standard_read" },
  listProjects:     { decision: "allow", category: "standard_read" },
  getPlan:          { decision: "allow", category: "standard_read" },
  getSchedule:      { decision: "allow", category: "standard_read" },
  // getBusinessHours returns the caller's effective business-hours placement
  // floor (owner-scoped read, BearerAuth). Same class as getSchedule.
  getBusinessHours: { decision: "allow", category: "standard_read" },
  // getMeetingPolicy returns the caller's effective owned-meeting
  // attendee-enforcement default. Same class as getBusinessHours.
  getMeetingPolicy: { decision: "allow", category: "standard_read" },

  // Writes — optical's own D1 only
  createTask:       { decision: "allow", category: "standard_write" },
  updateTask:       { decision: "allow", category: "standard_write" },
  deleteTask:       { decision: "allow", category: "standard_write" },
  createTemplate:   { decision: "allow", category: "standard_write" },
  deleteTemplate:   { decision: "allow", category: "standard_write" },
  createProject:    { decision: "allow", category: "standard_write" },
  updateProject:    { decision: "allow", category: "standard_write" },

  // Planner ops
  resolve:          { decision: "allow", category: "standard_write" },
  // commit writes to the operator's own Google Calendar. Optical's `meeting`
  // context is a label on a task, not a Google Meet invite — there is no fan-out
  // to other humans. Safe enough for `allow`.
  commit:           { decision: "allow", category: "standard_write" },
  // acceptPlan signs off on a proposed plan from /resolve. Same external-side-
  // effect class as commit (calendar write on the operator's own account). The
  // LLM uses judgement to accept, replan, or surface to the user.
  acceptPlan:       { decision: "allow", category: "standard_write" },
  // deletePlan is destructive but recoverable: re-run /resolve.
  deletePlan:       { decision: "allow", category: "standard_write" },

  // Calendar busy-feed endpoint ops (multi-endpoint calendar feeds) —
  // caller-scoped, optical's own D1. None of these return a feed secret or
  // URL directly: create/regenerate hand back a single-use reveal_url the
  // user opens in a browser, so the feed URL itself never crosses the MCP
  // tool-call boundary.
  // listCalendarFeeds never returns secrets or feed URLs (read).
  listCalendarFeeds:  { decision: "allow", category: "standard_read" },
  // createCalendarFeed provisions a new endpoint with its own secret; the
  // response is a reveal_url, not the secret. Caller-scoped, no fan-out.
  createCalendarFeed: { decision: "allow", category: "standard_write" },
  // updateCalendarFeed edits label/reveal-regex config only; the secret and
  // subscription URL are untouched.
  updateCalendarFeed: { decision: "allow", category: "standard_write" },
  // deleteCalendarFeed is destructive but recoverable: create a new endpoint.
  deleteCalendarFeed: { decision: "allow", category: "standard_write" },
  // regenerateCalendarFeedSecret breaks the OLD feed URL immediately and
  // returns a fresh single-use reveal_url. Re-categorize as `elicit` (breaks
  // any existing subscription) once Claude.ai renders elicitation prompts.
  regenerateCalendarFeedSecret: { decision: "allow", category: "standard_write" },

  // Caller-scoped reads added in the attendee-enforcement / federation work.
  // whoami returns the caller's identity + effective timezone; getContexts the
  // caller's effective context config; getLatestProposedPlan the caller's
  // latest uncommitted /resolve plan. All owner-scoped reads, optical's own D1.
  whoami:               { decision: "allow", category: "standard_read" },
  getContexts:          { decision: "allow", category: "standard_read" },
  getLatestProposedPlan: { decision: "allow", category: "standard_read" },
  // listPendingPlans lists every pending (uncommitted, unexpired) proposed plan
  // for the caller — the plural sibling of getLatestProposedPlan, same owner-
  // scoped read over optical's own D1.
  listPendingPlans:     { decision: "allow", category: "standard_read" },
  // replanNow manually triggers the caller's webhook-style re-resolve. Same
  // class as resolve: recomputes a proposed plan in optical's D1, no direct
  // fan-out to other humans.
  replanNow:            { decision: "allow", category: "standard_write" },

  // Public booking page ops. getBookingPage and listBookings are owner-scoped
  // reads over optical's own D1 — the config the caller already owns, and the
  // bookings already taken against it. listBookings carries booker-supplied
  // names/emails, but those are the caller's own meeting attendees: the same
  // PII class as getSchedule.
  getBookingPage:    { decision: "allow", category: "standard_read" },
  listBookings:      { decision: "allow", category: "standard_read" },
  // updateBookingPage PUBLISHES. With `enabled: true` and a slug set, the page
  // at /book/<slug> becomes reachable by anyone on the internet, who can then
  // take slots on the caller's calendar. That is wider reach than anything else
  // in this file — every other write touches the caller's own data or fans out
  // only to attendees they had already invited. Kept `allow` for consistency
  // with commit / acceptPlan / regenerateCalendarFeedSecret, and because
  // `elicit` is a silent soft-deny on Claude.ai today (see the header note).
  // This is the FIRST entry to re-categorize as `elicit` once that lands.
  updateBookingPage: { decision: "allow", category: "standard_write" },

  // Meeting-poll ops. These are the only entries in this file whose writes send
  // EMAIL to third parties — every other write either stays in optical's D1 or
  // fans out to attendees already on an event the caller owns. The invitee list
  // is supplied by the caller in the same call, so the LLM is not widening reach
  // on its own; that is what keeps them `allow` rather than `deny`.
  //
  // getMeetingPoll carries invitee names, emails, and their painted
  // availability — same PII class as listBookings.
  getMeetingPoll:     { decision: "allow", category: "standard_read" },
  // createMeetingPoll emails every invitee on the list it is given.
  createMeetingPoll:  { decision: "allow", category: "standard_write" },
  // cancelMeetingPoll closes the poll; recoverable only by creating a new one
  // (which re-emails everyone).
  cancelMeetingPoll:  { decision: "allow", category: "standard_write" },
  // nudgeMeetingPoll re-emails non-responders AND rotates each invitee's link,
  // so every link in an older email goes dead. Repeated calls are indistinguish-
  // able from spam to the invitee. Re-categorize as `elicit` immediately after
  // updateBookingPage once Claude.ai renders elicitation prompts.
  nudgeMeetingPoll:   { decision: "allow", category: "standard_write" },
  // updateMeetingPoll edits an open poll (title, location, invitees, deadline,
  // guest link). Least-email by design: only invitees materially affected by a
  // given field are notified, and a deadline change emails every non-dropped
  // invitee — same reach as nudgeMeetingPoll but tied to a concrete edit.
  updateMeetingPoll:  { decision: "allow", category: "standard_write" },
  // resolveMeetingPoll forces the booking now: it creates a real calendar event
  // and sends invites, including to invitees who never responded. Largest
  // fan-out of the five — second in the `elicit` queue behind nudgeMeetingPoll.
  resolveMeetingPoll: { decision: "allow", category: "standard_write" },

  // Solver-weights ops (2026-08 re-vendor). All caller-scoped rows in
  // optical's own D1: getWeights reads the effective six-field snapshot,
  // updateWeights merges a partial over it, resetWeights deletes the custom
  // row so the caller tracks the instance default again. update/reset are
  // recoverable via each other — same class as updateContext/resetContext.
  getWeights:    { decision: "allow", category: "standard_read" },
  updateWeights: { decision: "allow", category: "standard_write" },
  resetWeights:  { decision: "allow", category: "standard_write" },

  // Per-context config ops (2026-08 re-vendor). Same merge-over-effective /
  // reset-to-default pair as the weights ops, scoped to one context. The
  // read side is the pre-existing getContexts.
  updateContext: { decision: "allow", category: "standard_write" },
  resetContext:  { decision: "allow", category: "standard_write" },

  // subscribeWebhook ensures a Google Calendar watch channel exists for the
  // caller's own primary calendar so external edits trigger replans.
  // Idempotent, BearerAuth, no fan-out to other humans — same reach class as
  // replanNow.
  subscribeWebhook: { decision: "allow", category: "standard_write" },

  // Timezone ops (2026-09 re-vendor). Caller-scoped `users.home_tz` in
  // optical's own D1. setTimezone discards the caller's own pending plans and
  // stamps the old zone onto their untimezoned task windows; resetTimezone
  // falls back to the instance default. Each is recoverable via the other and
  // nothing fans out to other humans — same class as updateWeights/resetWeights.
  getTimezone:   { decision: "allow", category: "standard_read" },
  setTimezone:   { decision: "allow", category: "standard_write" },
  resetTimezone: { decision: "allow", category: "standard_write" },

  // googleCalendarWebhook is the machine-to-machine receiver Google's push
  // notifications POST to. It authenticates via X-Goog-Channel-Token, not
  // Bearer, and the spec marks it "Not for end-user clients". The agent
  // calling it would at best no-op and at worst spoof a calendar-change
  // notification to force replans. Not an agent-surface operation. Deny.
  googleCalendarWebhook: {
    decision: "deny",
    category: "external_data_flow",
    reasoning:
      "Machine-to-machine Google Calendar push-notification receiver, authenticated by " +
      "X-Goog-Channel-Token rather than the caller's Bearer token. Not an end-user " +
      "operation; exposing it would let the agent spoof calendar-change notifications.",
  },

  // getCalendarAccessToken mints a *raw* Google OAuth access token — the user's
  // actual Google credential — and requires the privileged `calendar:raw-token`
  // scope, which the optical worker withholds from non-operator clients. This
  // MCP provider only requests scheduler:read/scheduler:write, so the call would
  // 403 (insufficient_scope) regardless; surfacing it would hand the LLM a
  // credential-minting tool it must never have. Deny.
  getCalendarAccessToken: {
    decision: "deny",
    category: "capability_escalation",
    reasoning:
      "Mints the caller's raw Google OAuth access token; requires the privileged " +
      "calendar:raw-token scope this provider never requests. A raw credential must " +
      "not be exposed to the agent surface.",
  },
});
