import { describe, it, expect } from "vitest";
import { providerSurfaceReviewTests } from "@local/scaffold/testing";
import { hintFromSpecInfo } from "@local/scaffold";
import { opticalProvider, spec } from "../index";
import { surfaceReview } from "../surface-review";

providerSurfaceReviewTests(opticalProvider);

describe("optical surface-review entries", () => {
  const EXPECTED_ALLOW_OPS = [
    "listTasks", "createTask", "getTask", "updateTask", "deleteTask",
    "listTemplates", "createTemplate", "deleteTemplate",
    "listProjects", "createProject", "updateProject",
    "resolve", "commit", "acceptPlan",
    "getPlan", "deletePlan", "getSchedule",
    "getBusinessHours", "getMeetingPolicy",
    "listCalendarFeeds", "createCalendarFeed", "updateCalendarFeed", "deleteCalendarFeed",
    "regenerateCalendarFeedSecret",
    "whoami", "getContexts", "getLatestProposedPlan", "replanNow",
    "listPendingPlans",
    "getBookingPage", "updateBookingPage", "listBookings",
    "createMeetingPoll", "getMeetingPoll", "nudgeMeetingPoll",
    "cancelMeetingPoll", "resolveMeetingPoll", "updateMeetingPoll",
    "getWeights", "updateWeights", "resetWeights",
    "updateContext", "resetContext",
    "subscribeWebhook",
    "getTimezone", "setTimezone", "resetTimezone",
  ];

  // getCalendarAccessToken mints the caller's raw Google credential and needs a
  // privileged scope this provider never requests — denied, not exposed.
  // googleCalendarWebhook is Google's machine-to-machine push receiver
  // (X-Goog-Channel-Token auth, "Not for end-user clients") — denied.
  const EXPECTED_DENY_OPS = ["getCalendarAccessToken", "googleCalendarWebhook"];

  it("all 47 expected allow operationIds are present in the surface review", () => {
    const missing = EXPECTED_ALLOW_OPS.filter((id) => surfaceReview[id] === undefined);
    expect(missing).toEqual([]);
  });

  it("all 47 expected allow operationIds are categorised `allow`", () => {
    const notAllow = EXPECTED_ALLOW_OPS
      .filter((id) => surfaceReview[id])
      .filter((id) => surfaceReview[id]!.decision !== "allow")
      .map((id) => `${id} (decision=${surfaceReview[id]!.decision})`);
    expect(notAllow).toEqual([]);
  });

  it("all expected deny operationIds are categorised `deny` with reasoning", () => {
    const bad = EXPECTED_DENY_OPS
      .map((id) => ({ id, e: surfaceReview[id] }))
      .filter(({ e }) => !e || e.decision !== "deny" || !e.reasoning)
      .map(({ id, e }) => `${id} (decision=${e?.decision}, reasoning=${e?.reasoning ? "yes" : "no"})`);
    expect(bad).toEqual([]);
  });

  it("no surface-review key is outside the expected allow/deny sets", () => {
    const expected = new Set([...EXPECTED_ALLOW_OPS, ...EXPECTED_DENY_OPS]);
    const unexpected = Object.keys(surfaceReview).filter((k) => !expected.has(k));
    expect(unexpected).toEqual([]);
  });
});

describe("optical executeHint wiring", () => {
  it("opticalProvider.executeHint mirrors hintFromSpecInfo(spec)", () => {
    expect(opticalProvider.executeHint).toBe(hintFromSpecInfo(spec));
    // Defensive: prevent silent drift if hintFromSpecInfo is moved or the
    // wiring is deleted. `executeHint` must be a declared property on the
    // provider literal (value may be undefined when spec.info.description is).
    expect("executeHint" in opticalProvider).toBe(true);
  });
});

describe("optical oauth scopes", () => {
  it("requests the optical worker's canonical scheduler:* scopes", () => {
    // The optical worker's /oauth/authorize enforces a per-client allow-list of
    // scheduler:read / scheduler:write (bearer-admin-consolidation). Requesting
    // the bare legacy `read`/`write` names fails that exact-match gate with
    // error=invalid_scope. Keep these aligned with the client's allowed_scopes.
    expect(opticalProvider.oauth.scopes).toEqual(["scheduler:read", "scheduler:write"]);
  });
});
