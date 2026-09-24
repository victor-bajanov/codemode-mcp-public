#!/usr/bin/env node
// Vendor optical's openapi.json into src/spec.json, applying the same
// corrections optical's punch-list will eventually apply:
//   - prepend `/v1` to each `paths` key
//   - set `operationId` on each operation (per lookup table below)
// When optical ships its punch-list, these become no-ops. At that point,
// delete this script + the `vendor:spec` package.json entry, and switch to:
//   cp ../optical/schema/openapi.json packages/providers/optical/src/spec.json
//
// Skips webhook/removed endpoints (/plans/{hash}/preview removed in the
// federation rewrite; /webhook/* uses header-token auth, not bearer).
// `/plans/{hash}/accept` IS in the surface — post-federation it accepts an
// optical bearer (as well as the capability-token email link path), and the
// LLM uses it to sign off on /resolve plans.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Defaults to an `optical` checkout alongside this repo. `OPTICAL_SPEC`
// overrides the source so a spec can be vendored from a worktree or feature
// branch checkout, not only from the main checkout.
const SOURCE =
  process.env.OPTICAL_SPEC ??
  resolve(__dirname, "..", "..", "..", "..", "..", "optical", "schema", "openapi.json");
const TARGET = resolve(__dirname, "..", "src", "spec.json");

// path (post-/v1) → method → operationId.
// Keep in sync with surface-review.ts entries and the EXPECTED_OPS test list.
const OPERATION_IDS = {
  "/v1/tasks":              { get: "listTasks", post: "createTask" },
  "/v1/tasks/{id}":         { get: "getTask", patch: "updateTask", delete: "deleteTask" },
  "/v1/templates":          { get: "listTemplates", post: "createTemplate" },
  "/v1/templates/{id}":     { delete: "deleteTemplate" },
  "/v1/projects":           { get: "listProjects", post: "createProject" },
  "/v1/projects/{id}":      { patch: "updateProject" },
  "/v1/plans":              { get: "listPendingPlans" },
  "/v1/resolve":            { post: "resolve" },
  "/v1/commit":             { post: "commit" },
  "/v1/schedule":           { get: "getSchedule" },
  "/v1/business-hours":     { get: "getBusinessHours" },
  "/v1/meeting-policy":     { get: "getMeetingPolicy" },
  "/v1/plans/{plan_hash}":         { get: "getPlan", delete: "deletePlan" },
  "/v1/plans/{plan_hash}/accept":  { post: "acceptPlan" },
  "/v1/calendar-feeds":                  { get: "listCalendarFeeds", post: "createCalendarFeed" },
  "/v1/calendar-feeds/{id}":             { patch: "updateCalendarFeed", delete: "deleteCalendarFeed" },
  "/v1/calendar-feeds/{id}/regenerate":  { post: "regenerateCalendarFeedSecret" },
  "/v1/booking-page":              { get: "getBookingPage", put: "updateBookingPage" },
  "/v1/bookings":                  { get: "listBookings" },
  "/v1/whoami":                    { get: "whoami" },
  "/v1/contexts":                  { get: "getContexts" },
  "/v1/plans/latest":              { get: "getLatestProposedPlan" },
  "/v1/replan-now":                { post: "replanNow" },
  "/v1/calendar-access-token":     { get: "getCalendarAccessToken" },
  // Meeting polls. Optical publishes these operationIds itself, so these
  // entries are documentation only — the fill-in below is already a no-op for
  // them. Listed to keep this table a complete picture of the vendored surface.
  "/v1/polls":                     { post: "createMeetingPoll" },
  "/v1/polls/{id}":                { get: "getMeetingPoll", patch: "updateMeetingPoll" },
  "/v1/polls/{id}/nudge":          { post: "nudgeMeetingPoll" },
  "/v1/polls/{id}/cancel":         { post: "cancelMeetingPoll" },
  "/v1/polls/{id}/resolve":        { post: "resolveMeetingPoll" },
};

// The webhook ops are vendored since e8d81ba (2026-08-19): subscribeWebhook is
// an agent-surface write and googleCalendarWebhook is classified `deny` in
// surface-review.ts — the review is where they are gated, not this list.
const EXCLUDE_PATH_SUFFIXES = ["/preview"];
const EXCLUDE_PATH_PREFIXES = ["/v1/plans/{plan_hash}/preview"];

function isExcluded(path) {
  return EXCLUDE_PATH_SUFFIXES.some((s) => path.endsWith(s))
    || EXCLUDE_PATH_PREFIXES.some((p) => path.startsWith(p));
}

const spec = JSON.parse(readFileSync(SOURCE, "utf8"));
if (typeof spec.paths !== "object" || spec.paths === null) {
  console.error("Source spec has no .paths object — aborting.");
  process.exit(1);
}

const newPaths = {};
for (const [path, methods] of Object.entries(spec.paths)) {
  const correctedPath = path.startsWith("/v1") ? path : "/v1" + path;
  if (isExcluded(correctedPath)) continue;
  const correctedMethods = {};
  for (const [m, op] of Object.entries(methods)) {
    if (typeof op !== "object" || op === null) {
      correctedMethods[m] = op;
      continue;
    }
    const expectedOpId = OPERATION_IDS[correctedPath]?.[m];
    if (op.operationId === undefined && expectedOpId !== undefined) {
      correctedMethods[m] = { operationId: expectedOpId, ...op };
    } else {
      correctedMethods[m] = op;
    }
  }
  newPaths[correctedPath] = correctedMethods;
}

const out = { ...spec, paths: newPaths };
writeFileSync(TARGET, JSON.stringify(out, null, 2) + "\n");

const ids = new Set();
for (const ms of Object.values(newPaths)) {
  for (const op of Object.values(ms)) {
    if (op && typeof op === "object" && op.operationId) ids.add(op.operationId);
  }
}
console.log(`vendored optical spec → ${TARGET}`);
console.log(`  paths: ${Object.keys(newPaths).length}`);
console.log(`  operationIds: ${ids.size}`);
// 46 = every operationId optical publishes (webhook ops included — see the
// exclusion note above). Bump deliberately when optical's surface grows, in
// the same commit that adds the new ops to surface-review.ts and its test.
if (ids.size !== 46) {
  console.error(`expected 46 operationIds, got ${ids.size}; check OPERATION_IDS table and the source spec.`);
  process.exit(1);
}
