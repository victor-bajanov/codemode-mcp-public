// The `execute` tool description is the ONLY client-visible place that can say
// this server also speaks Google Calendar — the search/execute boilerplate comes
// from codemode's openApiMcpServer and is API-agnostic. That is now ALL the hint
// does: it names the two APIs, their path prefixes and operationId prefixes, and
// points at the per-operation descriptions for availability.
//
// The per-operation gating detail this file used to pin (tier lists, elicit
// wording, the attendee ceiling) moved onto the operations themselves, where
// `search` surfaces it only when relevant instead of the hint paying for it in
// every context window. Those contracts are now asserted in
// __tests__/annotated-spec.test.ts and __tests__/client-notes.test.ts.

import { describe, it, expect } from "vitest";
import { buildExecuteAddendum, SURFACE_REVIEW_MARKER } from "@local/scaffold";
import { gmailProvider } from "../index";

const hint = gmailProvider.executeHint ?? "";

// Phrases that promise the user a dialog. Elicitation only renders on clients
// that advertise the capability; on everything else (Claude.ai included)
// elicit.ts throws ToolError("...requires user approval; outcome: unsupported")
// without showing anything, so a hint that promises a prompt is a lie on the
// primary client.
const PROMPT_PROMISES =
  /(the user is asked|asks the user|prompts? the user|you will be prompted|user is prompted|confirmation dialog)/i;

describe("gmailProvider.executeHint — Calendar discoverability", () => {
  it("is set at all (the only client-visible place Calendar can be announced)", () => {
    expect("executeHint" in gmailProvider).toBe(true);
    expect(hint.length).toBeGreaterThan(0);
  });

  it("names both APIs and both path prefixes", () => {
    expect(hint).toContain("Gmail");
    expect(hint).toContain("Google Calendar");
    expect(hint).toContain("/gmail/v1/users/me/");
    expect(hint).toContain("/calendar/v3/");
  });

  it("says `search` covers both specs, and names the two operationId prefixes", () => {
    expect(hint).toContain("search");
    expect(hint).toContain("gmail.");
    expect(hint).toContain("calendar.");
  });

  it("defers the ACCESS convention to the scaffold rather than restating it", () => {
    // The convention is explained once by buildExecuteAddendum for EVERY
    // provider; repeating it here would cost every context window twice and
    // could drift. The hint only needs to say availability varies.
    expect(hint).toMatch(/availability varies/i);
    for (const stagingEnabled of [true, false]) {
      const addendum = buildExecuteAddendum(gmailProvider, stagingEnabled);
      expect(addendum).toContain(SURFACE_REVIEW_MARKER);
      expect(addendum).toMatch(/with NO\s+`?ACCESS:\s*`?\s+line is plainly available/i);
      // Explained before the Gmail-specific hint that refers back to it.
      expect(addendum.indexOf("Operation availability")).toBeLessThan(addendum.indexOf(hint));
    }
  });

  it("carries NO per-operation tier list — that detail lives on the operations", () => {
    // A full operationId in the hint means the tier lists came back; the prefix
    // mentions above ("gmail." / "calendar.") are not full ids.
    const operationIds = hint.match(/\b(?:gmail|calendar)\.[A-Za-z]+\.[A-Za-z]+/g) ?? [];
    expect(operationIds).toEqual([]);
  });

  it("never promises a prompt for approval-gated operations", () => {
    // Elicitation is unavailable on the primary client, so the promise would be
    // false wherever it appeared.
    expect(hint).not.toMatch(PROMPT_PROMISES);
  });

  it("states capabilities without directing what the assistant may say", () => {
    // Granular Google consent lets a user grant Gmail and decline Calendar, so
    // "this server is not mail-only" is not always true — and telling the model
    // what it may not say is not this hint's job either way.
    expect(hint).not.toMatch(/do(?: not|n't)\s+(?:tell|say|claim)/i);
    expect(hint).not.toMatch(/mail-only/i);
  });

  it("stays small — it is paid for in every context window", () => {
    // 2,125 chars before the per-operation move; the ACCESS convention then
    // moved out to the scaffold, leaving only the two-API fact.
    expect(hint.length).toBeLessThan(600);
  });

  it("reaches the composed execute tool description", () => {
    for (const stagingEnabled of [true, false]) {
      const addendum = buildExecuteAddendum(gmailProvider, stagingEnabled);
      expect(addendum).toContain(hint);
      // Ahead of the harness blocks, per buildExecuteAddendum's assembly order.
      expect(addendum.indexOf(hint)).toBeLessThan(
        addendum.indexOf("## codemode.request body modes"),
      );
    }
  });
});
