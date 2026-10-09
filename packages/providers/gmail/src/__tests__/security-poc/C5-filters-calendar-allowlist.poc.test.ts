// Security-review POC C5 — Gmail filter inspector, Calendar attendee inspector
// and the shared recipient allowlist matcher.
//
// C5a filters: `inspectFilterCreate` denied `action.delete === true`, but the
//      Gmail FilterAction resource has no `delete` field at all — "Delete it" is
//      expressed as `addLabelIds: ["TRASH"]`, and "Mark as spam" as
//      `addLabelIds: ["SPAM"]`. Both passed the inspector as `allow`, although
//      the entry's stated policy is that silently hiding matching mail
//      (`removeLabelIds: ["INBOX"]`) needs approval.
//      Status: FIXED (F-8) — TRASH/SPAM in `addLabelIds` now elicit
//      (`filter-trash-or-spam`) and the dead `delete` check is gone.
// C5b calendar: `inspectEventAttendees` exempted every `resource: true`
//      attendee. The Calendar API lets a caller set `resource` when an attendee
//      is first added, so any external address could be marked as a
//      "resource" to skip the allowlist.
//      Status: FIXED (F-9) — only `resource: true` attendees at
//      `resource.calendar.google.com` (Workspace rooms/equipment) are exempt.
// C5c allowlist: `isAllowedRecipient` split on the LAST "@" with no address
//      validation, so `outsider@evil.example@allowed.example` was accepted.
//      Status: FIXED (F-18) — addresses must have a plain addr-spec shape
//      (exactly one "@", no quotes, brackets, whitespace, …) before matching.
// The original attack payloads are kept as regression inputs.
import { describe, it, expect } from "vitest";
import { inspectFilterCreate } from "../../inspectors/filters";
import { inspectEventAttendees } from "../../inspectors/calendar-attendees";
import { isAllowedRecipient } from "../../inspectors/allowlist";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example" };

describe("C5a filters.create inspector", () => {
  it("removeLabelIds INBOX (archive) requires approval — the documented control", () => {
    const r = inspectFilterCreate({ body: { criteria: { from: "x" }, action: { removeLabelIds: ["INBOX"] } } });
    expect(r.decision).toBe("elicit");
  });
  it("FIXED (F-8): addLabelIds TRASH (Gmail's 'delete it') now requires approval", () => {
    const r = inspectFilterCreate({ body: { criteria: { from: "security@bank.example" }, action: { addLabelIds: ["TRASH"] } } });
    expect(r.decision).toBe("elicit");
    expect(r.reason).toBe("filter-trash-or-spam");
  });
  it("FIXED (F-8): addLabelIds SPAM now requires approval", () => {
    const r = inspectFilterCreate({ body: { criteria: { from: "x" }, action: { addLabelIds: ["SPAM"] } } });
    expect(r.decision).toBe("elicit");
    expect(r.reason).toBe("filter-trash-or-spam");
  });
  it("FIXED (F-8): the dead `delete: true` check is gone; unknown keys fail closed", () => {
    // `delete` is not a FilterAction field. "Delete it" is covered by the
    // TRASH case; any key outside the known FilterAction set is refused as
    // malformed so an unread spelling cannot carry a label change past it.
    const r = inspectFilterCreate({ body: { action: { delete: true } } });
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("filter-unknown-action-field");
  });
  it("FIXED (F-8): the proto field-name spelling add_label_ids TRASH needs approval", () => {
    const r = inspectFilterCreate({ body: { criteria: { from: "x" }, action: { add_label_ids: ["TRASH"] } } });
    expect(r.decision).toBe("elicit");
    expect(r.reason).toBe("filter-trash-or-spam");
  });
  it("FIXED (F-8): the proto field-name spelling remove_label_ids INBOX needs approval", () => {
    const r = inspectFilterCreate({ body: { criteria: { from: "x" }, action: { remove_label_ids: ["INBOX"] } } });
    expect(r.decision).toBe("elicit");
    expect(r.reason).toBe("filter-skip-inbox");
  });
});

describe("C5b calendar attendee inspector", () => {
  it("an external attendee is denied", () => {
    const r = inspectEventAttendees({ body: { attendees: [{ email: "outsider@evil.example" }] } }, ENV);
    expect(r.decision).toBe("deny");
  });
  it("FIXED (F-9): the same address flagged resource:true is no longer exempt from the allowlist", () => {
    const r = inspectEventAttendees(
      { body: { attendees: [{ email: "outsider@evil.example", resource: true }] } },
      ENV,
    );
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-attendee");
  });
  it("a real Workspace room (resource:true at resource.calendar.google.com) stays exempt (control)", () => {
    const r = inspectEventAttendees(
      { body: { attendees: [{ email: "room-101@resource.calendar.google.com", resource: true }] } },
      ENV,
    );
    expect(r.decision).toBe("allow");
  });
});

describe("C5c recipient allowlist matcher", () => {
  it("FIXED (F-18): refuses an address with two '@' even when the trailing domain is allowed", () => {
    expect(isAllowedRecipient("outsider@evil.example@allowed.example", ["*@allowed.example"])).toBe(false);
  });
  it("does not match subdomains or look-alike domains (control)", () => {
    expect(isAllowedRecipient("a@sub.allowed.example", ["*@allowed.example"])).toBe(false);
    expect(isAllowedRecipient("a@allowed.example.evil", ["*@allowed.example"])).toBe(false);
    expect(isAllowedRecipient("a@аllowed.example", ["*@allowed.example"])).toBe(false); // Cyrillic а
  });
});
