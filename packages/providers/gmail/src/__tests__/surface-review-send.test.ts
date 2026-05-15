// Tests for the outbound-recipient inspector (Task 8 — failing red state).
//
// These tests target two not-yet-existing modules implemented in Task 9:
//   - ../inspectors/allowlist  → OUTBOUND_RECIPIENT_ALLOWLIST, isAllowedRecipient,
//                                assertAllowlistEntry
//   - ../inspectors/outbound   → MASS_SEND_THRESHOLD, inspectOutboundMessage
//
// Notes for Task 9 implementer (decisions baked into these tests):
//
//  * `assertAllowlistEntry(entry: string): void` is the named export the
//    malformed-allowlist test calls directly. The module-load validator should
//    iterate OUTBOUND_RECIPIENT_ALLOWLIST and call assertAllowlistEntry on each.
//
//  * Mass-send semantics: > MASS_SEND_THRESHOLD (i.e. 26+) triggers `elicit`.
//    25 exactly does NOT trigger.
//
//  * Mass-send tests below use ALLOWLISTED recipients to sidestep ordering
//    ambiguity between the off-allowlist (deny) and mass-send (elicit) checks.
//    Recommended order: off-allowlist check first (deny wins), mass-send second.
//
//  * Drafts.update vs drafts.create: the inspector cannot tell them apart from
//    body shape alone. When `body.message` is missing, return
//    `draft-update-no-message`. The plan only pins this for drafts.update.

import { describe, it, expect } from "vitest";
import {
  isAllowedRecipient,
  assertAllowlistEntry,
  OUTBOUND_RECIPIENT_ALLOWLIST,
} from "../inspectors/allowlist";
import {
  inspectOutboundMessage,
  MASS_SEND_THRESHOLD,
} from "../inspectors/outbound";

function rfc822(headers: Record<string, string>, body = ""): string {
  const headerLines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\r\n");
  return `${headerLines}\r\n\r\n${body}`;
}

function toBase64Url(s: string): string {
  return Buffer.from(s, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

describe("A) isAllowedRecipient", () => {
  it("matches the exact-address allowlist entry", () => {
    expect(isAllowedRecipient("someone@gmail.com")).toBe(true);
  });

  it("matches the wildcard-domain allowlist entry", () => {
    expect(isAllowedRecipient("someone@example.com")).toBe(true);
  });

  it("rejects an unrelated address on a non-allowlisted domain", () => {
    // gmail.com itself is NOT allowlisted; only the specific burner address is.
    expect(isAllowedRecipient("someone@gmail.com")).toBe(false);
  });

  it("normalizes case before comparing", () => {
    expect(isAllowedRecipient("you@example.com")).toBe(true);
  });

  it("treats plus-addressing as strict (a+tag@x ≠ a@x)", () => {
    // Known behavior, not a bug — see plan.
    expect(isAllowedRecipient("someone+tag@gmail.com")).toBe(false);
  });

  it("does not match subdomains of an allowlisted domain", () => {
    expect(isAllowedRecipient("someone@sub.example.com")).toBe(false);
  });

  it("OUTBOUND_RECIPIENT_ALLOWLIST contains the expected entries", () => {
    // Sanity check that the constant is exported and contains the documented
    // entries. This protects against accidental edits to the allowlist.
    expect(OUTBOUND_RECIPIENT_ALLOWLIST).toEqual([
      "*@example.com",
      "someone@gmail.com",
    ]);
  });
});

describe("B) assertAllowlistEntry", () => {
  it("throws on an entry with no @ sign", () => {
    expect(() => assertAllowlistEntry("no-at-sign")).toThrow();
  });

  it("throws on an entry with empty domain after wildcard", () => {
    expect(() => assertAllowlistEntry("*@")).toThrow();
  });

  it("does not throw on a valid exact-address entry", () => {
    expect(() => assertAllowlistEntry("someone@gmail.com")).not.toThrow();
  });

  it("does not throw on a valid wildcard-domain entry", () => {
    expect(() => assertAllowlistEntry("*@example.com")).not.toThrow();
  });
});

describe("C) inspectOutboundMessage — messages.send body shape (top-level Message)", () => {
  it("allows when all recipients are allowlisted (payload.headers)", () => {
    const result = inspectOutboundMessage({
      body: {
        payload: {
          headers: [
            { name: "To", value: "alice@example.com" },
            { name: "Cc", value: "bob@example.com" },
          ],
        },
      },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies as external-send when any recipient is off the allowlist", () => {
    const result = inspectOutboundMessage({
      body: {
        payload: {
          headers: [
            { name: "To", value: "alice@example.com" },
            { name: "Cc", value: "attacker@example.com" },
          ],
        },
      },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });

  it("elicits as mass-send when deduplicated recipient count exceeds the threshold", () => {
    // Use 30 unique allowlisted recipients to sidestep the off-allowlist vs
    // mass-send ordering question — see the comment at the top of this file.
    const recipients = Array.from(
      { length: 30 },
      (_, i) => `user${i}@example.com`,
    );
    const result = inspectOutboundMessage({
      body: {
        payload: {
          headers: [{ name: "To", value: recipients.join(", ") }],
        },
      },
    });
    expect(result).toMatchObject({
      decision: "elicit",
      category: "external_data_flow",
      reason: "mass-send",
    });
    expect(result.summary).toMatchObject({ count: expect.any(Number) });
    // Boundary sanity: 30 > 25 = MASS_SEND_THRESHOLD.
    expect(MASS_SEND_THRESHOLD).toBe(25);
  });

  it("deduplicates recipients across To/Cc/Bcc before counting", () => {
    // Same address appears in both To and Cc — should count once.
    // With one (allowlisted) recipient, expect allow (NOT mass-send, NOT external).
    const result = inspectOutboundMessage({
      body: {
        payload: {
          headers: [
            { name: "To", value: "alice@example.com" },
            { name: "Cc", value: "alice@example.com" },
          ],
        },
      },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("extracts recipients from a base64url-encoded RFC 822 raw body", () => {
    const raw = toBase64Url(
      rfc822({
        To: "alice@example.com",
        Cc: "bob@example.com, charlie@example.com",
        Bcc: "dave@example.com",
        Subject: "Hello",
      }),
    );
    const result = inspectOutboundMessage({ body: { raw } });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies as malformed when no recipients can be extracted", () => {
    const result = inspectOutboundMessage({ body: {} });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "send-no-recipients",
    });
  });
});

describe("D) inspectOutboundMessage — drafts.create body shape ({message: ...})", () => {
  it("allows when message.raw recipients are allowlisted", () => {
    const raw = toBase64Url(
      rfc822({
        To: "alice@example.com",
        Subject: "Draft hello",
      }),
    );
    const result = inspectOutboundMessage({
      body: { message: { raw } },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies when message.payload.headers contains an off-allowlist recipient", () => {
    const result = inspectOutboundMessage({
      body: {
        message: {
          payload: {
            headers: [{ name: "To", value: "attacker@example.com" }],
          },
        },
      },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });
});

describe("E) inspectOutboundMessage — drafts.update body shape ({id, message: ...})", () => {
  it("allows when message recipients are allowlisted", () => {
    const result = inspectOutboundMessage({
      body: {
        id: "d1",
        message: {
          payload: {
            headers: [
              { name: "To", value: "alice@example.com" },
            ],
          },
        },
      },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies as malformed when the body has only {id} and no message", () => {
    const result = inspectOutboundMessage({ body: { id: "d1" } });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "draft-update-no-message",
    });
  });
});
