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
  inspectDraftSend,
  MASS_SEND_THRESHOLD,
} from "../inspectors/outbound";
import { surfaceReview } from "../surface-review";

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
    expect(isAllowedRecipient("adam@gmail.com")).toBe(true);
  });

  it("matches the wildcard-domain allowlist entry", () => {
    expect(isAllowedRecipient("bob@example.com")).toBe(true);
  });

  it("rejects an unrelated address on a non-allowlisted domain", () => {
    // gmail.com itself is NOT allowlisted; only the specific burner address is.
    expect(isAllowedRecipient("eve@gmail.com")).toBe(false);
  });

  it("normalizes case before comparing", () => {
    expect(isAllowedRecipient("you@example.com")).toBe(true);
  });

  it("treats plus-addressing as strict (a+tag@x ≠ a@x)", () => {
    // Known behavior, not a bug — see plan.
    expect(isAllowedRecipient("adam+tag@gmail.com")).toBe(false);
  });

  it("does not match subdomains of an allowlisted domain", () => {
    expect(isAllowedRecipient("eve@sub.example.com")).toBe(false);
  });

  it("OUTBOUND_RECIPIENT_ALLOWLIST contains the expected entries", () => {
    // Sanity check that the constant is exported and contains the documented
    // entries. This protects against accidental edits to the allowlist.
    expect(OUTBOUND_RECIPIENT_ALLOWLIST).toEqual([
      "*@example.com",
      "adam@gmail.com",
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
    expect(() => assertAllowlistEntry("adam@gmail.com")).not.toThrow();
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
            { name: "Cc", value: "eve@evil.com" },
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
            headers: [{ name: "To", value: "eve@evil.com" }],
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

describe("F) drafts surface wiring (AUTHZ-VULN-04) — allowlist bites on create/update/send", () => {
  it("wires inspectOutboundMessage onto drafts.create and drafts.update", () => {
    for (const id of ["gmail.users.drafts.create", "gmail.users.drafts.update"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, id).toBe(inspectOutboundMessage);
    }
  });

  it("wires inspectDraftSend onto drafts.send", () => {
    const entry = surfaceReview["gmail.users.drafts.send"];
    expect(entry?.decision).toBe("allow");
    expect(entry?.inspect).toBe(inspectDraftSend);
  });

  it("drafts.create denies an off-allowlist recipient (allowlist now bites)", () => {
    const raw = toBase64Url(
      rfc822({ To: "eve@evil.com", Subject: "Draft hello" }),
    );
    const inspect = surfaceReview["gmail.users.drafts.create"]!.inspect!;
    expect(inspect({ body: { message: { raw } } })).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });

  it("drafts.update denies an off-allowlist recipient (allowlist now bites)", () => {
    const inspect = surfaceReview["gmail.users.drafts.update"]!.inspect!;
    expect(
      inspect({
        body: {
          id: "d1",
          message: {
            payload: { headers: [{ name: "To", value: "eve@evil.com" }] },
          },
        },
      }),
    ).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });
});

describe("G) inspectDraftSend — bare-id send is safe by construction; update-and-send is re-inspected", () => {
  it("allows a bare {id} send (already-vetted draft)", () => {
    expect(inspectDraftSend({ body: { id: "d1" } })).toMatchObject({
      decision: "allow",
    });
  });

  it("allows an empty body {} (no message carried)", () => {
    expect(inspectDraftSend({ body: {} })).toMatchObject({ decision: "allow" });
  });

  it("denies an update-and-send carrying an off-allowlist message.raw", () => {
    const raw = toBase64Url(
      rfc822({ To: "eve@evil.com", Subject: "sneaky" }),
    );
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } })).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });

  it("allows an update-and-send carrying an allowlisted message.raw", () => {
    const raw = toBase64Url(
      rfc822({ To: "alice@example.com", Subject: "ok" }),
    );
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } })).toMatchObject({
      decision: "allow",
    });
  });

  it("delegates a non-JSON media channel to inspectOutboundMessage (off-allowlist denied)", () => {
    const req = {
      rawBody: new TextEncoder().encode(
        "To: eve@evil.com\r\nSubject: hi\r\n\r\nbody",
      ),
      contentType: "message/rfc822",
    };
    expect(inspectDraftSend(req)).toMatchObject({
      decision: "deny",
      reason: "external-send",
    });
  });
});
