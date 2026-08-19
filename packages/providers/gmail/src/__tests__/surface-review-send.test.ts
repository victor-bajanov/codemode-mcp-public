// Tests for the outbound-recipient inspector.
//
// Modules under test:
//   - ../inspectors/allowlist  → outboundAllowlistFromEnv, isAllowedRecipient,
//                                assertAllowlistEntry
//   - ../inspectors/outbound   → MASS_SEND_THRESHOLD, inspectOutboundMessage
//
// The allowlist is per-deployment: inspectors resolve it from the
// OUTBOUND_RECIPIENT_ALLOWLIST wrangler var on the env threaded through by the
// request handler. Tests pass an env fixture mirroring the prod deployment's
// var; the per-deployment describe block at the bottom pins the divergence and
// fail-closed semantics.
//
// Decisions baked into these tests:
//
//  * Mass-send semantics: > MASS_SEND_THRESHOLD (i.e. 26+) triggers `elicit`.
//    25 exactly does NOT trigger.
//
//  * Mass-send tests below use ALLOWLISTED recipients to sidestep ordering
//    ambiguity between the off-allowlist (deny) and mass-send (elicit) checks.
//    Order: off-allowlist check first (deny wins), mass-send second.
//
//  * Drafts.update vs drafts.create: the inspector cannot tell them apart from
//    body shape alone. When `body.message` is missing, return
//    `draft-update-no-message`.

import { describe, it, expect } from "vitest";
import {
  isAllowedRecipient,
  assertAllowlistEntry,
  outboundAllowlistFromEnv,
} from "../inspectors/allowlist";
import {
  inspectOutboundMessage,
  inspectDraftSend,
  MASS_SEND_THRESHOLD,
} from "../inspectors/outbound";
import { surfaceReview } from "../surface-review";

// Mirrors the prod (gmail/gmail-dev) wrangler var.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
};
const ALLOWLIST = outboundAllowlistFromEnv(ENV);

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
    expect(isAllowedRecipient("adam@gmail.com", ALLOWLIST)).toBe(true);
  });

  it("matches the wildcard-domain allowlist entry", () => {
    expect(isAllowedRecipient("bob@example.com", ALLOWLIST)).toBe(true);
  });

  it("rejects an unrelated address on a non-allowlisted domain", () => {
    // gmail.com itself is NOT allowlisted; only the specific burner address is.
    expect(isAllowedRecipient("eve@gmail.com", ALLOWLIST)).toBe(false);
  });

  it("normalizes case before comparing", () => {
    expect(isAllowedRecipient("you@example.com", ALLOWLIST)).toBe(true);
  });

  it("treats plus-addressing as strict (a+tag@x ≠ a@x)", () => {
    // Known behavior, not a bug — see plan.
    expect(isAllowedRecipient("adam+tag@gmail.com", ALLOWLIST)).toBe(false);
  });

  it("does not match subdomains of an allowlisted domain", () => {
    expect(isAllowedRecipient("eve@sub.example.com", ALLOWLIST)).toBe(false);
  });

  it("matches nothing against an empty allowlist", () => {
    expect(isAllowedRecipient("adam@gmail.com", [])).toBe(false);
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

describe("B2) outboundAllowlistFromEnv — per-deployment resolution", () => {
  it("parses the comma-separated var, trimming whitespace", () => {
    expect(
      outboundAllowlistFromEnv({
        OUTBOUND_RECIPIENT_ALLOWLIST: " *@example.com , adam@gmail.com ",
      }),
    ).toEqual(["*@example.com", "adam@gmail.com"]);
  });

  it("returns an empty list when the env is missing (fail closed)", () => {
    expect(outboundAllowlistFromEnv(undefined)).toEqual([]);
  });

  it("returns an empty list when the var is unset or blank (fail closed)", () => {
    expect(outboundAllowlistFromEnv({})).toEqual([]);
    expect(outboundAllowlistFromEnv({ OUTBOUND_RECIPIENT_ALLOWLIST: "" })).toEqual([]);
    expect(outboundAllowlistFromEnv({ OUTBOUND_RECIPIENT_ALLOWLIST: "   " })).toEqual([]);
  });

  it("throws on a malformed entry rather than silently skipping it", () => {
    expect(() =>
      outboundAllowlistFromEnv({ OUTBOUND_RECIPIENT_ALLOWLIST: "ok@example.com,no-at-sign" }),
    ).toThrow(/no @/);
  });

  it("two deployments with different vars get independent allowlists", () => {
    const testerEnv = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@tester.example" };
    const testerList = outboundAllowlistFromEnv(testerEnv);
    expect(isAllowedRecipient("friend@tester.example", testerList)).toBe(true);
    expect(isAllowedRecipient("friend@tester.example", ALLOWLIST)).toBe(false);
    expect(isAllowedRecipient("you@example.com", testerList)).toBe(false);
    expect(isAllowedRecipient("you@example.com", ALLOWLIST)).toBe(true);
  });
});

describe("C) inspectOutboundMessage — messages.send body shape (top-level Message)", () => {
  it("allows when all recipients are allowlisted (payload.headers)", () => {
    const result = inspectOutboundMessage(
      {
        body: {
          payload: {
            headers: [
              { name: "To", value: "alice@example.com" },
              { name: "Cc", value: "bob@example.com" },
            ],
          },
        },
      },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies as external-send when any recipient is off the allowlist", () => {
    const result = inspectOutboundMessage(
      {
        body: {
          payload: {
            headers: [
              { name: "To", value: "alice@example.com" },
              { name: "Cc", value: "eve@evil.com" },
            ],
          },
        },
      },
      ENV,
    );
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
    const result = inspectOutboundMessage(
      {
        body: {
          payload: {
            headers: [{ name: "To", value: recipients.join(", ") }],
          },
        },
      },
      ENV,
    );
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
    const result = inspectOutboundMessage(
      {
        body: {
          payload: {
            headers: [
              { name: "To", value: "alice@example.com" },
              { name: "Cc", value: "alice@example.com" },
            ],
          },
        },
      },
      ENV,
    );
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
    const result = inspectOutboundMessage({ body: { raw } }, ENV);
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies as malformed when no recipients can be extracted", () => {
    const result = inspectOutboundMessage({ body: {} }, ENV);
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "send-no-recipients",
    });
  });
});

describe("D) inspectOutboundMessage — draft wrapper body shape ({message: ...}), reached via drafts.send update-and-send", () => {
  it("allows when message.raw recipients are allowlisted", () => {
    const raw = toBase64Url(
      rfc822({
        To: "alice@example.com",
        Subject: "Draft hello",
      }),
    );
    const result = inspectOutboundMessage({ body: { message: { raw } } }, ENV);
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies when message.payload.headers contains an off-allowlist recipient", () => {
    const result = inspectOutboundMessage(
      {
        body: {
          message: {
            payload: {
              headers: [{ name: "To", value: "eve@evil.com" }],
            },
          },
        },
      },
      ENV,
    );
    expect(result).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });
});

describe("E) inspectOutboundMessage — draft wrapper body shape ({id, message: ...}), reached via drafts.send update-and-send", () => {
  it("allows when message recipients are allowlisted", () => {
    const result = inspectOutboundMessage(
      {
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
      },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies as malformed when the body has only {id} and no message", () => {
    const result = inspectOutboundMessage({ body: { id: "d1" } }, ENV);
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "draft-update-no-message",
    });
  });
});

describe("F) drafts surface wiring — draft creation is ungated; the allowlist bites at send time only", () => {
  it("drafts.create and drafts.update are plain allows with NO inspector (draft to anyone is fine)", () => {
    for (const id of ["gmail.users.drafts.create", "gmail.users.drafts.update"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, id).toBeUndefined();
      expect(entry?.category, id).toBe("standard_write");
    }
  });

  it("wires inspectDraftSend onto drafts.send", () => {
    const entry = surfaceReview["gmail.users.drafts.send"];
    expect(entry?.decision).toBe("allow");
    expect(entry?.inspect).toBe(inspectDraftSend);
  });

  it("wires inspectOutboundMessage onto messages.send (direct sends stay gated)", () => {
    const entry = surfaceReview["gmail.users.messages.send"];
    expect(entry?.decision).toBe("allow");
    expect(entry?.inspect).toBe(inspectOutboundMessage);
  });
});

describe("G) inspectDraftSend — stored drafts are unvetted, so bare-id send fails closed; update-and-send is inspected", () => {
  it("denies a bare {id} send (stored draft's recipients cannot be verified)", () => {
    expect(inspectDraftSend({ body: { id: "d1" } }, ENV)).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "draft-send-unvetted-recipients",
      message: expect.stringContaining("update-and-send"),
    });
  });

  it("denies an empty body {} (no recipients to verify)", () => {
    expect(inspectDraftSend({ body: {} }, ENV)).toMatchObject({
      decision: "deny",
      reason: "draft-send-unvetted-recipients",
    });
  });

  it("denies an update-and-send carrying an off-allowlist message.raw", () => {
    const raw = toBase64Url(
      rfc822({ To: "eve@evil.com", Subject: "sneaky" }),
    );
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } }, ENV)).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-send",
    });
  });

  it("allows an update-and-send carrying an allowlisted message.raw", () => {
    const raw = toBase64Url(
      rfc822({ To: "alice@example.com", Subject: "ok" }),
    );
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } }, ENV)).toMatchObject({
      decision: "allow",
    });
  });

  it("elicits mass-send on an update-and-send exceeding the threshold (checks pass through)", () => {
    const recipients = Array.from(
      { length: MASS_SEND_THRESHOLD + 5 },
      (_, i) => `user${i}@example.com`,
    );
    const raw = toBase64Url(
      rfc822({ To: recipients.join(", "), Subject: "bulk" }),
    );
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } }, ENV)).toMatchObject({
      decision: "elicit",
      reason: "mass-send",
    });
  });

  it("delegates a non-JSON media channel to inspectOutboundMessage (off-allowlist denied)", () => {
    const req = {
      rawBody: new TextEncoder().encode(
        "To: eve@evil.com\r\nSubject: hi\r\n\r\nbody",
      ),
      contentType: "message/rfc822",
    };
    expect(inspectDraftSend(req, ENV)).toMatchObject({
      decision: "deny",
      reason: "external-send",
    });
  });
});

describe("H) per-deployment allowlist — inspectors resolve the env they are handed", () => {
  const send = (to: string) => ({
    body: {
      payload: { headers: [{ name: "To", value: to }] },
    },
  });

  it("denies every recipient when no env is passed (fail closed, no permissive default)", () => {
    expect(inspectOutboundMessage(send("you@example.com"))).toMatchObject({
      decision: "deny",
      reason: "external-send",
    });
  });

  it("denies every recipient when the var is unset on the env (fail closed)", () => {
    expect(inspectOutboundMessage(send("you@example.com"), {})).toMatchObject({
      decision: "deny",
      reason: "external-send",
    });
  });

  it("a tester deployment's var allows the tester's contacts and nothing else", () => {
    const testerEnv = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@tester.example,friend@gmail.com" };
    expect(inspectOutboundMessage(send("anyone@tester.example"), testerEnv)).toMatchObject({
      decision: "allow",
    });
    expect(inspectOutboundMessage(send("friend@gmail.com"), testerEnv)).toMatchObject({
      decision: "allow",
    });
    // The bajanov deployment's entries do NOT leak into the tester deployment.
    expect(inspectOutboundMessage(send("you@example.com"), testerEnv)).toMatchObject({
      decision: "deny",
      reason: "external-send",
    });
  });

  it("a malformed var makes the inspector throw (request errors before sending)", () => {
    const badEnv = { OUTBOUND_RECIPIENT_ALLOWLIST: "not-an-entry" };
    expect(() => inspectOutboundMessage(send("you@example.com"), badEnv)).toThrow(
      /no @/,
    );
  });
});
