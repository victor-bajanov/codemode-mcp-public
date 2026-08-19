// Regression tests for UTF-8 / non-ASCII handling in the outbound inspector's
// elicit summary. The bug: subjects with a non-ASCII character (e.g. an em dash
// "—", U+2014) came back mojibake'd ("â€"") in the mass-send elicit summary
// because base64UrlDecode used atob() and treated the result as a Latin-1
// binary string instead of decoding it as UTF-8. RFC 2047 encoded-word subjects
// (the form the send guidance now recommends for non-ASCII headers) were also
// shown verbatim as "=?UTF-8?B?...?=" rather than their decoded text.
//
// Only the mass-send (elicit) branch populates summary.subject, so each test
// uses 30 allowlisted recipients to reach it.

import { describe, it, expect } from "vitest";
import { inspectOutboundMessage } from "../inspectors/outbound";

// Mirrors the prod (gmail/gmail-dev) wrangler var.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
};

const RECIPIENTS = Array.from(
  { length: 30 },
  (_, i) => `user${i}@example.com`,
).join(", ");

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

function summarySubjectFor(subjectHeaderValue: string): string {
  const raw = toBase64Url(rfc822({ To: RECIPIENTS, Subject: subjectHeaderValue }));
  const result = inspectOutboundMessage({ body: { raw } }, ENV);
  expect(result).toMatchObject({ decision: "elicit", reason: "mass-send" });
  return (result.summary as { subject: string }).subject;
}

describe("outbound inspector — UTF-8 subject handling", () => {
  const EXPECTED = "Practitioner voices — Dynamic Workflows";

  it("preserves a literal UTF-8 em dash in a raw subject (no mojibake)", () => {
    const subject = summarySubjectFor(EXPECTED);
    expect(subject).toBe(EXPECTED);
    // Guard against the specific single-mojibake fingerprint of the old bug.
    expect(subject).not.toContain("â");
  });

  it("decodes an RFC 2047 'B' encoded-word subject to its real text", () => {
    const b64 = Buffer.from(EXPECTED, "utf8").toString("base64");
    const subject = summarySubjectFor(`=?UTF-8?B?${b64}?=`);
    expect(subject).toBe(EXPECTED);
  });

  it("decodes an RFC 2047 'Q' encoded-word subject (=XX bytes and _ as space)", () => {
    // "Practitioner voices — Dynamic" with the em dash as =E2=80=94 and _ spaces.
    const subject = summarySubjectFor(
      "=?UTF-8?Q?Practitioner_voices_=E2=80=94_Dynamic?=",
    );
    expect(subject).toBe("Practitioner voices — Dynamic");
  });

  it("leaves a plain ASCII subject untouched", () => {
    expect(summarySubjectFor("Plain ASCII subject")).toBe("Plain ASCII subject");
  });
});
