// Carry-over regression: the gmail.users.messages.import approval dialog shows
// what is being planted in the mailbox.
//
// Attacker: a prompt-injected LLM in the user's own session.
// Precondition: an MCP client that supports elicitation (import is statically
//   `elicit`; on a client without it the import is denied anyway).
// Payload: messages.import of a forged message ("From: ceo@corp.example",
//   "Subject: Wire transfer today") narrated as something harmless, or a body
//   carrying an output-only `payload` decoy beside `raw`.
// Control: `inspectMessageImport` reads the message from `raw` alone, refuses
//   any key Gmail does not read on input and any header block Gmail could read
//   differently, and hands the dialog the From/To/Subject/Date it will show.
// Pre-fix: the import had no inspector, so the dialog carried no fact about
//   the message being imported.
import { describe, it, expect } from "vitest";
import type { InspectRequest } from "@local/shared";
import { inspectMessageImport } from "../message-import";

const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const FORGED =
  "From: ceo@corp.example\r\n" +
  "To: victim@corp.example\r\n" +
  "Subject: Wire transfer today\r\n" +
  "Date: Mon, 9 Nov 2026 09:00:00 +1100\r\n" +
  "\r\n" +
  "Please wire the funds.\r\n";

describe("inspectMessageImport", () => {
  it("FIXED (carry-over): returns from, to, subject and date as written", () => {
    expect(inspectMessageImport({ body: { raw: b64url(FORGED) } })).toEqual({
      decision: "allow",
      summary: {
        from: "ceo@corp.example",
        to: "victim@corp.example",
        subject: "Wire transfer today",
        date: "Mon, 9 Nov 2026 09:00:00 +1100",
      },
    });
  });

  it("decodes an RFC 2047 encoded-word subject", () => {
    const subject = `=?UTF-8?B?${Buffer.from("Überweisung — heute", "utf8").toString("base64")}?=`;
    const r = inspectMessageImport({ body: { raw: b64url(`From: a@corp.example\r\nSubject: ${subject}\r\n\r\nx`) } });
    expect(r.summary).toEqual({ from: "a@corp.example", subject: "Überweisung — heute" });
  });

  it.each([
    ["From", "From: colleague@corp.example\r\nFrom: ceo@corp.example\r\nSubject: a\r\n\r\nb"],
    ["To", "To: a@corp.example\r\nTO: b@corp.example\r\n\r\nb"],
    ["Subject", "Subject: first\r\nSubject: second\r\n\r\nx"],
    ["Date", "Date: Mon, 9 Nov 2026 09:00:00 +1100\r\ndate: Tue, 10 Nov 2026 09:00:00 +1100\r\n\r\nx"],
  ])("denies a repeated %s header as duplicate-summary-header (readers disagree on which one shows)", (_name, msg) => {
    expect(inspectMessageImport({ body: { raw: b64url(msg) } })).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "duplicate-summary-header",
    });
  });

  it("still allows a repeated header the dialog does not show (Received)", () => {
    const r = inspectMessageImport({ body: { raw: b64url("Received: a\r\nReceived: b\r\nSubject: s\r\n\r\nx") } });
    expect(r).toEqual({ decision: "allow", summary: { subject: "s" } });
  });

  it("omits absent headers (an empty summary is fine)", () => {
    expect(inspectMessageImport({ body: { raw: b64url("X-Other: 1\r\n\r\nbody") } })).toEqual({
      decision: "allow",
      summary: {},
    });
  });

  it("accepts threadId and labelIds beside raw", () => {
    const r = inspectMessageImport({ body: { raw: b64url(FORGED), threadId: "t1", labelIds: ["INBOX"] } });
    expect(r.decision).toBe("allow");
  });

  it.each<[string, Record<string, unknown>]>([
    ["{ payload }", { payload: { headers: [{ name: "From", value: "ceo@corp.example" }] } }],
    ["{ raw, payload }", { raw: b64url(FORGED), payload: { headers: [] } }],
    ["{ raw, message }", { raw: b64url(FORGED), message: { raw: b64url(FORGED) } }],
    ["{ raw, id }", { raw: b64url(FORGED), id: "x" }],
  ])("refuses %s as send-unexpected-key, naming messages.import", (_label, body) => {
    const r = inspectMessageImport({ body });
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "send-unexpected-key" });
    expect(r.message).toContain("gmail.users.messages.import");
    expect(r.message).toContain("Gmail builds the imported message from `raw` alone");
  });

  it.each<[string, Record<string, unknown>]>([
    ["{}", {}],
    ["{ raw: \"\" }", { raw: "" }],
    ["{ raw: null }", { raw: null }],
    ["{ raw: 0 }", { raw: 0 }],
    ["an undecodable raw", { raw: "%%%not base64%%%" }],
  ])("denies %s as import-no-raw", (_label, body) => {
    expect(inspectMessageImport({ body })).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "import-no-raw",
    });
  });

  it.each<[string, InspectRequest]>([
    ["a string body", { body: "raw" }],
    ["an array body", { body: [] }],
    ["no body", {}],
    ["a media body", { rawBody: new TextEncoder().encode(FORGED), contentType: "message/rfc822" }],
  ])("denies %s as import-body-not-object", (_label, req) => {
    expect(inspectMessageImport(req)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "import-body-not-object",
    });
  });

  it("denies a lone CR in the header block as ambiguous-line-ending", () => {
    const raw = b64url("From: ceo@corp.example\rSubject: hidden\r\nSubject: shown\r\n\r\nx");
    expect(inspectMessageImport({ body: { raw } })).toMatchObject({
      decision: "deny",
      reason: "ambiguous-line-ending",
    });
  });

  it("denies a header name outside RFC 5322 ftext as malformed-header-name", () => {
    const raw = b64url("From: a@corp.example\r\nSub ject: x\r\n\r\nbody");
    expect(inspectMessageImport({ body: { raw } })).toMatchObject({
      decision: "deny",
      reason: "malformed-header-name",
    });
  });
});
