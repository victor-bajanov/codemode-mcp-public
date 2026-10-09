// RFC 5322 header-block parsing in the outbound inspector (F-3): the header
// section ends at the first empty line (CRLF or bare LF), a lone CR or mixed
// CRLF/LF line endings in the header block deny as ambiguous, and a repeated
// To/Cc/Bcc header is denied rather than judged on one occurrence. A header
// name outside RFC 5322 ftext denies as malformed, and an address-list element
// carrying a quoted string or a comment is refused rather than having a
// look-alike angle-addr pulled out of it (F-3, F-18).
// Every case runs on each channel that carries RFC 822 text: JSON `raw`,
// `rawBody` (uploadType=media) and `multipart` (uploadType=multipart).

import { describe, it, expect } from "vitest";
import type { InspectRequest } from "@local/shared";
import {
  inspectDraftSend,
  inspectOutboundMessage,
  MASS_SEND_THRESHOLD,
  UNREADABLE_RECIPIENT_MESSAGE,
} from "../inspectors/outbound";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example" };
const OK = "staff@allowed.example";
const OK2 = "other@allowed.example";
const EVIL = "outsider@evil.example";

function b64url(s: string): string {
  return Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

/** The same RFC 822 text on each channel the inspector reads it from. */
const CHANNELS: ReadonlyArray<[string, (msg: string) => InspectRequest]> = [
  ["JSON raw", (msg) => ({ body: { raw: b64url(msg) } })],
  ["rawBody", (msg) => ({ rawBody: new TextEncoder().encode(msg), contentType: "message/rfc822" })],
  [
    "multipart",
    (msg) => ({
      multipart: [
        { name: "metadata", contentType: "application/json", value: "{}" },
        { name: "media", contentType: "message/rfc822", bodyBase64: b64(msg) },
      ],
      contentType: "multipart/related",
    }),
  ],
];

describe.each(CHANNELS)("duplicate recipient headers (%s)", (_channel, req) => {
  it.each([
    ["To", `To: ${EVIL}\r\nTo: ${OK}\r\nSubject: hi\r\n\r\nbody\r\n`],
    ["Cc", `To: ${OK}\r\nCc: ${EVIL}\r\nCc: ${OK2}\r\nSubject: hi\r\n\r\nbody\r\n`],
    ["Bcc", `To: ${OK}\r\nBcc: ${EVIL}\r\nBcc: ${OK2}\r\n\r\nbody\r\n`],
    ["To, differing case", `To: ${OK}\r\nTO: ${EVIL}\r\n\r\nbody\r\n`],
    ["To, both allowlisted", `To: ${OK}\r\nTo: ${OK2}\r\n\r\nbody\r\n`],
    ["To, bare LF", `To: ${OK}\nTo: ${EVIL}\n\nbody\n`],
  ])("denies a repeated %s header", (_label, msg) => {
    expect(inspectOutboundMessage(req(msg), ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "duplicate-recipient-header",
      message: expect.stringMatching(/repeats a To, Cc or Bcc header/),
    });
  });

  it("does not treat a folded continuation as a second occurrence", () => {
    const msg = `To: ${OK},\r\n ${OK2}\r\nSubject: hi\r\n\r\nbody\r\n`;
    expect(inspectOutboundMessage(req(msg), ENV).decision).toBe("allow");
  });

  it("allows one To, one Cc and one Bcc each carrying several allowlisted addresses", () => {
    const msg = `To: ${OK}, ${OK2}\r\nCc: a@allowed.example, b@allowed.example\r\nBcc: c@allowed.example\r\n\r\nbody\r\n`;
    expect(inspectOutboundMessage(req(msg), ENV).decision).toBe("allow");
  });

  it("still allows a repeated non-recipient header (Subject, Received)", () => {
    const msg = `Received: a\r\nReceived: b\r\nTo: ${OK}\r\nSubject: one\r\nSubject: two\r\n\r\nbody\r\n`;
    expect(inspectOutboundMessage(req(msg), ENV).decision).toBe("allow");
  });
});

describe.each(CHANNELS)("header block ends at the first empty line (%s)", (_channel, req) => {
  it("bare-LF headers with a CRLFCRLF later in the body: the body is ignored, the real To is judged", () => {
    const msg =
      `To: ${EVIL}\n` +
      "Subject: hi\n" +
      "\n" +
      "This is the body.\n" +
      `To: ${OK}\n` +
      "\r\n\r\n" +
      "rest of body\n";
    expect(inspectOutboundMessage(req(msg), ENV)).toMatchObject({ decision: "deny", reason: "external-send" });
  });

  it("an off-list To in the body of a bare-LF message does not taint an allowlisted send", () => {
    const msg = `To: ${OK}\nSubject: hi\n\nquoted reply:\nTo: ${EVIL}\r\n\r\nmore\n`;
    expect(inspectOutboundMessage(req(msg), ENV).decision).toBe("allow");
  });

  it("a lone CR in the header block denies as ambiguous (readers disagree on it)", () => {
    const ambiguous = { decision: "deny", category: "malformed", reason: "ambiguous-line-ending" };
    for (const msg of [
      // Only lone CRs: some readers see two headers and a body, others one line.
      `To: ${OK}\rSubject: hi\r\rbody\r`,
      `Subject: hi\rTo: ${EVIL}\r\rbody\r`,
      // A lone-CR "blank line" before an off-list To: a reader that splits on
      // CR sees the second To as body, one that does not sees a To line
      // carrying the outsider (or two To headers).
      `To: ${OK}\r\rTo: ${EVIL}\r\n\r\nbody`,
      // A lone CR inside an otherwise CRLF header line.
      `To: ${OK}\rCc: ${EVIL}\r\nSubject: hi\r\n\r\nbody`,
      // CR CR LF: the CR before CRLF is lone.
      `To: ${OK}\r\r\nTo: ${EVIL}\r\n\r\nbody`,
    ]) {
      expect(inspectOutboundMessage(req(msg), ENV), JSON.stringify(msg)).toMatchObject({
        ...ambiguous,
        message: expect.stringMatching(/bare CR or mixes CRLF with bare LF/),
      });
    }
  });

  it("a lone CR in the body, after a proper blank line, is not examined", () => {
    expect(inspectOutboundMessage(req(`To: ${OK}\r\nSubject: hi\r\n\r\nbody\rTo: ${EVIL}\r\r`), ENV).decision).toBe(
      "allow",
    );
    expect(inspectOutboundMessage(req(`To: ${OK}\nSubject: hi\n\nbody\r\rmore\r`), ENV).decision).toBe("allow");
  });

  it("CRLF mixed with bare LF in the header block denies as ambiguous", () => {
    for (const msg of [
      `To: ${OK}\r\nSubject: hi\r\n\nTo: ${EVIL}\r\n\r\n`,
      `To: ${OK}\n\r\nTo: ${EVIL}\r\n\r\n`,
      `To: ${EVIL}\r\n\nTo: ${OK}\r\n\r\n`,
      `To: ${OK}\r\nSubject: hi\nCc: ${OK2}\r\n\r\nbody`,
    ]) {
      expect(inspectOutboundMessage(req(msg), ENV), JSON.stringify(msg)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "ambiguous-line-ending",
      });
    }
  });

  it("mixed line endings in the body only are not examined", () => {
    expect(inspectOutboundMessage(req(`To: ${OK}\r\nSubject: hi\r\n\r\nline\nline\r\n`), ENV).decision).toBe("allow");
    expect(inspectOutboundMessage(req(`To: ${OK}\nSubject: hi\n\nline\r\nline\n`), ENV).decision).toBe("allow");
  });

  it("a message that begins with an empty line has no headers, so no recipients (fail closed)", () => {
    expect(inspectOutboundMessage(req(`\r\nTo: ${OK}\r\n\r\nbody`), ENV)).toMatchObject({
      decision: "deny",
      reason: "send-no-recipients",
    });
  });

  it("an unparseable recipient address denies as external-send", () => {
    for (const to of [`${EVIL}@allowed.example`, '"a b"@allowed.example', `undisclosed: ${EVIL};`]) {
      expect(inspectOutboundMessage(req(`To: ${to}\r\n\r\nbody`), ENV), to).toMatchObject({
        decision: "deny",
        reason: "external-send",
      });
    }
  });

  it("an unreadable recipient tells the caller how to write it; an off-allowlist one does not (F-18)", () => {
    expect(inspectOutboundMessage(req(`To: "Smith, John" <${OK}>\r\n\r\nbody`), ENV)).toMatchObject({
      decision: "deny",
      reason: "external-send",
      message: UNREADABLE_RECIPIENT_MESSAGE,
    });
    expect(inspectOutboundMessage(req(`To: ${EVIL}\r\n\r\nbody`), ENV).message).toBeUndefined();
  });
});

describe("header-only messages", () => {
  it("JSON raw with no blank line: the whole text is the header section", () => {
    const raw = b64url(`To: ${OK}\r\nSubject: hi`);
    expect(inspectOutboundMessage({ body: { raw } }, ENV).decision).toBe("allow");
    const evil = b64url(`Subject: hi\nTo: ${EVIL}`);
    expect(inspectOutboundMessage({ body: { raw: evil } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "external-send",
    });
  });

  it("JSON raw ending at the header terminator (empty body)", () => {
    const raw = b64url(`To: ${OK}\r\nSubject: hi\r\n\r\n`);
    expect(inspectOutboundMessage({ body: { raw } }, ENV).decision).toBe("allow");
  });

  it("an upload with no blank line at all still fails closed (terminator must be in the scan window)", () => {
    const req = { rawBody: new TextEncoder().encode(`To: ${OK}\r\nSubject: hi`), contentType: "message/rfc822" };
    expect(inspectOutboundMessage(req, ENV)).toMatchObject({ decision: "deny", reason: "send-no-recipients" });
  });
});

describe("drafts.send update-and-send and payload.headers", () => {
  it("drafts.send { id, message: { raw } } with a repeated To is denied", () => {
    const raw = b64url(`To: ${EVIL}\r\nTo: ${OK}\r\n\r\nbody`);
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "duplicate-recipient-header",
    });
  });

  it("payload.headers already collects every occurrence, so a repeated To there is judged in full", () => {
    const twoTo = (a: string, b: string): InspectRequest => ({
      body: { payload: { headers: [{ name: "To", value: a }, { name: "To", value: b }] } },
    });
    expect(inspectOutboundMessage(twoTo(EVIL, OK), ENV)).toMatchObject({ decision: "deny", reason: "external-send" });
    expect(inspectOutboundMessage(twoTo(OK, OK2), ENV).decision).toBe("allow");
  });

  it("the mass-send summary shows the first Subject occurrence", () => {
    const to = Array.from({ length: MASS_SEND_THRESHOLD + 1 }, (_, i) => `r${i}@allowed.example`).join(", ");
    const raw = b64url(`To: ${to}\r\nSubject: first\r\nSubject: second\r\n\r\nbody`);
    const r = inspectOutboundMessage({ body: { raw } }, ENV);
    expect(r).toMatchObject({ decision: "elicit", reason: "mass-send" });
    expect(r.summary).toMatchObject({ subject: "first" });
  });
});

/** Address-list elements whose quoted string or comment carries a look-alike
 *  angle-addr: every MTA delivers these to the outsider, never to OK. */
const ANGLE_ADDR_DECOYS: ReadonlyArray<[string, string]> = [
  ["quoted display-name holding an angle-addr", `"<${OK}>" <${EVIL}>`],
  ["addr-spec followed by a comment holding an angle-addr", `${EVIL} (<${OK}>)`],
  ["comment holding an angle-addr before the addr-spec", `(<${OK}>) ${EVIL}`],
  ["quoted string holding an angle-addr before the addr-spec", `"a<${OK}>" ${EVIL}`],
  ["quoted display-name with a comma and an angle-addr", `"x, <${OK}>" <${EVIL}>`],
  ["comment inside the angle-addr", `Staff <${OK}(note)>`],
  ["text after the angle-addr", `<${OK}> ${EVIL}`],
  ["two angle-addrs", `<${EVIL}> <${OK}>`],
  ["stray closing bracket in the display-name", `Staff> <${OK}>`],
  // Display-names that are not an RFC 5322 phrase: a mainstream parser
  // (CPython email, policy.default) reads each as a message to the outsider.
  ["addr-spec as the display-name", `${EVIL} <${OK}>`],
  ["group syntax before the angle-addr", `g:${EVIL}; <${OK}>`],
  ["colon after an addr-spec display-name", `${EVIL}: <${OK}>`],
  ["semicolon after an addr-spec display-name", `${EVIL}; <${OK}>`],
  ["square brackets in the display-name", `Staff [x] <${OK}>`],
  ["backslash in the display-name", `Staff\\x <${OK}>`],
];

describe.each(CHANNELS)("quoted strings and comments in address lists fail closed (%s)", (_channel, req) => {
  it.each(ANGLE_ADDR_DECOYS)("denies %s as external-send", (_label, to) => {
    for (const field of ["To", "Cc", "Bcc"]) {
      const msg = field === "To" ? `To: ${to}\r\n\r\nbody` : `To: ${OK}\r\n${field}: ${to}\r\n\r\nbody`;
      expect(inspectOutboundMessage(req(msg), ENV), `${field}: ${to}`).toMatchObject({
        decision: "deny",
        category: "external_data_flow",
        reason: "external-send",
      });
    }
  });

  it("refuses a quoted display-name even when the angle-addr is allowlisted (documented false positive)", () => {
    for (const to of [`"Staff" <${OK}>`, `"Smith, John" <${OK}>`, `${OK} (Staff)`]) {
      expect(inspectOutboundMessage(req(`To: ${to}\r\n\r\nbody`), ENV), to).toMatchObject({
        decision: "deny",
        reason: "external-send",
      });
    }
  });

  it("still allows a bare addr-spec, a bare angle-addr and an unquoted display-name", () => {
    for (const to of [
      OK,
      `<${OK}>`,
      `Staff <${OK}>`,
      `Staff Member <${OK}>, ${OK2}`,
      `J. O'Brien-Smith <${OK}>`,
      `José Núñez <${OK}>`,
      `=?utf-8?B?Sm9zw6k=?= <${OK}>`,
    ]) {
      expect(inspectOutboundMessage(req(`To: ${to}\r\n\r\nbody`), ENV).decision, to).toBe("allow");
    }
  });
});

describe("quoted strings and comments in payload.headers fail closed", () => {
  it.each(ANGLE_ADDR_DECOYS)("denies %s as external-send", (_label, to) => {
    for (const name of ["To", "cc", "BCC"]) {
      const headers = name === "To" ? [{ name, value: to }] : [{ name: "To", value: OK }, { name, value: to }];
      expect(inspectOutboundMessage({ body: { payload: { headers } } }, ENV), `${name}: ${to}`).toMatchObject({
        decision: "deny",
        reason: "external-send",
      });
    }
  });

  it("drafts.send update-and-send with a quoted decoy is denied", () => {
    const body = { id: "d1", message: { payload: { headers: [{ name: "To", value: `"<${OK}>" <${EVIL}>` }] } } };
    expect(inspectDraftSend({ body }, ENV)).toMatchObject({ decision: "deny", reason: "external-send" });
  });

  it("still allows an unquoted display-name", () => {
    const headers = [{ name: "To", value: `Staff <${OK}>` }];
    expect(inspectOutboundMessage({ body: { payload: { headers } } }, ENV).decision).toBe("allow");
  });
});

describe.each(CHANNELS)("header names outside RFC 5322 ftext (%s)", (_channel, req) => {
  it.each([
    ["NUL in the name", `To: ${OK}\r\nBcc\0: ${EVIL}\r\n\r\nbody`],
    ["space inside the name", `To: ${OK}\r\nB cc: ${EVIL}\r\n\r\nbody`],
    ["non-ASCII in the name", `To: ${OK}\r\nBc\u00e7: ${EVIL}\r\n\r\nbody`],
    ["DEL in the name", `To: ${OK}\r\nBcc\x7f: ${EVIL}\r\n\r\nbody`],
    ["empty name", `To: ${OK}\r\n: ${EVIL}\r\n\r\nbody`],
  ])("denies %s as malformed-header-name", (_label, msg) => {
    expect(inspectOutboundMessage(req(msg), ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "malformed-header-name",
    });
  });

  it("tolerates whitespace before the colon and leaves body lines alone", () => {
    expect(inspectOutboundMessage(req(`To : ${OK}\r\nSubject\t: hi\r\n\r\nB cc: ${EVIL}\r\n`), ENV).decision).toBe(
      "allow",
    );
  });
});
