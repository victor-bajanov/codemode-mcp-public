// RFC 5322 header-block parsing in the outbound inspector (F-3): the header
// section ends at the first empty line (CRLF or bare LF), a lone CR or mixed
// CRLF/LF line endings in the header block deny as ambiguous, and a repeated
// To/Cc/Bcc header is denied rather than judged on one occurrence. A header
// name outside RFC 5322 ftext denies as malformed, and an address-list element
// carrying a quoted string or a comment is refused rather than having a
// look-alike angle-addr pulled out of it (F-3, F-18).
// Every case runs on each path that carries RFC 822 text: messages.send `raw`,
// drafts.send `message.raw` and the messages.send.media `rawBody` upload. The
// JSON messages.send endpoint refuses a rawBody or multipart body outright.

import { describe, it, expect } from "vitest";
import type { InspectRequest, InspectResult } from "@local/shared";
import {
  inspectDraftSend,
  inspectOutboundMessage,
  inspectOutboundMessageMedia,
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

const media = (msg: string): InspectRequest => ({
  rawBody: new TextEncoder().encode(msg),
  contentType: "message/rfc822",
  query: { uploadType: "media" },
});

/** The same RFC 822 text judged on each path that reads it: messages.send
 *  `raw`, drafts.send `message.raw` and the messages.send.media upload. */
const CHANNELS: ReadonlyArray<[string, (msg: string) => InspectResult]> = [
  ["messages.send raw", (msg) => inspectOutboundMessage({ body: { raw: b64url(msg) } }, ENV)],
  ["drafts.send message.raw", (msg) => inspectDraftSend({ body: { id: "d1", message: { raw: b64url(msg) } } }, ENV)],
  ["messages.send.media rawBody", (msg) => inspectOutboundMessageMedia(media(msg), ENV)],
];

describe("non-JSON channels on the JSON messages.send endpoint are refused", () => {
  const msg = `To: ${OK}\r\nSubject: hi\r\n\r\nbody\r\n`;
  it.each<[string, InspectRequest]>([
    ["rawBody", media(msg)],
    ["multipart", {
      multipart: [
        { name: "metadata", contentType: "application/json", value: "{}" },
        { name: "media", contentType: "message/rfc822", bodyBase64: b64(msg) },
      ],
      contentType: "multipart/related",
    }],
  ])("denies an allowlisted %s message as send-no-raw", (_label, req) => {
    expect(inspectOutboundMessage(req, ENV)).toMatchObject({ decision: "deny", reason: "send-no-raw" });
  });

  it("the media send still refuses a multipart body (unchanged)", () => {
    const req: InspectRequest = {
      multipart: [{ name: "media", contentType: "message/rfc822", value: msg }],
      contentType: "message/rfc822",
      query: { uploadType: "media" },
    };
    expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({ decision: "deny", reason: "send-no-recipients" });
  });
});

describe.each(CHANNELS)("duplicate recipient headers (%s)", (_channel, judge) => {
  it.each([
    ["To", `To: ${EVIL}\r\nTo: ${OK}\r\nSubject: hi\r\n\r\nbody\r\n`],
    ["Cc", `To: ${OK}\r\nCc: ${EVIL}\r\nCc: ${OK2}\r\nSubject: hi\r\n\r\nbody\r\n`],
    ["Bcc", `To: ${OK}\r\nBcc: ${EVIL}\r\nBcc: ${OK2}\r\n\r\nbody\r\n`],
    ["To, differing case", `To: ${OK}\r\nTO: ${EVIL}\r\n\r\nbody\r\n`],
    ["To, both allowlisted", `To: ${OK}\r\nTo: ${OK2}\r\n\r\nbody\r\n`],
    ["To, bare LF", `To: ${OK}\nTo: ${EVIL}\n\nbody\n`],
  ])("denies a repeated %s header", (_label, msg) => {
    expect(judge(msg)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "duplicate-recipient-header",
      message: expect.stringMatching(/repeats a To, Cc or Bcc header/),
    });
  });

  it("does not treat a folded continuation as a second occurrence", () => {
    const msg = `To: ${OK},\r\n ${OK2}\r\nSubject: hi\r\n\r\nbody\r\n`;
    expect(judge(msg).decision).toBe("allow");
  });

  it("allows one To, one Cc and one Bcc each carrying several allowlisted addresses", () => {
    const msg = `To: ${OK}, ${OK2}\r\nCc: a@allowed.example, b@allowed.example\r\nBcc: c@allowed.example\r\n\r\nbody\r\n`;
    expect(judge(msg).decision).toBe("allow");
  });

  it("still allows a repeated non-recipient header (Subject, Received)", () => {
    const msg = `Received: a\r\nReceived: b\r\nTo: ${OK}\r\nSubject: one\r\nSubject: two\r\n\r\nbody\r\n`;
    expect(judge(msg).decision).toBe("allow");
  });
});

describe.each(CHANNELS)("header block ends at the first empty line (%s)", (_channel, judge) => {
  it("bare-LF headers with a CRLFCRLF later in the body: the body is ignored, the real To is judged", () => {
    const msg =
      `To: ${EVIL}\n` +
      "Subject: hi\n" +
      "\n" +
      "This is the body.\n" +
      `To: ${OK}\n` +
      "\r\n\r\n" +
      "rest of body\n";
    expect(judge(msg)).toMatchObject({ decision: "deny", reason: "external-send" });
  });

  it("an off-list To in the body of a bare-LF message does not taint an allowlisted send", () => {
    const msg = `To: ${OK}\nSubject: hi\n\nquoted reply:\nTo: ${EVIL}\r\n\r\nmore\n`;
    expect(judge(msg).decision).toBe("allow");
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
      expect(judge(msg), JSON.stringify(msg)).toMatchObject({
        ...ambiguous,
        message: expect.stringMatching(/bare CR or mixes CRLF with bare LF/),
      });
    }
  });

  it("a lone CR in the body, after a proper blank line, is not examined", () => {
    expect(judge(`To: ${OK}\r\nSubject: hi\r\n\r\nbody\rTo: ${EVIL}\r\r`).decision).toBe(
      "allow",
    );
    expect(judge(`To: ${OK}\nSubject: hi\n\nbody\r\rmore\r`).decision).toBe("allow");
  });

  it("CRLF mixed with bare LF in the header block denies as ambiguous", () => {
    for (const msg of [
      `To: ${OK}\r\nSubject: hi\r\n\nTo: ${EVIL}\r\n\r\n`,
      `To: ${OK}\n\r\nTo: ${EVIL}\r\n\r\n`,
      `To: ${EVIL}\r\n\nTo: ${OK}\r\n\r\n`,
      `To: ${OK}\r\nSubject: hi\nCc: ${OK2}\r\n\r\nbody`,
    ]) {
      expect(judge(msg), JSON.stringify(msg)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "ambiguous-line-ending",
      });
    }
  });

  it("mixed line endings in the body only are not examined", () => {
    expect(judge(`To: ${OK}\r\nSubject: hi\r\n\r\nline\nline\r\n`).decision).toBe("allow");
    expect(judge(`To: ${OK}\nSubject: hi\n\nline\r\nline\n`).decision).toBe("allow");
  });

  it("a message that begins with an empty line has no headers, so no recipients (fail closed)", () => {
    expect(judge(`\r\nTo: ${OK}\r\n\r\nbody`)).toMatchObject({
      decision: "deny",
      reason: "send-no-recipients",
    });
  });

  it("an unparseable recipient address denies as external-send", () => {
    for (const to of [`${EVIL}@allowed.example`, '"a b"@allowed.example', `undisclosed: ${EVIL};`]) {
      expect(judge(`To: ${to}\r\n\r\nbody`), to).toMatchObject({
        decision: "deny",
        reason: "external-send",
      });
    }
  });

  it("an unreadable recipient tells the caller how to write it; an off-allowlist one does not (F-18)", () => {
    expect(judge(`To: "Smith, John" <${OK}>\r\n\r\nbody`)).toMatchObject({
      decision: "deny",
      reason: "external-send",
      message: UNREADABLE_RECIPIENT_MESSAGE,
    });
    expect(judge(`To: ${EVIL}\r\n\r\nbody`).message).toBeUndefined();
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
    expect(inspectOutboundMessageMedia(media(`To: ${OK}\r\nSubject: hi`), ENV)).toMatchObject({
      decision: "deny",
      reason: "send-no-recipients",
    });
  });
});

describe("drafts.send { id, message: { raw } } and the payload decoy", () => {
  it("drafts.send { id, message: { raw } } with a repeated To is denied", () => {
    const raw = b64url(`To: ${EVIL}\r\nTo: ${OK}\r\n\r\nbody`);
    expect(inspectDraftSend({ body: { id: "d1", message: { raw } } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "duplicate-recipient-header",
    });
  });

  it("a repeated To in raw is denied on both send paths; a payload.headers decoy is refused unread", () => {
    for (const [a, b] of [[EVIL, OK], [OK, OK2]]) {
      const raw = b64url(`To: ${a}\r\nTo: ${b}\r\n\r\nbody`);
      expect(inspectOutboundMessage({ body: { raw } }, ENV)).toMatchObject({
        decision: "deny",
        reason: "duplicate-recipient-header",
      });
      expect(inspectDraftSend({ body: { id: "d1", message: { raw } } }, ENV)).toMatchObject({
        decision: "deny",
        reason: "duplicate-recipient-header",
      });
      const headers = [{ name: "To", value: a }, { name: "To", value: b }];
      expect(inspectOutboundMessage({ body: { payload: { headers } } }, ENV)).toMatchObject({
        decision: "deny",
        reason: "send-unexpected-key",
      });
    }
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

describe.each(CHANNELS)("quoted strings and comments in address lists fail closed (%s)", (_channel, judge) => {
  it.each(ANGLE_ADDR_DECOYS)("denies %s as external-send", (_label, to) => {
    for (const field of ["To", "Cc", "Bcc"]) {
      const msg = field === "To" ? `To: ${to}\r\n\r\nbody` : `To: ${OK}\r\n${field}: ${to}\r\n\r\nbody`;
      expect(judge(msg), `${field}: ${to}`).toMatchObject({
        decision: "deny",
        category: "external_data_flow",
        reason: "external-send",
      });
    }
  });

  it("refuses a quoted display-name even when the angle-addr is allowlisted (documented false positive)", () => {
    for (const to of [`"Staff" <${OK}>`, `"Smith, John" <${OK}>`, `${OK} (Staff)`]) {
      expect(judge(`To: ${to}\r\n\r\nbody`), to).toMatchObject({
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
      expect(judge(`To: ${to}\r\n\r\nbody`).decision, to).toBe("allow");
    }
  });
});

describe("quoted strings and comments: drafts.send message.raw fails closed, payload.headers is refused unread", () => {
  it.each(ANGLE_ADDR_DECOYS)("denies %s as external-send in a drafts.send message.raw", (_label, to) => {
    for (const name of ["To", "cc", "BCC"]) {
      const msg = name === "To" ? `To: ${to}\r\n\r\nbody` : `To: ${OK}\r\n${name}: ${to}\r\n\r\nbody`;
      const body = { id: "d1", message: { raw: b64url(msg) } };
      expect(inspectDraftSend({ body }, ENV), `${name}: ${to}`).toMatchObject({
        decision: "deny",
        reason: "external-send",
      });
    }
  });

  it.each(ANGLE_ADDR_DECOYS)("refuses %s in payload.headers as send-unexpected-key", (_label, to) => {
    for (const name of ["To", "cc", "BCC"]) {
      const headers = name === "To" ? [{ name, value: to }] : [{ name: "To", value: OK }, { name, value: to }];
      expect(inspectOutboundMessage({ body: { payload: { headers } } }, ENV), `${name}: ${to}`).toMatchObject({
        decision: "deny",
        reason: "send-unexpected-key",
      });
      expect(inspectDraftSend({ body: { id: "d1", message: { payload: { headers } } } }, ENV), `${name}: ${to}`)
        .toMatchObject({ decision: "deny", reason: "send-unexpected-key" });
    }
  });

  it("still allows an unquoted display-name in a drafts.send message.raw", () => {
    const body = { id: "d1", message: { raw: b64url(`To: Staff <${OK}>\r\n\r\nbody`) } };
    expect(inspectDraftSend({ body }, ENV).decision).toBe("allow");
  });
});

describe.each(CHANNELS)("header names outside RFC 5322 ftext (%s)", (_channel, judge) => {
  it.each([
    ["NUL in the name", `To: ${OK}\r\nBcc\0: ${EVIL}\r\n\r\nbody`],
    ["space inside the name", `To: ${OK}\r\nB cc: ${EVIL}\r\n\r\nbody`],
    ["non-ASCII in the name", `To: ${OK}\r\nBc\u00e7: ${EVIL}\r\n\r\nbody`],
    ["DEL in the name", `To: ${OK}\r\nBcc\x7f: ${EVIL}\r\n\r\nbody`],
    ["empty name", `To: ${OK}\r\n: ${EVIL}\r\n\r\nbody`],
  ])("denies %s as malformed-header-name", (_label, msg) => {
    expect(judge(msg)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "malformed-header-name",
    });
  });

  it("tolerates whitespace before the colon and leaves body lines alone", () => {
    expect(judge(`To : ${OK}\r\nSubject\t: hi\r\n\r\nB cc: ${EVIL}\r\n`).decision).toBe(
      "allow",
    );
  });
});
