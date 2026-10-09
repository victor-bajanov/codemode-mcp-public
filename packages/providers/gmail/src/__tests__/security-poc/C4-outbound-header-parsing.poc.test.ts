// Security-review POC C4 — Gmail outbound inspector: header-parsing
// differentials between `parseHeaders` (inspectors/outbound.ts) and a
// standards-conformant RFC 5322 reader such as Gmail's.
//
// The inspector is the ONLY control between sandbox code and an outbound
// send on this deployment (the surface review marks messages.send `allow` and
// relies on `inspectOutboundMessage` for the recipient allowlist). Two
// properties of its header parser mean a crafted `raw` message can be ruled on
// using recipients that are not the ones Gmail will deliver to:
//
//   (a) `headers.set(name, value)` keeps only the LAST occurrence of a repeated
//       header name, so a message carrying two `To:` lines is judged on the
//       second one only.
//   (b) The end of the header block is located by searching for "\r\n\r\n"
//       FIRST and only falling back to "\n\n" if none is found. A message that
//       uses bare-LF line endings for its real header block but contains a
//       CRLFCRLF sequence later in the BODY has its body text parsed as
//       headers, and any `To:` line in the body overrides the real one.
//
// Originally CONFIRMED at the inspector level (the inspector returned `allow`
// for a message whose first/real To header was off-allowlist). RFC 5322 §3.6
// makes the header block end at the FIRST empty line and MTAs commonly honour
// every To/Cc/Bcc line, so the inspector's view was the non-standard one in
// both cases.
//
// Status: FIXED (F-3) — `parseHeaders` now normalises CRLF to LF, ends the
// header block at the first empty line and keeps every occurrence; a repeated
// To/Cc/Bcc is denied as `duplicate-recipient-header`. A lone CR, or CRLF
// mixed with bare LF, in the header block is denied as
// `ambiguous-line-ending`, since readers disagree on where such a header
// block ends (case (c) below). An address-list element carrying a quoted
// string or a comment is refused rather than having a look-alike angle-addr
// extracted from it, and so is one whose display-name is not an RFC 5322
// phrase (it holds `@`, `:`, `;` and so on), which a mainstream parser reads
// as a message to the address in the name (see the display-name control).
// The attack payloads below
// are kept as regression inputs.
import { describe, it, expect } from "vitest";
import { inspectOutboundMessage } from "../../inspectors/outbound";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example" };

function b64url(s: string): string {
  return Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("C4 outbound inspector header parsing", () => {
  it("baseline: a single off-allowlist To is denied", () => {
    const raw = b64url("To: outsider@evil.example\r\nSubject: hi\r\n\r\nbody\r\n");
    const r = inspectOutboundMessage({ body: { raw } }, ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
  });

  it("FIXED (F-3): (a) duplicate To headers are denied, not judged on the last one", () => {
    const raw = b64url(
      "To: outsider@evil.example\r\n" +
        "To: staff@allowed.example\r\n" +
        "Subject: hi\r\n\r\nbody\r\n",
    );
    const r = inspectOutboundMessage({ body: { raw } }, ENV);
    // Previously `allow` (only the second, allowlisted To was seen).
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("duplicate-recipient-header");
  });

  it("FIXED (F-3): (a') duplicate Cc with the off-list address first is denied the same way", () => {
    const raw = b64url(
      "To: staff@allowed.example\r\n" +
        "Cc: outsider@evil.example\r\n" +
        "Cc: other@allowed.example\r\n" +
        "Subject: hi\r\n\r\nbody\r\n",
    );
    const r = inspectOutboundMessage({ body: { raw } }, ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("duplicate-recipient-header");
  });

  it("FIXED (F-3): (b) LF header block + CRLFCRLF in the body: the body is ignored, the real To is judged", () => {
    const msg =
      "To: outsider@evil.example\n" + // the real header block (bare LF)
      "Subject: hi\n" +
      "\n" + // real end of headers (first empty line)
      "This is the body.\n" +
      "To: staff@allowed.example\n" + // body text, but parsed as a header
      "\r\n\r\n" + // the CRLFCRLF the inspector searches for first
      "rest of body\n";
    const r = inspectOutboundMessage({ body: { raw: b64url(msg) } }, ENV);
    // Previously `allow` (the body's To = staff@allowed.example overrode the
    // real one). The header block now ends at the first empty line.
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
  });

  it("FIXED (F-3): (c) a lone-CR blank line before an off-list To is denied as ambiguous", () => {
    // A reader that splits on a lone CR sees the second To as body; one that
    // does not (MimeKit, many MTAs) sees a To line carrying the outsider.
    for (const msg of [
      "To: staff@allowed.example\r\rTo: outsider@evil.example\r\n\r\nbody",
      "To: staff@allowed.example\r\n\nTo: outsider@evil.example\r\n\r\nbody",
    ]) {
      const r = inspectOutboundMessage({ body: { raw: b64url(msg) } }, ENV);
      expect(r.decision, JSON.stringify(msg)).toBe("deny");
      expect(r.reason, JSON.stringify(msg)).toBe("ambiguous-line-ending");
    }
  });

  it("(b') the same message with consistent CRLF endings is correctly denied", () => {
    const msg =
      "To: outsider@evil.example\r\n" +
      "Subject: hi\r\n" +
      "\r\n" +
      "This is the body.\r\n" +
      "To: staff@allowed.example\r\n" +
      "\r\n\r\n" +
      "rest of body\r\n";
    const r = inspectOutboundMessage({ body: { raw: b64url(msg) } }, ENV);
    expect(r.decision).toBe("deny");
  });

  it("control: group syntax, display-name tricks and comma-in-name all fail closed", () => {
    for (const to of [
      "undisclosed: outsider@evil.example;",
      '"staff@allowed.example" <outsider@evil.example>',
      "staff@allowed.example <outsider@evil.example>",
      '"Smith, John" <staff@allowed.example>', // legit but denied (false positive)
      // A look-alike angle-addr inside a quoted display-name or a comment is
      // not the recipient: MTAs deliver both of these to the outsider. The
      // angle-addr used to be extracted from the first `<`…`>` regardless of
      // quoting, so both were allowed (F-3, F-18).
      '"<staff@allowed.example>" <outsider@evil.example>',
      "outsider@evil.example (<staff@allowed.example>)",
      "(<staff@allowed.example>) outsider@evil.example",
      '"a<staff@allowed.example>" outsider@evil.example',
      // A display-name that is not an RFC 5322 phrase: CPython's email
      // parser reads each of these as a message to the outsider, while the
      // angle-addr used to be extracted and judged (F-3).
      "outsider@evil.example <staff@allowed.example>",
      "g:outsider@evil.example; <staff@allowed.example>",
      "outsider@evil.example: <staff@allowed.example>",
      "outsider@evil.example; <staff@allowed.example>",
    ]) {
      const raw = b64url(`To: ${to}\r\nSubject: hi\r\n\r\nbody\r\n`);
      const r = inspectOutboundMessage({ body: { raw } }, ENV);
      expect(r.decision, to).toBe("deny");
      expect(r.reason, to).toBe("external-send");
    }
  });

  it("control: Resent-To / Reply-To are not recipients and are ignored (documented, not a bypass)", () => {
    const raw = b64url(
      "To: staff@allowed.example\r\nResent-To: outsider@evil.example\r\nReply-To: outsider@evil.example\r\n\r\nbody\r\n",
    );
    // Gmail's API ignores Resent-* for routing on messages.send, so this is
    // consistent with upstream; recorded for coverage only.
    expect(inspectOutboundMessage({ body: { raw } }, ENV).decision).toBe("allow");
  });
});
