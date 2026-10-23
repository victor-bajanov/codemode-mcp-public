// Issue #59, Task C2: the media-upload send inspector and the three
// `/upload/` surface-review entries. A composed send reaches the inspector as
// the inspection view (D6): `rawBody` is the text segments verbatim with each
// staged segment replaced by U+FFFC, plus `staged[]` metadata and the exact
// `assembledByteLength`. The staged bytes are base64 (no CR/LF of their own
// beyond the encoder's line breaks, no `:`), so they cannot form headers — as
// long as the header block has ended before the first staged slot.

import { describe, it, expect } from "vitest";
import type { InspectRequest } from "@local/shared";
import { inspectOutboundMessageMedia, MASS_SEND_THRESHOLD } from "../outbound";
import { repairRfc822Text } from "../normalize-subject";
import { surfaceReview } from "../../surface-review";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com" };
const SLOT = "\uFFFC";
const GMAIL_MEDIA_MAX = 36_700_160;

function head(to: string, subject = "Quarterly report", extra: string[] = []): string {
  return [
    "From: me",
    `To: ${to}`,
    `Subject: ${subject}`,
    ...extra,
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b1"',
    "",
    "--b1",
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    "hello",
    "",
    "--b1",
    'Content-Type: application/pdf; name="q.pdf"',
    'Content-Disposition: attachment; filename="q.pdf"',
    "Content-Transfer-Encoding: base64",
    "",
    "",
  ].join("\r\n");
}

function composedReq(text: string, over: Partial<InspectRequest> = {}): InspectRequest {
  const rawBody = text + SLOT + "--b1--\r\n";
  return {
    rawBody,
    contentType: "message/rfc822",
    query: { uploadType: "media" },
    staged: [{ index: 1, byteLength: 1000, contentType: "application/pdf", filename: "q.pdf", encoding: "base64-lines" }],
    assembledByteLength: 2000,
    ...over,
  };
}

describe("inspectOutboundMessageMedia — recipients", () => {
  it("denies an off-allowlist recipient as external-send", () => {
    const r = inspectOutboundMessageMedia(composedReq(head("eve@evil.com")), ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "external-send" });
  });

  it("allows an allowlisted recipient", () => {
    expect(inspectOutboundMessageMedia(composedReq(head("bob@example.com")), ENV).decision).toBe("allow");
  });

  it("denies everything when the allowlist is unset (fail closed)", () => {
    expect(inspectOutboundMessageMedia(composedReq(head("bob@example.com"))).decision).toBe("deny");
  });

  it("still applies the header-parsing denies (duplicate To)", () => {
    const r = inspectOutboundMessageMedia(
      composedReq(head("bob@example.com", "x", ["To: eve@evil.com"])),
      ENV,
    );
    expect(r).toMatchObject({ decision: "deny", reason: "duplicate-recipient-header" });
  });

  it("allows a plain (non-composed) media send with no staged slot", () => {
    const req: InspectRequest = {
      rawBody: "To: bob@example.com\r\nSubject: hi\r\n\r\nbody",
      contentType: "message/rfc822",
      query: { uploadType: "media" },
    };
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("allow");
  });
});

describe("inspectOutboundMessageMedia — staged slot placement (sentinel rule)", () => {
  it("denies a staged slot before the header block has ended", () => {
    const text = "From: me\r\nTo: bob@example.com\r\n";
    const r = inspectOutboundMessageMedia(composedReq(text), ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "attachment-before-header-end" });
  });

  it("denies a staged slot inside a header line", () => {
    const req = composedReq("", {
      rawBody: `To: bob@example.com\r\nSubject: ${SLOT}\r\n\r\nbody`,
    });
    expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({
      decision: "deny",
      reason: "attachment-before-header-end",
    });
  });

  it("denies a sole staged segment (a pre-built message the inspector cannot read)", () => {
    const req = composedReq("", {
      rawBody: SLOT,
      staged: [{ index: 0, byteLength: 500, contentType: "message/rfc822", filename: null, encoding: "identity" }],
    });
    expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({
      decision: "deny",
      reason: "attachment-before-header-end",
    });
  });

  it("denies a staged slot standing in for the header terminator itself", () => {
    const req = composedReq("", { rawBody: `To: bob@example.com\r\n${SLOT}\r\nbody` });
    expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({
      decision: "deny",
      reason: "attachment-before-header-end",
    });
  });

  it("allows a slot that follows the blank line ending the headers", () => {
    const req = composedReq("", { rawBody: `To: bob@example.com\r\n\r\n${SLOT}` });
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("allow");
  });
});

describe("inspectOutboundMessageMedia — request shape", () => {
  it("denies an assembled body over Gmail's 35 MiB media limit", () => {
    const r = inspectOutboundMessageMedia(
      composedReq(head("bob@example.com"), { assembledByteLength: GMAIL_MEDIA_MAX + 1 }),
      ENV,
    );
    expect(r).toMatchObject({ decision: "deny", reason: "message-too-large" });
    expect(r.message).toContain("36700160");
  });

  it("allows an assembled body exactly at the limit", () => {
    const r = inspectOutboundMessageMedia(
      composedReq(head("bob@example.com"), { assembledByteLength: GMAIL_MEDIA_MAX }),
      ENV,
    );
    expect(r.decision).toBe("allow");
  });

  it("measures a plain rawBody's byte length when no assembled length is given", () => {
    const big = "To: bob@example.com\r\n\r\n" + "x".repeat(GMAIL_MEDIA_MAX);
    const r = inspectOutboundMessageMedia(
      { rawBody: big, contentType: "message/rfc822", query: { uploadType: "media" } },
      ENV,
    );
    expect(r).toMatchObject({ decision: "deny", reason: "message-too-large" });
  });

  it.each([undefined, "multipart", "resumable", "MEDIA"])("denies uploadType=%s", (uploadType) => {
    const query = uploadType === undefined ? {} : { uploadType };
    const r = inspectOutboundMessageMedia(composedReq(head("bob@example.com"), { query }), ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "upload-type-not-media" });
  });

  it.each([undefined, "application/octet-stream", "multipart/form-data", "message/rfc822x", "text/plain"])(
    "denies contentType %s",
    (contentType) => {
      const over: Partial<InspectRequest> = {};
      const req = composedReq(head("bob@example.com"), over);
      if (contentType === undefined) delete req.contentType;
      else req.contentType = contentType;
      expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({ decision: "deny", reason: "media-content-type" });
    },
  );

  it("accepts message/rfc822 with parameters and in any case", () => {
    const req = composedReq(head("bob@example.com"), { contentType: "Message/RFC822; charset=utf-8" });
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("allow");
  });

  it("denies a JSON body on the media endpoint (no readable message)", () => {
    const req: InspectRequest = {
      body: { raw: "x" },
      contentType: "message/rfc822",
      query: { uploadType: "media" },
    };
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("deny");
  });

  it("denies a multipart body on the media endpoint", () => {
    const req: InspectRequest = {
      multipart: [{ name: "media", contentType: "message/rfc822", value: "To: bob@example.com\r\n\r\nx" }],
      contentType: "message/rfc822",
      query: { uploadType: "media" },
    };
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("deny");
  });
});

describe("inspectOutboundMessageMedia — query and content-type allowlists (review fix 1)", () => {
  const ok = () => composedReq(head("bob@example.com"));

  it.each([undefined, "raw"])("allows upload_protocol=%s", (p) => {
    const req = ok();
    if (p !== undefined) req.query = { uploadType: "media", upload_protocol: p };
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("allow");
  });

  it.each(["multipart", "resumable", "RAW", ""])("denies upload_protocol=%s", (p) => {
    const req = ok();
    req.query = { uploadType: "media", upload_protocol: p };
    expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({ decision: "deny", reason: "upload-type-not-media" });
  });

  it.each(["fields", "prettyPrint", "quotaUser"])("allows the harmless standard parameter %s", (k) => {
    const req = ok();
    req.query = { uploadType: "media", [k]: "x" };
    expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("allow");
  });

  it.each(["alt", "callback", "key", "access_token", "oauth_token", "$.xgafv", "uploadtype", "to"])(
    "denies any other query parameter (%s)",
    (k) => {
      const req = ok();
      req.query = { uploadType: "media", [k]: "x" };
      expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({ decision: "deny", reason: "media-query-param" });
    },
  );

  it.each(["message/rfc822; boundary=zz", "message/rfc822; charset=utf-8; boundary=zz", "message/rfc822; name=x", "message/rfc822; charset"])(
    "denies content-type parameters other than charset (%s)",
    (contentType) => {
      const req = ok();
      req.contentType = contentType;
      expect(inspectOutboundMessageMedia(req, ENV)).toMatchObject({ decision: "deny", reason: "media-content-type" });
    },
  );

  it.each(["message/rfc822", "message/rfc822; charset=UTF-8", 'message/rfc822;charset="utf-8"'])(
    "allows %s",
    (contentType) => {
      const req = ok();
      req.contentType = contentType;
      expect(inspectOutboundMessageMedia(req, ENV).decision).toBe("allow");
    },
  );
});

describe("inspectOutboundMessageMedia — header terminator edge cases (review fix 3)", () => {
  const view = (rawBody: string) => composedReq("", { rawBody });

  it("allows a slot after a bare-LF header block", () => {
    expect(inspectOutboundMessageMedia(view(`To: bob@example.com\nSubject: hi\n\n${SLOT}`), ENV).decision).toBe(
      "allow",
    );
  });

  it("denies a slot inside a folded continuation line", () => {
    expect(
      inspectOutboundMessageMedia(view(`To: bob@example.com\r\nSubject: hi\r\n ${SLOT}\r\n\r\nbody`), ENV),
    ).toMatchObject({ decision: "deny", reason: "attachment-before-header-end" });
  });

  it("denies a mixed LF / CRLF terminator before a slot as ambiguous", () => {
    expect(inspectOutboundMessageMedia(view(`To: bob@example.com\n\r\n${SLOT}`), ENV)).toMatchObject({
      decision: "deny",
      reason: "ambiguous-line-ending",
    });
  });
});

describe("inspectOutboundMessageMedia — mass-send summary", () => {
  const many = Array.from({ length: MASS_SEND_THRESHOLD + 1 }, (_, i) => `u${i}@example.com`).join(", ");

  it("still elicits past the mass-send threshold", () => {
    const r = inspectOutboundMessageMedia(composedReq(head(many)), ENV);
    expect(r).toMatchObject({ decision: "elicit", reason: "mass-send" });
    expect(r.summary?.["count"]).toBe(MASS_SEND_THRESHOLD + 1);
  });

  it("lists the attachments with sizes in the summary", () => {
    const r = inspectOutboundMessageMedia(
      composedReq(head(many), {
        staged: [
          { index: 1, byteLength: 1234, contentType: "application/pdf", filename: "q.pdf", encoding: "base64-lines" },
          { index: 3, byteLength: 99, contentType: "text/csv", filename: null, encoding: "base64-lines" },
        ],
      }),
      ENV,
    );
    const attachments = String(r.summary?.["attachments"]);
    expect(attachments).toContain("q.pdf");
    expect(attachments).toContain("1234 bytes");
    expect(attachments).toContain("99 bytes");
  });

  it("strips bidi overrides and other format characters from summary filenames", () => {
    const r = inspectOutboundMessageMedia(
      composedReq(head(many), {
        staged: [
          {
            index: 1,
            byteLength: 10,
            contentType: "application/pdf",
            filename: "invoice\u202Efdp.exe\u200B\r\nx",
            encoding: "base64-lines",
          },
        ],
      }),
      ENV,
    );
    const attachments = String(r.summary?.["attachments"]);
    expect(attachments).not.toMatch(/[\u202E\u200B\r\n]/);
    expect(attachments).toContain("invoicefdp.exe");
  });

  it("strips C1 controls and line/paragraph separators, and truncates by code point (review fix 2)", () => {
    const astral = "\u{1F600}";
    const r = inspectOutboundMessageMedia(
      composedReq(head(many), {
        staged: [
          {
            index: 1,
            byteLength: 10,
            contentType: "application/pdf",
            filename: "a\u0085b\u2028c\u2029d\u009Be" + "x".repeat(94) + astral + "tail",
            encoding: "base64-lines",
          },
          ...Array.from({ length: 40 }, (_, i) => ({
            index: i + 2,
            byteLength: 1,
            contentType: "text/plain",
            filename: astral.repeat(20),
            encoding: "base64-lines" as const,
          })),
        ],
      }),
      ENV,
    );
    const attachments = String(r.summary?.["attachments"]);
    expect(attachments).not.toMatch(/[\u0080-\u009F\u2028\u2029]/);
    // No lone surrogate anywhere: every high surrogate is followed by a low one.
    expect(attachments).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
    expect(attachments).not.toContain("tail");
  });

  it("omits the attachments field when nothing is staged", () => {
    const r = inspectOutboundMessageMedia(
      { rawBody: `To: ${many}\r\n\r\nx`, contentType: "message/rfc822", query: { uploadType: "media" } },
      ENV,
    );
    expect(r.decision).toBe("elicit");
    expect(r.summary).not.toHaveProperty("attachments");
  });
});

describe("surface review entries for the media operations", () => {
  const send = surfaceReview["gmail.users.messages.send.media"];
  const create = surfaceReview["gmail.users.drafts.create.media"];
  const update = surfaceReview["gmail.users.drafts.update.media"];

  it("send.media is allowed, inspected by inspectOutboundMessageMedia, accepts staged bodies", () => {
    expect(send).toMatchObject({ decision: "allow", acceptsStaged: true });
    expect(send?.inspect).toBe(inspectOutboundMessageMedia);
    expect(send?.clientNote?.trim()).toBeTruthy();
    expect(send?.normalizeComposedText).toBe(repairRfc822Text);
  });

  it.each([
    ["gmail.users.drafts.create.media", create],
    ["gmail.users.drafts.update.media", update],
  ])("%s is a plain allow with the composed-text normaliser", (_id, entry) => {
    expect(entry).toMatchObject({ decision: "allow", category: "standard_write", acceptsStaged: true });
    expect(entry?.inspect).toBeUndefined();
    expect(entry?.normalizeComposedText).toBe(repairRfc822Text);
  });

  it("the drafts media entries record that a sole identity segment makes an uninspected draft (R-8)", () => {
    for (const entry of [create, update]) {
      expect(entry?.reasoning).toMatch(/identity/);
      expect(entry?.reasoning).toMatch(/send time/);
    }
  });

  it("the JSON messages.send entry does not accept staged bodies (composed is refused by rule)", () => {
    expect(surfaceReview["gmail.users.messages.send"]?.acceptsStaged).toBeUndefined();
    expect(surfaceReview["gmail.users.drafts.send"]?.acceptsStaged).toBeUndefined();
    expect(surfaceReview["gmail.users.drafts.create"]?.acceptsStaged).toBeUndefined();
  });

  it("the media send normaliser repairs a mojibake subject without touching recipients", () => {
    const text = head("bob@example.com", Buffer.from("a — b", "utf8").toString("latin1"));
    const fixed = send!.normalizeComposedText!(text)!;
    expect(fixed).toContain("To: bob@example.com\r\n");
    expect(fixed).toMatch(/Subject: =\?UTF-8\?B\?/);
  });
});
