import { describe, it, expect } from "vitest";
import { inspectOutboundMessage } from "../inspectors/outbound";

// Mirrors the prod (gmail/gmail-dev) wrangler var.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
};

function rfc822(to: string, subject = "hi"): string {
  return `To: ${to}\r\nSubject: ${subject}\r\n\r\nbody`;
}
function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

describe("rawBody (media upload) channel", () => {
  it("allows an allowlisted recipient in decoded rfc822", () => {
    const req = {
      rawBody: new TextEncoder().encode(rfc822("adam@gmail.com")),
      contentType: "message/rfc822",
    };
    expect(inspectOutboundMessage(req, ENV).decision).toBe("allow");
  });

  it("denies an off-allowlist recipient in decoded rfc822", () => {
    const req = {
      rawBody: new TextEncoder().encode(rfc822("eve@evil.com")),
      contentType: "message/rfc822",
    };
    const r = inspectOutboundMessage(req, ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
  });

  it("denies when no recipient can be parsed (fail closed)", () => {
    const req = { rawBody: new TextEncoder().encode("not an email"), contentType: "application/octet-stream" };
    expect(inspectOutboundMessage(req, ENV).decision).toBe("deny");
  });
});

describe("multipart (uploadType=multipart) channel", () => {
  it("reads the message/rfc822 part and denies off-allowlist", () => {
    const req = {
      multipart: [
        { name: "metadata", contentType: "application/json", value: "{}" },
        { name: "media", contentType: "message/rfc822", bodyBase64: b64(rfc822("eve@evil.com")) },
      ],
      contentType: "multipart/form-data",
    };
    const r = inspectOutboundMessage(req, ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
  });

  it("allows an allowlisted recipient in the message part (value form)", () => {
    const req = {
      multipart: [{ name: "media", contentType: "message/rfc822", value: rfc822("bob@example.com") }],
      contentType: "multipart/form-data",
    };
    expect(inspectOutboundMessage(req, ENV).decision).toBe("allow");
  });

  it("denies when no message part is present (fail closed)", () => {
    const req = {
      multipart: [{ name: "metadata", contentType: "application/json", value: "{}" }],
      contentType: "multipart/form-data",
    };
    expect(inspectOutboundMessage(req, ENV).decision).toBe("deny");
  });
});

describe("adversarial fail-closed edge cases", () => {
  it("denies when the real headers/terminator fall past the 64 KiB scan window (junk padding hides Cc)", () => {
    // Visible To: is allowlisted; the malicious Cc sits behind >64 KiB of
    // padding so the blank-line terminator never appears within the scanned
    // prefix. Must deny rather than silently ignore the unseen Cc.
    const padded =
      `To: adam@gmail.com\r\n` +
      `X-Pad: ${"A".repeat(70_000)}\r\n` +
      `Cc: eve@evil.com\r\n\r\nbody`;
    const req = {
      rawBody: new TextEncoder().encode(padded),
      contentType: "message/rfc822",
    };
    expect(inspectOutboundMessage(req, ENV).decision).toBe("deny");
  });

  it("denies rather than throwing when multipart bodyBase64 is not valid base64", () => {
    const req = {
      multipart: [{ name: "media", contentType: "message/rfc822", bodyBase64: "!!!!not-base64!!!!" }],
      contentType: "multipart/form-data",
    };
    expect(() => inspectOutboundMessage(req, ENV)).not.toThrow();
    expect(inspectOutboundMessage(req, ENV).decision).toBe("deny");
  });

  it("denies external-send when a folded To: header hides an off-allowlist continuation recipient", () => {
    const folded = `To: adam@gmail.com,\r\n eve@evil.com\r\n\r\nbody`;
    const req = {
      rawBody: new TextEncoder().encode(folded),
      contentType: "message/rfc822",
    };
    const r = inspectOutboundMessage(req, ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
  });

  it("denies when two ambiguous non-JSON multipart parts are present (no message/rfc822-typed part)", () => {
    const req = {
      multipart: [
        { name: "part1", contentType: "text/plain", value: rfc822("adam@gmail.com") },
        { name: "part2", contentType: "text/plain", value: rfc822("eve@evil.com") },
      ],
      contentType: "multipart/form-data",
    };
    expect(inspectOutboundMessage(req, ENV).decision).toBe("deny");
  });
});

describe("json body channel is unchanged", () => {
  it("still allows allowlisted body.raw", () => {
    const raw = Buffer.from(rfc822("adam@gmail.com"), "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(inspectOutboundMessage({ body: { raw } }, ENV).decision).toBe("allow");
  });
});
