import { describe, it, expect } from "vitest";
import type { InspectRequest } from "@local/shared";
import { inspectOutboundMessage, inspectOutboundMessageMedia } from "../inspectors/outbound";

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
/** A messages.send.media upload of `text`. */
function media(text: string, contentType = "message/rfc822"): InspectRequest {
  return { rawBody: new TextEncoder().encode(text), contentType, query: { uploadType: "media" } };
}

describe("rawBody (media upload) channel — messages.send.media", () => {
  it("allows an allowlisted recipient in decoded rfc822", () => {
    expect(inspectOutboundMessageMedia(media(rfc822("adam@gmail.com")), ENV).decision).toBe("allow");
  });

  it("denies an off-allowlist recipient in decoded rfc822", () => {
    const r = inspectOutboundMessageMedia(media(rfc822("eve@evil.com")), ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
  });

  it("denies when no recipient can be parsed (fail closed)", () => {
    expect(inspectOutboundMessageMedia(media("not an email"), ENV).decision).toBe("deny");
  });

  it("the JSON messages.send endpoint refuses a rawBody, even an allowlisted one (send-no-raw)", () => {
    for (const req of [
      media(rfc822("adam@gmail.com")),
      { rawBody: new TextEncoder().encode(rfc822("eve@evil.com")), contentType: "message/rfc822" },
      { rawBody: new TextEncoder().encode("not an email"), contentType: "application/octet-stream" },
    ]) {
      expect(inspectOutboundMessage(req, ENV)).toMatchObject({ decision: "deny", reason: "send-no-raw" });
    }
  });
});

describe("multipart (uploadType=multipart) channel — refused on the JSON messages.send endpoint", () => {
  it.each<[string, NonNullable<InspectRequest["multipart"]>]>([
    ["a message/rfc822 part off the allowlist", [
      { name: "metadata", contentType: "application/json", value: "{}" },
      { name: "media", contentType: "message/rfc822", bodyBase64: b64(rfc822("eve@evil.com")) },
    ]],
    ["an allowlisted message part (value form)", [
      { name: "media", contentType: "message/rfc822", value: rfc822("bob@example.com") },
    ]],
    ["no message part", [{ name: "metadata", contentType: "application/json", value: "{}" }]],
    ["a part whose bodyBase64 is not valid base64", [
      { name: "media", contentType: "message/rfc822", bodyBase64: "!!!!not-base64!!!!" },
    ]],
    ["two ambiguous non-JSON parts", [
      { name: "part1", contentType: "text/plain", value: rfc822("adam@gmail.com") },
      { name: "part2", contentType: "text/plain", value: rfc822("eve@evil.com") },
    ]],
  ])("denies %s as send-no-raw", (_label, multipart) => {
    const req: InspectRequest = { multipart, contentType: "multipart/form-data" };
    expect(() => inspectOutboundMessage(req, ENV)).not.toThrow();
    expect(inspectOutboundMessage(req, ENV)).toMatchObject({ decision: "deny", reason: "send-no-raw" });
  });
});

describe("adversarial fail-closed edge cases — messages.send.media", () => {
  it("denies when the real headers/terminator fall past the 64 KiB scan window (junk padding hides Cc)", () => {
    // Visible To: is allowlisted; the malicious Cc sits behind >64 KiB of
    // padding so the blank-line terminator never appears within the scanned
    // prefix. Must deny rather than silently ignore the unseen Cc.
    const padded =
      `To: adam@gmail.com\r\n` +
      `X-Pad: ${"A".repeat(70_000)}\r\n` +
      `Cc: eve@evil.com\r\n\r\nbody`;
    expect(inspectOutboundMessageMedia(media(padded), ENV).decision).toBe("deny");
  });

  it("denies external-send when a folded To: header hides an off-allowlist continuation recipient", () => {
    const folded = `To: adam@gmail.com,\r\n eve@evil.com\r\n\r\nbody`;
    const r = inspectOutboundMessageMedia(media(folded), ENV);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("external-send");
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
