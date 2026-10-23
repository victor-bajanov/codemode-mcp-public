// Issue #59 (Task C4): the Gmail upload hint moves from the getFile + base64url
// `{ raw }` recipe to the media-upload endpoint with a host-assembled
// `composed` body, so attachment bytes never enter the sandbox.

import { describe, it, expect } from "vitest";
import { gmailProvider } from "../index";

const hint = gmailProvider.attachmentHint ?? "";

describe("GMAIL_ATTACHMENT_HINT (composed + media upload)", () => {
  it("sends through the media-upload endpoint with uploadType=media and message/rfc822", () => {
    expect(hint).toContain("/upload/gmail/v1/users/me/messages/send");
    expect(hint).toMatch(/uploadType:\s*"media"/);
    expect(hint).toContain('contentType: "message/rfc822"');
  });

  it("splices the staged file in with a composed base64-lines segment", () => {
    expect(hint).toContain("composed: { segments: [");
    expect(hint).toContain('{ staged: { file_handle, token }, encoding: "base64-lines" }');
  });

  it("names the drafts media endpoints too", () => {
    expect(hint).toContain("/upload/gmail/v1/users/me/drafts");
  });

  it("keeps the literal CRLF .join() and the RFC 2047 header guidance", () => {
    expect(hint).toContain('.join("\\r\\n")');
    expect(hint).toMatch(/RFC 2047/);
    expect(hint).toContain("=?UTF-8?B?");
  });

  it("states the 35 MiB message and ≈25 MiB attachment ceilings", () => {
    expect(hint).toMatch(/35 MiB/);
    expect(hint).toMatch(/25 MiB/);
  });

  it("says getFile is for reading small files in code, not for sending", () => {
    expect(hint).toMatch(/getFile[^.]*small files[^.]*not for sending/i);
  });

  it("no longer teaches the getFile + base64url { raw } attachment recipe or denies /upload/ exists", () => {
    expect(hint).not.toContain("f.bytesBase64");
    expect(hint).not.toMatch(/no `?\/upload\/[^`]*`? path is registered/);
    expect(hint).not.toMatch(/has NO raw-octet/);
  });

  it("says headers must come before the first staged segment, not that they must sit in the first text segment", () => {
    expect(hint).toMatch(/before the first staged segment/);
    expect(hint).not.toMatch(/in the first text segment/);
  });
});
