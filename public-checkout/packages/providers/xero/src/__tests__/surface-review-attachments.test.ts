import { describe, it, expect } from "vitest";
import {
  inspectAttachmentUpload,
  ATTACHMENT_MIME_ALLOWLIST,
  ATTACHMENT_MAX_SIZE,
} from "../inspectors/attachments";

describe("inspectAttachmentUpload", () => {
  it("exposes a populated MIME allowlist and a size limit (sanity)", () => {
    expect(ATTACHMENT_MIME_ALLOWLIST.has("application/pdf")).toBe(true);
    expect(ATTACHMENT_MAX_SIZE).toBe(25 * 1024 * 1024);
  });

  it("allows a small PDF", () => {
    const body = new ArrayBuffer(1024);
    expect(inspectAttachmentUpload({ contentType: "application/pdf", rawBody: body })).toEqual({
      decision: "allow",
    });
  });

  it("allows when content-type carries a charset suffix", () => {
    expect(inspectAttachmentUpload({
      contentType: "text/csv; charset=utf-8",
      rawBody: new ArrayBuffer(100),
    })).toEqual({ decision: "allow" });
  });

  it("allows xlsx", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      rawBody: new ArrayBuffer(50_000),
    })).toEqual({ decision: "allow" });
  });

  it("denies application/x-msdownload (.exe-class) as malformed/bad MIME", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/x-msdownload",
      rawBody: new ArrayBuffer(1024),
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "attachment-bad-mime" });
  });

  it("denies a PDF over 25MB", () => {
    const big = new ArrayBuffer(ATTACHMENT_MAX_SIZE + 1);
    expect(inspectAttachmentUpload({ contentType: "application/pdf", rawBody: big })).toMatchObject({
      decision: "deny", category: "malformed", reason: "attachment-too-large",
    });
  });

  it("allows a PDF exactly at 25MB", () => {
    const atLimit = new ArrayBuffer(ATTACHMENT_MAX_SIZE);
    expect(inspectAttachmentUpload({ contentType: "application/pdf", rawBody: atLimit })).toEqual({
      decision: "allow",
    });
  });

  it("denies when content-type is missing", () => {
    expect(inspectAttachmentUpload({ rawBody: new ArrayBuffer(1) })).toMatchObject({
      decision: "deny", category: "malformed", reason: "attachment-bad-mime",
    });
  });

  it("computes size from string body length when rawBody is a string", () => {
    expect(inspectAttachmentUpload({
      contentType: "text/csv",
      rawBody: "hello,world",
    })).toEqual({ decision: "allow" });
  });

  it("treats the MIME match case-insensitively", () => {
    expect(inspectAttachmentUpload({
      contentType: "APPLICATION/PDF",
      rawBody: new ArrayBuffer(100),
    })).toEqual({ decision: "allow" });
  });
});
