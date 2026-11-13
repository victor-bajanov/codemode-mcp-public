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

  it("allows a short string rawBody", () => {
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

  // F2-5 size source: a string rawBody is measured in UTF-8 bytes, not UTF-16
  // code units (`.length` under-counted multibyte text).
  it("FIXED (F2-5): counts a string rawBody in UTF-8 bytes, not string length", () => {
    // 3-byte chars: string length is a third of the byte length.
    const chars = Math.floor(ATTACHMENT_MAX_SIZE / 3) + 1;
    const rawBody = "\u20ac".repeat(chars);
    expect(rawBody.length).toBeLessThanOrEqual(ATTACHMENT_MAX_SIZE);
    expect(inspectAttachmentUpload({ contentType: "text/csv", rawBody })).toMatchObject({
      decision: "deny", category: "malformed", reason: "attachment-too-large",
    });
  });

  it("FIXED (F2-5): 10 multibyte chars are measured as their UTF-8 byte count", () => {
    // 10 x 3 bytes = 30 bytes: allowed, and the at-limit edge uses bytes too.
    const tenChars = "\u20ac".repeat(10);
    expect(new TextEncoder().encode(tenChars).byteLength).toBe(30);
    expect(inspectAttachmentUpload({ contentType: "text/csv", rawBody: tenChars })).toEqual({ decision: "allow" });
    const pad = "a".repeat(ATTACHMENT_MAX_SIZE - 30);
    expect(inspectAttachmentUpload({ contentType: "text/csv", rawBody: pad + tenChars })).toEqual({ decision: "allow" });
    expect(inspectAttachmentUpload({ contentType: "text/csv", rawBody: pad + "a" + tenChars })).toMatchObject({
      decision: "deny", reason: "attachment-too-large",
    });
  });

  it("FIXED (F2-5): uses assembledByteLength (composed body) over a short rawBody", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/pdf",
      rawBody: "\ufffc",
      staged: [{ index: 0, byteLength: ATTACHMENT_MAX_SIZE + 1, contentType: "application/pdf", filename: "a.pdf", encoding: "identity" }],
      assembledByteLength: ATTACHMENT_MAX_SIZE + 1,
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "attachment-too-large" });
  });

  it("allows a composed staged upload within the cap", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/pdf",
      rawBody: "\ufffc",
      staged: [{ index: 0, byteLength: 4096, contentType: "application/pdf", filename: "invoice.pdf", encoding: "identity" }],
      assembledByteLength: 4096,
    })).toEqual({ decision: "allow" });
  });

  it("FIXED (F2-5): a JSON body is not the file's bytes → attachment-not-bytes", () => {
    const r = inspectAttachmentUpload({ contentType: "application/json", body: { file: "x" } });
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "attachment-not-bytes" });
    expect(r.message).toMatch(/bodyBase64 or a composed staged reference/);
  });

  it("FIXED (F2-5): a multipart body → attachment-not-bytes, even with an accepted MIME", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/pdf",
      multipart: [],
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "attachment-not-bytes" });
  });
});

/**
 * F2-5 (Medium). Attacker: content steering the agent (prompt injection in an
 * email or document it reads). Precondition: the agent can upload attachments
 * to invoices. Payload: `PUT /Invoices/<id>/Attachments/Updated-bank-details.pdf
 * ?IncludeOnline=true` with a PDF announcing new bank details. Control: the
 * inspector denies `IncludeOnline` unless it is explicitly false, because it
 * publishes the file on the customer's online invoice. Pre-fix, the inspector
 * never read the query (and was wired nowhere), so the file reached the customer.
 */
describe("inspectAttachmentUpload: IncludeOnline (F2-5)", () => {
  const pdf = { contentType: "application/pdf", rawBody: new TextEncoder().encode("%PDF-1.4 Our bank details have changed") };

  it.each([
    ["boolean true", { IncludeOnline: true }],
    ["string true", { IncludeOnline: "true" }],
    ["string True", { IncludeOnline: "True" }],
    ["number 1", { IncludeOnline: 1 }],
    ["number 0", { IncludeOnline: 0 }],
    ["empty string", { IncludeOnline: "" }],
    ["present but undefined", { IncludeOnline: undefined }],
    ["lower-case key", { includeonline: "true" }],
    ["two spellings, one true", { IncludeOnline: false, INCLUDEONLINE: "true" }],
  ] as const)("FIXED (F2-5): IncludeOnline %s → denied attachment-include-online", (_label, query) => {
    const r = inspectAttachmentUpload({ ...pdf, query: { ...query } });
    expect(r).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "attachment-include-online" });
    expect(r.message).toBe(
      "IncludeOnline publishes the attachment on the customer's online invoice; it is denied. Upload without IncludeOnline.",
    );
  });

  it.each([
    ["boolean false", { IncludeOnline: false }],
    ["string false", { IncludeOnline: "false" }],
    ["string FALSE", { IncludeOnline: "FALSE" }],
    ["no query key", {}],
  ] as const)("REFUTED: IncludeOnline %s → allowed (file stays internal)", (_label, query) => {
    expect(inspectAttachmentUpload({ ...pdf, query: { ...query } })).toEqual({ decision: "allow" });
  });

  it("checks IncludeOnline before the MIME type", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/x-msdownload",
      rawBody: new ArrayBuffer(1),
      query: { IncludeOnline: "true" },
    })).toMatchObject({ reason: "attachment-include-online" });
  });

  it("checks the body shape before IncludeOnline", () => {
    expect(inspectAttachmentUpload({
      contentType: "application/json",
      body: {},
      query: { IncludeOnline: "true" },
    })).toMatchObject({ reason: "attachment-not-bytes" });
  });
});
