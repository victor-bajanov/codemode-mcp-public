// Issue #41 (review follow-up): XERO_ATTACHMENT_HINT embedded its own
// "## Downloading an attachment FROM Xero" section inside the upload-direction
// hint, so on the Xero server register_file_handle's description said
// "downloading ... never calls this tool" and then walked through downloading
// four paragraphs later. Split exactly like Gmail: upload content stays in
// XERO_ATTACHMENT_HINT, the download section becomes XERO_DOWNLOAD_HINT wired
// to `downloadHint`.

import { describe, it, expect } from "vitest";
import { xeroProvider } from "../index";

const attachmentHint = xeroProvider.attachmentHint ?? "";
const downloadHint = xeroProvider.downloadHint ?? "";

describe("xeroProvider.attachmentHint / downloadHint split (issue #41 follow-up)", () => {
  it("downloadHint is set and non-empty", () => {
    expect("downloadHint" in xeroProvider).toBe(true);
    expect(downloadHint.length).toBeGreaterThan(0);
  });

  it("downloadHint carries the Xero download section", () => {
    expect(downloadHint).toContain("## Downloading an attachment FROM Xero");
    expect(downloadHint).toContain('returnAs: "stage"');
    expect(downloadHint).toContain("Accept: application/octet-stream");
  });

  it("attachmentHint (upload direction) no longer contains the download section", () => {
    expect(attachmentHint).not.toContain("## Downloading an attachment FROM Xero");
    expect(attachmentHint).not.toContain('returnAs: "stage"');
  });

  it("attachmentHint still carries the upload Step 3 content", () => {
    expect(attachmentHint).toContain("Step 3");
    expect(attachmentHint).toContain("Invoices/${invoiceId}/Attachments/");
    expect(attachmentHint).toContain("files.xro/1.0/Files");
  });
});
