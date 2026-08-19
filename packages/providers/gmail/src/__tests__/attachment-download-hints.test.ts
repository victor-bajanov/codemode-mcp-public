// Issue #41: GMAIL_ATTACHMENT_HINT used to carry BOTH the upload (Step 3) content
// AND the "Downloading an attachment FROM Gmail" section, spliced only into
// `attachmentHint` — which the scaffold only ever puts into the upload-only
// register_file_handle tool and the execute tool's attachment splice. The
// download section is split out into a new `downloadHint`, wired to the
// execute tool's dedicated downloadHint slot (see mcp-agent-factory.ts).

import { describe, it, expect } from "vitest";
import { gmailProvider } from "../index";

const attachmentHint = gmailProvider.attachmentHint ?? "";
const downloadHint = gmailProvider.downloadHint ?? "";

describe("gmailProvider.attachmentHint / downloadHint split (issue #41)", () => {
  it("downloadHint is set and non-empty", () => {
    expect("downloadHint" in gmailProvider).toBe(true);
    expect(downloadHint.length).toBeGreaterThan(0);
  });

  it("downloadHint carries the attachments.get download section", () => {
    expect(downloadHint).toContain("## Downloading an attachment FROM Gmail");
    expect(downloadHint).toContain("gmail.users.messages.attachments.get");
    expect(downloadHint).toContain("__stagingHost.stageFromUpstreamJson");
  });

  it("downloadHint's snippet passes the 5th arg (mimeType) sourced from the parent part", () => {
    expect(downloadHint).toMatch(/mimeType\s*\?\?\s*null/);
    expect(downloadHint).toMatch(/parent\s+.*messages\.get.*part/i);
  });

  it("downloadHint states the envelope never carries mimeType, so the 5th arg is mandatory", () => {
    // Old wording claimed the envelope mimeType "usually works" / falls back
    // gracefully; that was wrong for Gmail's attachments.get, which never
    // returns mimeType at all.
    expect(downloadHint).toMatch(/never includes.*mimeType|no mimeType|has NO mimeType/i);
    expect(downloadHint).toMatch(/ALWAYS pass/i);
  });

  it("downloadHint says filename flows through to X-Filename and Content-Disposition on fetch", () => {
    expect(downloadHint).toContain("X-Filename");
    expect(downloadHint).toMatch(/Content-Disposition:\s*attachment;\s*filename=/);
  });

  it("attachmentHint (upload direction) no longer contains the download section", () => {
    expect(attachmentHint).not.toContain("## Downloading an attachment FROM Gmail");
    expect(attachmentHint).not.toContain("gmail.users.messages.attachments.get");
  });

  it("attachmentHint still carries the upload Step 3 content and the send size limit section", () => {
    expect(attachmentHint).toContain("Step 3");
    expect(attachmentHint).toContain("messages/send");
    expect(attachmentHint).toContain("## Send size limit");
  });
});
