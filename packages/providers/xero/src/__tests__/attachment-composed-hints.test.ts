// Issue #59 (staged transfer v2): Xero's upload hint moves off
// `__stagingHost.getFile` + `bodyBase64` (bytes through the sandbox) onto the
// host-assembled channels: `composed` with a sole identity segment for the
// raw-octet `*AttachmentByFileName` PUT, and `multipart[].staged` for the
// Files API. The snippets are executed here against a recording
// `codemode.request`, so a hint that drifts from the documented shapes
// (plan §2/§3) fails loudly instead of teaching the model a dead shape.

import { describe, it, expect } from "vitest";
import { xeroProvider } from "../index";

const hint = xeroProvider.attachmentHint ?? "";

const FILE_HANDLE = "fh_AAAAAAAAAAAAAAAAAAAAAA";
const TOKEN = "stg_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

/** Every `await codemode.request({ … });` block in the hint, verbatim. */
function snippets(text: string): string[] {
  return [...text.matchAll(/^ {2}await codemode\.request\(\{\n[\s\S]*?\n {2}\}\);$/gm)].map((m) => m[0]);
}

const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (
  ...args: string[]
) => (...a: unknown[]) => Promise<unknown>;

/** Run one snippet with the free variables the hint documents bound to fixed
 *  values, returning the options object it passed to codemode.request. */
async function run(snippet: string): Promise<Record<string, unknown>> {
  const calls: Record<string, unknown>[] = [];
  const codemode = { request: async (o: Record<string, unknown>) => { calls.push(o); return { success: true }; } };
  const fn = new AsyncFunction("codemode", "invoiceId", "file_handle", "token", "fileName", snippet);
  await fn(codemode, "inv-1", FILE_HANDLE, TOKEN, "q 1.pdf");
  expect(calls).toHaveLength(1);
  return calls[0]!;
}

describe("XERO_ATTACHMENT_HINT — staged transfer v2 shapes (issue #59)", () => {
  it("carries exactly two runnable codemode.request snippets", () => {
    expect(snippets(hint)).toHaveLength(2);
  });

  it("the invoice attachment snippet is a raw-octet PUT whose body is a sole identity composed segment", async () => {
    const opts = await run(snippets(hint).find((s) => s.includes("/Attachments/"))!);
    expect(opts.method).toBe("PUT");
    expect(opts.path).toBe("/api.xro/2.0/Invoices/inv-1/Attachments/q%201.pdf");
    expect(typeof opts.contentType).toBe("string");
    expect(opts.composed).toEqual({
      segments: [{ staged: { file_handle: FILE_HANDLE, token: TOKEN }, encoding: "identity" }],
    });
    for (const k of ["body", "bodyBase64", "rawBody", "multipart"]) expect(opts).not.toHaveProperty(k);
  });

  it("the Files API snippet is a multipart POST with a staged part and no contentType", async () => {
    const opts = await run(snippets(hint).find((s) => s.includes("/files.xro/1.0/Files"))!);
    expect(opts.method).toBe("POST");
    expect(opts.path).toBe("/files.xro/1.0/Files");
    expect(opts).not.toHaveProperty("contentType");
    expect(opts).not.toHaveProperty("composed");
    const parts = opts.multipart as Array<Record<string, unknown>>;
    const staged = parts.filter((p) => "staged" in p);
    expect(staged).toHaveLength(1);
    expect(staged[0]!.name).toBe("file");
    expect(staged[0]!.staged).toEqual({ file_handle: FILE_HANDLE, token: TOKEN });
    // Mutually exclusive with inline bytes on the same part (plan §2).
    expect(staged[0]).not.toHaveProperty("value");
    expect(staged[0]).not.toHaveProperty("bodyBase64");
  });

  it("no longer routes bytes through the sandbox (getFile / bytesBase64)", () => {
    expect(hint).not.toContain("bytesBase64");
    expect(hint).not.toContain("getFile(");
  });

  it("says where `fileName` comes from", () => {
    expect(hint).toMatch(/`fileName` is [^\n]*register_file_handle/);
  });

  it("states Xero's measured per-request ceiling, not the docs' rounded figure", () => {
    // Measured on xero-dev (2026-10-15): 10,239,999 B accepted, 10,240,000 B → 413.
    expect(hint).toMatch(/10,240,000 bytes/);
    expect(hint).not.toMatch(/10 MB/);
  });

  it("warns that Files API multipart framing eats into the ceiling", () => {
    expect(hint).toMatch(/Files[^\n]*multipart[^\n]*(framing|overhead)/i);
  });

  it("warns that Xero rejects some file extensions such as .bin", () => {
    expect(hint).toMatch(/\.bin/);
  });
});
