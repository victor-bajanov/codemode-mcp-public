import { describe, it, expect } from "vitest";
import { z } from "zod";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { registerFileHandleTool, REGISTER_TOOL_INPUT_SHAPE } from "../register-tool";
import { lookupByHash } from "../repo";
import { sha256Bearer } from "../crypto";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

describe("registerFileHandleTool", () => {
  it("returns token, file_handle, upload_url, and TTLs", async () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://xero.example.com",
      now: () => 1000,
    });
    const out = await tool.handler({});
    expect(out.token).toMatch(/^stg_/);
    expect(out.file_handle).toMatch(/^fh_/);
    expect(out.upload_url).toBe("https://xero.example.com/staging/upload");
    expect(out.upload_ttl_seconds).toBe(300);
    expect(out.fetch_ttl_seconds).toBe(3600);
    expect(out.max_bytes).toBe(CFG.maxBytes);
  });

  it("inserts a pending row keyed by SHA-256(token)", async () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://xero.example.com",
      now: () => 1000,
    });
    const out = await tool.handler({ content_type: "image/png", filename: "x.png" });
    const row = await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(out.token));
    expect(row).not.toBeNull();
    expect(row!.state).toBe("pending");
    expect(row!.file_handle).toBe(out.file_handle);
    expect(row!.content_type_hint).toBe("image/png");
    expect(row!.filename).toBe("x.png");
    expect(row!.created_at).toBe(1000);
    expect(row!.expires_at).toBe(1000 + 300);
  });

  it("each call mints a distinct token", async () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database, config: CFG,
      uploadOrigin: "https://x.test", now: () => 1000,
    });
    const a = await tool.handler({});
    const b = await tool.handler({});
    expect(a.token).not.toBe(b.token);
    expect(a.file_handle).not.toBe(b.file_handle);
  });
});

describe("registerFileHandleTool description — scope (issue #41)", () => {
  it("no longer claims to be the tool for ANY file/attachment workflow", () => {
    const tool = registerFileHandleTool({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
    });
    // Old headline promised this tool covers every file workflow, including
    // download — but it is upload-only, so an agent asked to download an
    // attachment called it and got steered into the upload flow.
    expect(tool.description).not.toMatch(/ANY FILE\s*\/\s*ATTACHMENT WORKFLOW/i);
  });

  it("scopes itself to the upload/send direction", () => {
    const tool = registerFileHandleTool({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
    });
    expect(tool.description).toMatch(/UPLOAD\s*\/\s*SEND A FILE.*\bTO\b.*upstream/i);
  });

  it("routes the download/export direction to the execute tool's staging modes instead of itself", () => {
    const tool = registerFileHandleTool({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
    });
    expect(tool.description).toMatch(/download(ing)?/i);
    expect(tool.description).toMatch(/never calls this tool/i);
    expect(tool.description).toContain("execute");
  });

  it("keeps Steps 1-2 and the stepThree splice mechanism intact", () => {
    const withHint = registerFileHandleTool({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
      attachmentHint: "CUSTOM-STEP-THREE-MARKER",
    });
    expect(withHint.description).toContain("Step 1");
    expect(withHint.description).toContain("Step 2");
    expect(withHint.description).toContain("__stagingHost.getFile");
    expect(withHint.description).toContain("CUSTOM-STEP-THREE-MARKER");

    const withoutHint = registerFileHandleTool({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
    });
    // Generic fallback Step 3 still present when no provider hint is given.
    expect(withoutHint.description).toContain("Step 3");
  });
});

describe("REGISTER_TOOL_INPUT_SHAPE — filename cap (adjudicated)", () => {
  // This wave's Content-Disposition emission (fetch-handler.ts) amplifies a
  // long filename ~12x into a header via percent-encoding; the zod cap here
  // gives a clean 400 at registration on the primary path, with a truncation
  // backstop on the fetch side (impl-40's file, not this one).
  const schema = z.object(REGISTER_TOOL_INPUT_SHAPE);

  it("accepts a filename at the 255-character limit", () => {
    const result = schema.safeParse({ filename: "a".repeat(255) });
    expect(result.success).toBe(true);
  });

  it("rejects a filename over the 255-character limit", () => {
    const result = schema.safeParse({ filename: "a".repeat(256) });
    expect(result.success).toBe(false);
  });

  it("still allows filename to be omitted entirely", () => {
    const result = schema.safeParse({});
    expect(result.success).toBe(true);
  });

  it("documents the cap in the field description", () => {
    expect(REGISTER_TOOL_INPUT_SHAPE.filename.description).toMatch(/255/);
  });
});
