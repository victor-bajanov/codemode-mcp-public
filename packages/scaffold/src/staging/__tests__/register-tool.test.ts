import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { registerFileHandleTool } from "../register-tool";
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
