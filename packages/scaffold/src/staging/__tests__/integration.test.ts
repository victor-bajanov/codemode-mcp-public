import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { registerFileHandleTool } from "../register-tool";
import { handleUpload } from "../upload-handler";
import { handleFetch } from "../fetch-handler";
import { createGetFileCapability } from "../getfile-capability";
import { createPutFileCapability } from "../putfile-capability";
import { runSweep } from "../sweep";

const CFG = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

describe("integration: register → upload → fetch → getFile → sweep", () => {
  it("round-trips a 1MB file through the full pipeline", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    let clock = 1_000_000;
    const now = () => clock;

    // 1. register
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
      now,
    });
    const reg = await tool.handler({ content_type: "application/octet-stream", filename: "data.bin" });
    expect(reg.token.startsWith("stg_")).toBe(true);
    expect(reg.file_handle.startsWith("fh_")).toBe(true);

    // 2. upload
    // crypto.getRandomValues caps at 65,536 bytes per call — fill in 64KB chunks.
    const plain = new Uint8Array(1024 * 1024);
    const CHUNK = 65_536;
    for (let off = 0; off < plain.byteLength; off += CHUNK) {
      const len = Math.min(CHUNK, plain.byteLength - off);
      crypto.getRandomValues(plain.subarray(off, off + len));
    }
    clock += 1;
    const upRes = await handleUpload(
      new Request(reg.upload_url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${reg.token}`,
          "Content-Type": "application/octet-stream",
          "Content-Length": String(plain.byteLength),
        },
        body: plain,
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now },
    );
    expect(upRes.status).toBe(204);

    // 3. direct fetch via handler
    clock += 1;
    const fetchRes = await handleFetch(
      new Request(`https://x.test/staging/fetch/${reg.file_handle}`, {
        method: "GET",
        headers: { Authorization: `Bearer ${reg.token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now },
    );
    expect(fetchRes.status).toBe(200);
    const fetched = new Uint8Array(await fetchRes.arrayBuffer());
    expect(Buffer.from(fetched).equals(Buffer.from(plain))).toBe(true);

    // 4. fetch via getFile capability (what the sandbox sees)
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      // GetFileCapabilityDeps has an optional `now` field (Task 16 added one);
      // pass `now` so the inner handleFetch sees the same clock.
      now,
    });
    const out = await getFile(reg.file_handle, reg.token);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.byteLength).toBe(plain.byteLength);
    const bin = atob(out.bytesBase64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    expect(Buffer.from(bytes).equals(Buffer.from(plain))).toBe(true);

    // 5. advance past fetch TTL and verify sweep cleans up
    clock += CFG.fetchTtlSeconds + 10;
    const sweepResult = await runSweep({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      now,
    });
    expect(sweepResult.deletedRows).toBe(1);
    expect(sweepResult.deletedObjects).toBe(1);
    expect(r2.store.size).toBe(0);
  });
});

describe("integration: putFile round-trip via fetch_url", () => {
  it("getFile→putFile keeps bytes identical end-to-end", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    let clock = 2_000_000;
    const now = () => clock;

    // 1. register + upload an initial fixture.
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
      now,
    });
    const reg = await tool.handler({ content_type: "application/pdf", filename: "a.pdf" });

    const plain = new Uint8Array(64_000);
    crypto.getRandomValues(plain);
    clock += 1;
    const upRes = await handleUpload(
      new Request(reg.upload_url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${reg.token}`,
          "Content-Type": "application/pdf",
          "Content-Length": String(plain.byteLength),
        },
        body: plain,
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now },
    );
    expect(upRes.status).toBe(204);

    // 2. inside-sandbox flow: getFile then putFile on the same bytes.
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      now,
    });
    clock += 1;
    const got = await getFile(reg.file_handle, reg.token);
    expect(got.ok).toBe(true);
    if (!got.ok) return;

    const putFile = createPutFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      uploadOrigin: "https://x.test",
      now,
    });
    clock += 1;
    const stagedOut = await putFile(got.bytesBase64, got.contentType, got.filename);
    expect(stagedOut.ok).toBe(true);
    if (!stagedOut.ok) return;
    expect(stagedOut.fetch_url).toBe(`https://x.test/staging/fetch/${stagedOut.file_handle}`);
    expect(stagedOut.byte_length).toBe(plain.byteLength);

    // 3. simulated client `curl -H "Authorization: Bearer <token>" <fetch_url>`.
    clock += 1;
    const dlRes = await handleFetch(
      new Request(stagedOut.fetch_url, {
        method: "GET",
        headers: { Authorization: `Bearer ${stagedOut.token}` },
      }),
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now },
    );
    expect(dlRes.status).toBe(200);
    expect(dlRes.headers.get("Content-Type")).toBe("application/pdf");
    expect(dlRes.headers.get("X-Filename")).toBe("a.pdf");
    const dl = new Uint8Array(await dlRes.arrayBuffer());
    expect(Buffer.from(dl).equals(Buffer.from(plain))).toBe(true);
  });

  it("runSweep removes putFile-inserted rows after their TTL", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    let clock = 3_000_000;
    const now = () => clock;

    const putFile = createPutFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      uploadOrigin: "https://x.test",
      now,
    });
    const bytes = new Uint8Array([42, 42, 42]);
    let s = "";
    for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]!);
    const out = await putFile(btoa(s), "application/octet-stream", null);
    expect(out.ok).toBe(true);
    expect(r2.store.size).toBe(1);

    clock += CFG.fetchTtlSeconds + 10;
    const swept = await runSweep({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      now,
    });
    expect(swept.deletedRows).toBe(1);
    expect(swept.deletedObjects).toBe(1);
    expect(r2.store.size).toBe(0);
  });
});
