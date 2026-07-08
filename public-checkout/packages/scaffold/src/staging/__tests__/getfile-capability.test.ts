import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { handleUpload } from "../upload-handler";
import { insertPending } from "../repo";
import { mintToken, mintFileHandle } from "../tokens";
import { sha256Bearer } from "../crypto";
import { createGetFileCapability } from "../getfile-capability";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = {
  uploadTtlSeconds: 300,
  fetchTtlSeconds: 3600,
  maxBytes: 50 * 1024 * 1024,
};

async function uploadFixture(now: number, body: Uint8Array, ct = "image/png") {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const token = mintToken();
  const handle = mintFileHandle();
  await insertPending(d1 as unknown as D1Database, {
    token_hash: await sha256Bearer(token),
    file_handle: handle,
    content_type_hint: null,
    expected_byte_len: null,
    filename: null,
    created_at: now,
    expires_at: now + 300,
  });
  await handleUpload(
    new Request("https://x.test/staging/upload", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": ct,
        "Content-Length": String(body.byteLength),
      },
      body,
    }),
    {
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      now: () => now + 1,
    },
  );
  return { d1, r2, token, handle };
}

describe("createGetFileCapability", () => {
  it("returns ok with bytes for a valid (handle, token)", async () => {
    const { d1, r2, token, handle } = await uploadFixture(
      1_000_000,
      new Uint8Array([1, 2, 3]),
    );
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      now: () => 1_000_002,
    });
    const out = await getFile(handle, token);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.contentType).toBe("image/png");
    expect(out.byteLength).toBe(3);
    expect(atob(out.bytesBase64)).toBe(String.fromCharCode(1, 2, 3));
  });

  it("returns not-ok for a missing handle", async () => {
    const { d1, r2, token } = await uploadFixture(
      1_000_000,
      new Uint8Array([1]),
    );
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      now: () => 1_000_002,
    });
    const out = await getFile(mintFileHandle(), token);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(403);
  });

  it("returns not-ok for a wrong token", async () => {
    const { d1, r2, handle } = await uploadFixture(
      1_000_000,
      new Uint8Array([1]),
    );
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      now: () => 1_000_002,
    });
    const out = await getFile(handle, mintToken());
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(403);
  });
});
