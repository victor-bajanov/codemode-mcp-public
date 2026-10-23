import { describe, it, expect, vi } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { handleUpload } from "../upload-handler";
import { insertPending } from "../repo";
import { mintToken, mintFileHandle } from "../tokens";
import { sha256Bearer } from "../crypto";
import { createGetFileCapability } from "../getfile-capability";
import { seedV1Row } from "./__fixtures__/v1-row";
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

describe("createGetFileCapability — v2 cap and gate", () => {
  const BIG = 8 * 1024 * 1024;

  async function staged(size: number, cfg: StagingConfig = CFG) {
    const { stageFromBlocks, blockSourceFromBytes } = await import("../staged-file");
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const x = new Uint8Array(size);
    for (let i = 0; i < size; i++) x[i] = (i * 7 + 3) & 0xff;
    const out = await stageFromBlocks(
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: cfg, uploadOrigin: "https://x.test", now: () => 1_000_000 },
      blockSourceFromBytes(x), "text/csv", "a.csv",
    );
    if (!out.ok) throw new Error("stage failed");
    return { d1, r2, x, ref: out };
  }

  it("refuses a row larger than STAGING_GETFILE_MAX_BYTES with 413 and no R2 read; message points at composed", async () => {
    const cfg = { ...CFG, getFileMaxBytes: 100 };
    const { d1, r2, ref } = await staged(101, cfg);
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: cfg, now: () => 1_000_002,
    });
    const out = await getFile(ref.file_handle, ref.token);
    expect(out).toMatchObject({ ok: false, status: 413 });
    expect(out.ok ? "" : out.message).toMatch(/composed/);
    expect(out.ok ? "" : out.message).not.toContain(ref.token);
    expect(out.ok ? "" : out.message).not.toContain(ref.file_handle);
    expect(r2.getCalls).toBe(0);
  });

  it("round-trips an 8 MiB file without per-byte string building", async () => {
    const { d1, r2, x, ref } = await staged(BIG);
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => 1_000_002,
    });
    const spy = vi.spyOn(String, "fromCharCode");
    const out = await getFile(ref.file_handle, ref.token);
    const calls = spy.mock.calls.length;
    spy.mockRestore();
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(calls).toBeLessThanOrEqual(BIG / 0x8000 + 1);
    expect(out.byteLength).toBe(BIG);
    expect(out.filename).toBe("a.csv");
    expect(out.contentType).toBe("text/csv");
    expect(out.bytesBase64).toBe(Buffer.from(x).toString("base64"));
  });

  it("acquires the transfer gate (with the current run's key) and releases it", async () => {
    const { FakeGate } = await import("./__fixtures__/fake-gate");
    const { d1, r2, ref } = await staged(10);
    const gate = new FakeGate();
    const runKey = {};
    const signal = new AbortController().signal;
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => 1_000_002,
      transferGate: gate, currentRun: () => ({ runKey, signal }),
    });
    expect((await getFile(ref.file_handle, ref.token)).ok).toBe(true);
    expect(gate.acquired).toHaveLength(1);
    expect(gate.acquired[0]!.runKey).toBe(runKey);
    expect(gate.acquired[0]!.signal).toBe(signal);
    expect(gate.released).toBe(1);
  });

  it("maps a gate refusal to 429 without reading R2", async () => {
    const { FakeGate } = await import("./__fixtures__/fake-gate");
    const { d1, r2, ref } = await staged(10);
    const gate = new FakeGate();
    gate.rejectWith = new Error("one staged transfer at a time per execution; await each before starting the next");
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => 1_000_002,
      transferGate: gate, currentRun: () => undefined,
    });
    const out = await getFile(ref.file_handle, ref.token);
    expect(out).toMatchObject({ ok: false, status: 429 });
    expect(out.ok ? "" : out.message).toMatch(/one staged transfer at a time/);
    expect(r2.getCalls).toBe(0);
  });

  it("releases the gate when the read fails", async () => {
    const { FakeGate } = await import("./__fixtures__/fake-gate");
    const { d1, r2, ref } = await staged(10);
    r2.store.clear();
    const gate = new FakeGate();
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => 1_000_002,
      transferGate: gate, currentRun: () => undefined,
    });
    expect((await getFile(ref.file_handle, ref.token)).ok).toBe(false);
    expect(gate.released).toBe(1);
  });
});

describe("createGetFileCapability — filename sanitising (review item 5)", () => {
  it("returns the row filename with controls, format chars and lone surrogates stripped", async () => {
    const { stageFromBlocks, blockSourceFromBytes } = await import("../staged-file");
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const out = await stageFromBlocks(
      { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, uploadOrigin: "https://x.test", now: () => 1_000_000 },
      blockSourceFromBytes(new Uint8Array([1])), "text/plain", "a\r\nb\u202E\uD800.txt",
    );
    if (!out.ok) throw new Error("stage failed");
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, now: () => 1_000_002,
    });
    const f = await getFile(out.file_handle, out.token);
    expect(f.ok && f.filename).toBe("ab.txt");
  });
});

describe("createGetFileCapability — legacy rows", () => {
  it("returns 410 'legacy format' for a v1 row without reading R2", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const ref = await seedV1Row(d1, r2, new Uint8Array([1, 2, 3]), { now: 1_000_000 });
    const getFile = createGetFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      now: () => 1_000_001,
    });
    expect(await getFile(ref.handle, ref.token)).toEqual({
      ok: false,
      status: 410,
      message: "stored in a legacy format; re-stage the file",
    });
    expect(r2.getCalls).toBe(0);
  });
});
