import { describe, it, expect, vi } from "vitest";
import {
  createStageFromUpstreamJsonCapability,
  type StageFromUpstreamJsonDeps,
  type UpstreamRequestResult,
} from "../stage-from-upstream-json";
import type { PutFileResult } from "../putfile-capability";

// Pass-through spy on the block decoder, so tests can see the ranges it gets.
vi.mock("../codec", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../codec")>();
  return { ...orig, decodeBase64Into: vi.fn(orig.decodeBase64Into) };
});

type PutFileFn = StageFromUpstreamJsonDeps["putFile"];
type UpstreamFn = StageFromUpstreamJsonDeps["upstreamRequest"];

function okPutFileResult(overrides: Partial<Extract<PutFileResult, { ok: true }>> = {}): Extract<PutFileResult, { ok: true }> {
  return {
    ok: true,
    file_handle: "fh_x",
    token: "stg_y",
    fetch_url: "https://x.test/staging/fetch/fh_x",
    expires_at: 999,
    byte_length: 12,
    ...overrides,
  };
}

function makeDeps(opts: {
  upstreamResult?: UpstreamRequestResult;
  upstreamThrows?: unknown;
  putFileResult?: PutFileResult;
}) {
  const putFile = vi.fn<PutFileFn>(async () => {
    return opts.putFileResult ?? okPutFileResult();
  });
  const upstreamRequest = vi.fn<UpstreamFn>(async () => {
    if (opts.upstreamThrows !== undefined) throw opts.upstreamThrows;
    return opts.upstreamResult ?? { success: true, status: 200, result: {} };
  });
  const cap = createStageFromUpstreamJsonCapability({ putFile, upstreamRequest });
  return { cap, putFile, upstreamRequest };
}

const BASE_REQ = { method: "GET", path: "/gmail/v1/users/me/messages/m1/attachments/a1" };

describe("createStageFromUpstreamJsonCapability", () => {
  it("happy path, base64url (Gmail-shaped)", async () => {
    const { cap, putFile, upstreamRequest } = makeDeps({
      upstreamResult: {
        success: true,
        status: 200,
        result: { data: "SGVsbG8tV29ybGQ_", mimeType: "application/pdf", size: 12 },
      },
      putFileResult: okPutFileResult({ file_handle: "fh_x", byte_length: 12 }),
    });

    const out = await cap(BASE_REQ, "data", "base64url", null);

    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.file_handle).toBe("fh_x");

    expect(putFile).toHaveBeenCalledTimes(1);
    // The raw base64url string goes through untouched (no converted copy);
    // the url alphabet is decoded natively by the codec.
    expect(putFile).toHaveBeenCalledWith("SGVsbG8tV29ybGQ_", "application/pdf", null, "url");

    // upstreamRequest must have been called with bypassTruncate forced true.
    expect(upstreamRequest).toHaveBeenCalledTimes(1);
    expect(upstreamRequest.mock.calls[0]![0]).toMatchObject({
      method: "GET",
      path: BASE_REQ.path,
      bypassTruncate: true,
    });
  });

  it("happy path, base64 encoding flag passes through unchanged", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
    });

    const out = await cap(BASE_REQ, "data", "base64", null);

    expect(out.ok).toBe(true);
    expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null, "std");
  });

  it("field missing returns ok:false, putFile not called", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { size: 100 } },
    });

    const out = await cap(BASE_REQ, "data", "base64url", null);

    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(502);
    expect(out.message).toContain("data");
    expect(out.message).toContain("missing");
    expect(putFile).not.toHaveBeenCalled();
  });

  it("field non-string returns ok:false, putFile not called", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { data: 12345 } },
    });

    const out = await cap(BASE_REQ, "data", "base64url", null);

    expect(out.ok).toBe(false);
    expect(putFile).not.toHaveBeenCalled();
  });

  it("upstream non-2xx returns ok:false with passed-through status", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: false, status: 404, result: { error: "nope" } },
    });

    const out = await cap(BASE_REQ, "data", "base64url", null);

    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(404);
    expect(out.message).toBe("upstream non-2xx");
    expect(putFile).not.toHaveBeenCalled();
  });

  it("upstream throws returns ok:false 502, putFile not called", async () => {
    const { cap, putFile } = makeDeps({
      upstreamThrows: new Error("boom"),
    });

    const out = await cap(BASE_REQ, "data", "base64url", null);

    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(502);
    expect(out.message).toContain("failed");
    expect(putFile).not.toHaveBeenCalled();
  });

  it("putFile failure passes through", async () => {
    const { cap } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      putFileResult: { ok: false, status: 413, message: "too large" },
    });

    const out = await cap(BASE_REQ, "data", "base64", null);

    expect(out).toEqual({ ok: false, status: 413, message: "too large" });
  });

  it("mimeType fallback to application/octet-stream when missing", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
    });

    await cap(BASE_REQ, "data", "base64", null);

    expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null, "std");
  });

  it("filenameOverride is forwarded to putFile", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { data: "AAAA", mimeType: "application/pdf" } },
    });

    await cap(BASE_REQ, "data", "base64", "x.pdf");

    expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", "x.pdf", "std");
  });

  it("bad dataField (empty string) returns 400, putFile not called, upstream not called", async () => {
    const { cap, putFile, upstreamRequest } = makeDeps({});

    const out = await cap(BASE_REQ, "", "base64url", null);

    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(400);
    expect(putFile).not.toHaveBeenCalled();
    expect(upstreamRequest).not.toHaveBeenCalled();
  });

  it("bad dataEncoding returns 400, putFile not called", async () => {
    const { cap, putFile, upstreamRequest } = makeDeps({});

    const out = await cap(BASE_REQ, "data", "hex" as unknown as "base64", null);

    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(400);
    expect(putFile).not.toHaveBeenCalled();
    expect(upstreamRequest).not.toHaveBeenCalled();
  });

  describe("contentTypeOverride", () => {
    it("override wins over an envelope mimeType", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: {
          success: true,
          status: 200,
          result: { data: "AAAA", mimeType: "application/pdf" },
        },
      });

      await cap(BASE_REQ, "data", "base64", null, "image/png");

      expect(putFile).toHaveBeenCalledWith("AAAA", "image/png", null, "std");
    });

    it("override supplies the type when the envelope has no mimeType (Gmail case)", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, "application/pdf");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null, "std");
    });

    it("omitted override preserves existing fallback to envelope mimeType", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: {
          success: true,
          status: 200,
          result: { data: "AAAA", mimeType: "application/pdf" },
        },
      });

      await cap(BASE_REQ, "data", "base64", null);

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null, "std");
    });

    it("null override preserves existing fallback to envelope mimeType", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: {
          success: true,
          status: 200,
          result: { data: "AAAA", mimeType: "application/pdf" },
        },
      });

      await cap(BASE_REQ, "data", "base64", null, null);

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null, "std");
    });

    it("neither override nor envelope mimeType present falls back to octet-stream", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, null);

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null, "std");
    });

    it("empty-string override falls through to envelope mimeType", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: {
          success: true,
          status: 200,
          result: { data: "AAAA", mimeType: "application/pdf" },
        },
      });

      await cap(BASE_REQ, "data", "base64", null, "");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null, "std");
    });

    it("whitespace-only override falls through to envelope mimeType", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: {
          success: true,
          status: 200,
          result: { data: "AAAA", mimeType: "application/pdf" },
        },
      });

      await cap(BASE_REQ, "data", "base64", null, "   ");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null, "std");
    });

    it("override with surrounding whitespace reaches putFile trimmed", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, "  application/pdf ");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null, "std");
    });

    it("whitespace-only envelope mimeType (no override) falls back to octet-stream", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA", mimeType: "   " } },
      });

      await cap(BASE_REQ, "data", "base64", null, null);

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null, "std");
    });

    it("empty-string override AND absent envelope mimeType falls back to octet-stream", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, "");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null, "std");
    });
  });

  describe("requestOpts hygiene (F-24)", () => {
    it("forwards only the declared StageRequestOpts fields plus bypassTruncate", async () => {
      const { cap, upstreamRequest } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });
      const opts = {
        method: "POST",
        path: "/x",
        query: { a: 1 },
        body: { k: "v" },
        contentType: "application/json",
        rawBody: false,
        bodyBase64: "e30=",
        // Undeclared: must not ride through to the handler ctx.
        headers: { "X-Extra": "1" },
        returnAs: "stage",
        multipart: [],
        relatedRequestId: "rid-1",
      };
      await cap(opts as never, "data", "base64");
      expect(upstreamRequest).toHaveBeenCalledTimes(1);
      expect(upstreamRequest.mock.calls[0]![0]).toEqual({
        method: "POST",
        path: "/x",
        query: { a: 1 },
        body: { k: "v" },
        contentType: "application/json",
        rawBody: false,
        bodyBase64: "e30=",
        bypassTruncate: true,
      });
    });

    it("omits declared fields that are undefined rather than forwarding undefined keys", async () => {
      const { cap, upstreamRequest } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });
      await cap({ method: "GET", path: "/x", query: undefined } as never, "data", "base64");
      const ctx = upstreamRequest.mock.calls[0]![0];
      expect(Object.keys(ctx).sort()).toEqual(["bypassTruncate", "method", "path"]);
    });

    it("a sandbox-supplied bypassTruncate cannot be turned off", async () => {
      const { cap, upstreamRequest } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });
      await cap({ ...BASE_REQ, bypassTruncate: false } as never, "data", "base64");
      expect(upstreamRequest.mock.calls[0]![0].bypassTruncate).toBe(true);
    });

    it.each([
      ["null", null],
      ["a string", "GET /x"],
      ["an array", [{ method: "GET", path: "/x" }]],
      ["a number", 42],
    ])("rejects requestOpts that is %s with 400 and never calls upstream", async (_label, bad) => {
      const { cap, upstreamRequest, putFile } = makeDeps({});
      const out = await cap(bad as never, "data", "base64");
      expect(out).toEqual({ ok: false, status: 400, message: "requestOpts must be an object" });
      expect(upstreamRequest).not.toHaveBeenCalled();
      expect(putFile).not.toHaveBeenCalled();
    });
  });

  describe("base64url is passed through raw", () => {
    it.each(["AAA", "AB", "AAAA", "AB=="])("%s reaches putFile unchanged with the url alphabet", async (data) => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data } },
      });
      await cap(BASE_REQ, "data", "base64url", null);
      expect(putFile).toHaveBeenCalledWith(data, "application/octet-stream", null, "url");
    });
  });
});

describe("stageFromUpstreamJson — v2 staging side (real putFile)", () => {
  const BLOCK = 1_048_576;

  async function realDeps(
    data: unknown,
    maxBytes = 50 * 1024 * 1024,
    opts: { acquire?: boolean; throwAfterAcquire?: boolean } = {},
  ) {
    const { FakeD1 } = await import("./__fixtures__/fake-d1");
    const { FakeR2 } = await import("./__fixtures__/fake-r2");
    const { FakeGate } = await import("./__fixtures__/fake-gate");
    const { createPutFileCapability } = await import("../putfile-capability");
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const gate = new FakeGate();
    const runKey = {};
    const putFile = createPutFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes },
      uploadOrigin: "https://x.test",
    });
    let heldBeforeAcquire = false;
    // Stands in for WP-B's handler: it acquires the lease only after approval
    // and token mint, i.e. inside the upstream call.
    const upstreamRequest = vi.fn<UpstreamFn>(async (_ctx, lease) => {
      heldBeforeAcquire = gate.inFlight > 0;
      if (opts.acquire !== false) await lease.acquire();
      if (opts.throwAfterAcquire) throw new Error("network down");
      return { success: true, status: 200, result: { data, mimeType: "application/pdf" } };
    });
    const cap = createStageFromUpstreamJsonCapability({
      putFile,
      upstreamRequest,
      transferGate: gate,
      currentRun: () => ({ runKey, signal: new AbortController().signal }),
    });
    return { cap, d1, r2, gate, runKey, heldBeforeAcquire: () => heldBeforeAcquire };
  }

  function pat(n: number): Uint8Array {
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i++) a[i] = (i * 29 + 5) & 0xff;
    return a;
  }

  it("decodes a multi-block base64url field block by block (never a whole-file decode, never atob)", async () => {
    const codec = await import("../codec");
    const x = pat(3 * BLOCK + 2);
    const data = Buffer.from(x).toString("base64url");
    const { cap, d1, r2 } = await realDeps(data);
    const atob = vi.spyOn(globalThis, "atob");
    const decode = vi.mocked(codec.decodeBase64Into);
    decode.mockClear();
    const out = await cap(BASE_REQ, "data", "base64url", "q.pdf");
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(atob).not.toHaveBeenCalled();
    expect(decode.mock.calls.length).toBeGreaterThan(3);
    for (const [, start, end] of decode.mock.calls) {
      expect(end - start).toBeLessThanOrEqual(Math.ceil(BLOCK / 3) * 4 + 4);
    }
    // Round-trip through the opener.
    const { createStagedFileOpener } = await import("../staged-file");
    const open = createStagedFileOpener({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket,
      config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 },
    });
    const r = await open({ file_handle: out.file_handle, token: out.token });
    if (!r.ok) throw new Error("open failed");
    expect(r.file.meta).toEqual({ byteLength: x.byteLength, contentType: "application/pdf", filename: "q.pdf" });
    const parts: Uint8Array[] = [];
    await r.file.readBlocks(async (b) => { parts.push(b.slice()); });
    expect(Buffer.concat(parts).equals(Buffer.from(x))).toBe(true);
  });

  it("a mixed-alphabet data string → 400, nothing stored", async () => {
    const { cap, r2, d1 } = await realDeps("AA-A+/AA");
    expect(await cap(BASE_REQ, "data", "base64url", null)).toMatchObject({ ok: false, status: 400 });
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });

  it("a data string longer than 4/3·maxBytes → 413 before any decoding", async () => {
    const codec = await import("../codec");
    const decode = vi.mocked(codec.decodeBase64Into);
    const { cap, r2 } = await realDeps("A".repeat(Math.ceil(1000 / 3) * 4 + 8), 1000);
    decode.mockClear();
    expect(await cap(BASE_REQ, "data", "base64url", null)).toMatchObject({ ok: false, status: 413 });
    expect(decode).not.toHaveBeenCalled();
    expect(r2.store.size).toBe(0);
  });

  it("non-string and empty data stay 502", async () => {
    for (const data of [42, ""]) {
      const { cap } = await realDeps(data);
      expect(await cap(BASE_REQ, "data", "base64url", null)).toMatchObject({ ok: false, status: 502 });
    }
  });

  it("never acquires the gate itself: the slot is taken through the lease inside the upstream call", async () => {
    const { cap, gate, runKey, heldBeforeAcquire } = await realDeps(Buffer.from(pat(10)).toString("base64url"));
    expect((await cap(BASE_REQ, "data", "base64url", null)).ok).toBe(true);
    expect(heldBeforeAcquire()).toBe(false); // nothing held while the request (and any elicitation) runs
    expect(gate.acquired).toHaveLength(1);
    expect(gate.acquired[0]!.runKey).toBe(runKey);
    expect(gate.released).toBe(1);
  });

  it("does not acquire when the upstream call never takes the lease", async () => {
    const { cap, gate } = await realDeps(Buffer.from(pat(10)).toString("base64url"), undefined, { acquire: false });
    expect((await cap(BASE_REQ, "data", "base64url", null)).ok).toBe(true);
    expect(gate.acquired).toHaveLength(0);
    expect(gate.released).toBe(0);
  });

  it("releases the lease when putFile fails", async () => {
    const { cap, gate } = await realDeps("AA-A+/AA");
    expect((await cap(BASE_REQ, "data", "base64url", null)).ok).toBe(false);
    expect(gate.acquired).toHaveLength(1);
    expect(gate.released).toBe(1);
  });

  it("releases the lease when the upstream call throws after acquiring", async () => {
    const { cap, gate } = await realDeps("AAAA", undefined, { throwAfterAcquire: true });
    expect(await cap(BASE_REQ, "data", "base64url", null)).toMatchObject({ ok: false, status: 502 });
    expect(gate.acquired).toHaveLength(1);
    expect(gate.released).toBe(1);
  });

  it("an upstream timeout after acquiring the lease surfaces /timed out/ and releases the lease", async () => {
    const { FakeGate } = await import("./__fixtures__/fake-gate");
    const { createPutFileCapability } = await import("../putfile-capability");
    const { FakeD1 } = await import("./__fixtures__/fake-d1");
    const { FakeR2 } = await import("./__fixtures__/fake-r2");
    const gate = new FakeGate();
    const cap = createStageFromUpstreamJsonCapability({
      putFile: createPutFileCapability({
        STAGING_D1: new FakeD1() as unknown as D1Database,
        STAGING_R2: new FakeR2() as unknown as R2Bucket,
        config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 1024 },
        uploadOrigin: "https://x.test",
      }),
      upstreamRequest: async (_ctx, lease) => {
        await lease.acquire();
        throw new Error("staged transfer timed out after 60000 ms and was aborted");
      },
      transferGate: gate,
      currentRun: () => undefined,
    });
    const out = await cap(BASE_REQ, "data", "base64url", null);
    expect(out).toMatchObject({ ok: false, status: 502 });
    expect(out.ok ? "" : out.message).toMatch(/timed out/);
    expect(gate.acquired).toHaveLength(1);
    expect(gate.released).toBe(1);
  });

  it("a refused lease → 429 with the gate's message", async () => {
    const { cap, gate } = await realDeps("AAAA");
    gate.rejectWith = new Error("staged transfers are busy; retry shortly");
    const out = await cap(BASE_REQ, "data", "base64url", null);
    expect(out).toMatchObject({ ok: false, status: 429, message: "staged transfers are busy; retry shortly" });
  });
});

describe("stageFromUpstreamJson — alphabet tolerance (review item 3)", () => {
  async function stageWith(data: string, encoding: "base64url" | "base64" = "base64url") {
    const { FakeD1 } = await import("./__fixtures__/fake-d1");
    const { FakeR2 } = await import("./__fixtures__/fake-r2");
    const { createPutFileCapability } = await import("../putfile-capability");
    const { createStagedFileOpener } = await import("../staged-file");
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const store = {
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 },
      uploadOrigin: "https://x.test",
    };
    const cap = createStageFromUpstreamJsonCapability({
      putFile: createPutFileCapability(store),
      upstreamRequest: async () => ({ success: true, status: 200, result: { data } }),
    });
    const out = await cap(BASE_REQ, "data", encoding, null);
    let bytes: Buffer | null = null;
    if (out.ok) {
      const r = await createStagedFileOpener(store)({ file_handle: out.file_handle, token: out.token });
      if (!r.ok) throw new Error("open failed");
      const parts: Uint8Array[] = [];
      await r.file.readBlocks(async (b) => { parts.push(b.slice()); });
      bytes = Buffer.concat(parts);
    }
    return { out, bytes };
  }

  it("standard-alphabet data under the default base64url mode stages the right bytes", async () => {
    const x = Buffer.from([0xfb, 0xff, 0xbf, 0x00, 0x3e, 0x3f, 0xfa]);
    const std = x.toString("base64");
    expect(std).toMatch(/[+/]/);
    const { out, bytes } = await stageWith(std);
    expect(out.ok).toBe(true);
    expect(bytes!.equals(x)).toBe(true);
  });

  it("data mixing both alphabets → 400", async () => {
    const { out } = await stageWith("+/-_AAAA");
    expect(out).toMatchObject({ ok: false, status: 400 });
  });
});
