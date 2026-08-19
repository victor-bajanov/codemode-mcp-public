import { describe, it, expect, vi } from "vitest";
import {
  createStageFromUpstreamJsonCapability,
  type StageFromUpstreamJsonDeps,
  type UpstreamRequestResult,
} from "../stage-from-upstream-json";
import type { PutFileResult } from "../putfile-capability";

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
    // "SGVsbG8tV29ybGQ_" → replace `-`→`+`, `_`→`/` → "SGVsbG8tV29ybGQ/" (len 16, no padding needed).
    expect(putFile).toHaveBeenCalledWith("SGVsbG8tV29ybGQ/", "application/pdf", null);

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
    expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null);
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

    expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null);
  });

  it("filenameOverride is forwarded to putFile", async () => {
    const { cap, putFile } = makeDeps({
      upstreamResult: { success: true, status: 200, result: { data: "AAAA", mimeType: "application/pdf" } },
    });

    await cap(BASE_REQ, "data", "base64", "x.pdf");

    expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", "x.pdf");
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

      expect(putFile).toHaveBeenCalledWith("AAAA", "image/png", null);
    });

    it("override supplies the type when the envelope has no mimeType (Gmail case)", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, "application/pdf");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null);
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

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null);
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

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null);
    });

    it("neither override nor envelope mimeType present falls back to octet-stream", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, null);

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null);
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

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null);
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

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null);
    });

    it("override with surrounding whitespace reaches putFile trimmed", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, "  application/pdf ");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/pdf", null);
    });

    it("whitespace-only envelope mimeType (no override) falls back to octet-stream", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA", mimeType: "   " } },
      });

      await cap(BASE_REQ, "data", "base64", null, null);

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null);
    });

    it("empty-string override AND absent envelope mimeType falls back to octet-stream", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });

      await cap(BASE_REQ, "data", "base64", null, "");

      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null);
    });
  });

  describe("base64url padding correctness", () => {
    it("3 chars → 1 pad char ('AAA' → 'AAA=')", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAA" } },
      });
      await cap(BASE_REQ, "data", "base64url", null);
      expect(putFile).toHaveBeenCalledWith("AAA=", "application/octet-stream", null);
    });

    it("2 chars → 2 pad chars ('AB' → 'AB==')", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AB" } },
      });
      await cap(BASE_REQ, "data", "base64url", null);
      expect(putFile).toHaveBeenCalledWith("AB==", "application/octet-stream", null);
    });

    it("4 chars → 0 pad chars ('AAAA' → 'AAAA')", async () => {
      const { cap, putFile } = makeDeps({
        upstreamResult: { success: true, status: 200, result: { data: "AAAA" } },
      });
      await cap(BASE_REQ, "data", "base64url", null);
      expect(putFile).toHaveBeenCalledWith("AAAA", "application/octet-stream", null);
    });
  });
});
