// B9 — Staging capabilities as reachable from sandbox code.
//
//   getFile(handle, token): both must match one row; token is 32 random bytes,
//     handle 16 random bytes, lookup is by SHA-256(token) then constant-time
//     handle compare, so cross-user enumeration is infeasible. (REFUTED)
//   putFile: base64 used to be fully decoded BEFORE the size cap was applied,
//     so an over-cap payload cost host CPU/memory first. The string length is
//     now bounded before decoding. (FIXED, F-24)
//   stageFromUpstreamJson: `requestOpts` used to be spread into the handler
//     ctx, so fields outside StageRequestOpts (headers, returnAs, multipart,
//     ...) rode through. Only the declared fields are now forwarded. (FIXED,
//     F-24; relatedRequestId was never injectable — separate HandleArgs field.)
//
// Status: FIXED (F-24) — putFile length-checks before decoding and
// stageFromUpstreamJson forwards only declared fields; getFile isolation
// stays REFUTED.
import { describe, it, expect, vi } from "vitest";
import { createPutFileCapability } from "../../staging/putfile-capability";
import { createGetFileCapability } from "../../staging/getfile-capability";
import { createStageFromUpstreamJsonCapability } from "../../staging/stage-from-upstream-json";
import { TOKEN_SECRET_BYTES, HANDLE_BYTES } from "../../staging/types";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";

const config = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 16 };

describe("B9 — staging capability isolation", () => {
  it("getFile needs BOTH the handle and the token of the same row; secrets are 32/16 random bytes (REFUTED)", async () => {
    const d1 = new FakeD1() as unknown as D1Database;
    const r2 = new FakeR2() as unknown as R2Bucket;
    const putFile = createPutFileCapability({ STAGING_D1: d1, STAGING_R2: r2, config, uploadOrigin: "https://poc.example" });
    const getFile = createGetFileCapability({ STAGING_D1: d1, STAGING_R2: r2, config });
    const a = await putFile(btoa("user-A-data"), "text/plain", "a.txt");
    const b = await putFile(btoa("user-B-data"), "text/plain", "b.txt");
    if (!a.ok || !b.ok) throw new Error("setup");
    expect(TOKEN_SECRET_BYTES).toBe(32);
    expect(HANDLE_BYTES).toBe(16);
    // Mix-and-match across rows is refused; the matching pair works.
    expect((await getFile(a.file_handle, b.token)).ok).toBe(false);
    expect((await getFile(b.file_handle, a.token)).ok).toBe(false);
    expect((await getFile(a.file_handle, "stg_not-a-token")).ok).toBe(false);
    const mine = await getFile(a.file_handle, a.token);
    expect(mine.ok && atob(mine.bytesBase64)).toBe("user-A-data");
    expect(JSON.stringify(mine)).not.toContain("user-B");
  });

  it("FIXED (F-24): putFile enforces maxBytes on the base64 length before decoding", async () => {
    const putFile = createPutFileCapability({ STAGING_D1: new FakeD1() as never, STAGING_R2: new FakeR2() as never, config, uploadOrigin: "https://poc.example" });
    const atobSpy = vi.spyOn(globalThis, "atob");
    try {
      // Over-cap AND malformed: a 413 (not 400 "bad base64") proves the size
      // check now runs first, and atob is never reached.
      const r = await putFile("!".repeat(1000), "text/plain", null);
      expect(r).toEqual({ ok: false, status: 413, message: "payload too large" });
      expect(atobSpy).not.toHaveBeenCalled();
    } finally {
      atobSpy.mockRestore();
    }
    const over = await putFile(btoa("x".repeat(config.maxBytes + 1)), "text/plain", null);
    expect(over).toEqual({ ok: false, status: 413, message: "payload too large" });
  });

  it("FIXED (F-24): stageFromUpstreamJson forwards only the declared requestOpts fields to the handler ctx", async () => {
    const seen: unknown[] = [];
    const cap = createStageFromUpstreamJsonCapability({
      putFile: async () => ({ ok: true, file_handle: "fh_x", token: "stg_x", fetch_url: "u", expires_at: 0, byte_length: 1 }),
      upstreamRequest: async (ctx) => { seen.push(ctx); return { success: true, status: 200, result: { data: "aGk=" } }; },
    });
    const opts = { method: "GET", path: "/w", headers: { "X-Extra": "1" }, returnAs: "stage", multipart: [], relatedRequestId: "rid-1" } as never;
    const r = await cap(opts, "data", "base64");
    expect(r.ok).toBe(true);
    const ctx = seen[0] as Record<string, unknown>;
    // Undeclared fields no longer ride through; only the declared ones plus
    // the capability's own bypassTruncate reach upstreamRequest.
    expect(ctx).toEqual({ method: "GET", path: "/w", bypassTruncate: true });
    expect(ctx).not.toHaveProperty("headers");
    expect(ctx).not.toHaveProperty("returnAs");
    expect(ctx).not.toHaveProperty("multipart");
    expect(ctx).not.toHaveProperty("relatedRequestId");
  });
});
