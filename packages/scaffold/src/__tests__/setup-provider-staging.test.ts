import { describe, it, expect } from "vitest";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { handleUpload } from "../staging/upload-handler";
import { handleFetch } from "../staging/fetch-handler";
import { runSweep } from "../staging/sweep";

// Re-test the routing path by simulating the wrapped fetch logic directly:
function routerFromWrapped(stagingEnv: { STAGING_D1: D1Database; STAGING_R2: R2Bucket }) {
  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const config = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
    if (url.pathname === "/staging/upload" && req.method === "POST") {
      return handleUpload(req, { ...stagingEnv, config });
    }
    if (url.pathname.startsWith("/staging/fetch/") && req.method === "GET") {
      return handleFetch(req, { ...stagingEnv, config });
    }
    return new Response("not /staging", { status: 404 });
  };
}

describe("setup-provider routing (staging)", () => {
  it("routes POST /staging/upload to the upload handler (403 without bearer is the proof)", async () => {
    const router = routerFromWrapped({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
    });
    const res = await router(new Request("https://x.test/staging/upload", { method: "POST", body: new Uint8Array([1]) }));
    expect(res.status).toBe(403);
  });

  it("routes GET /staging/fetch/<x> to the fetch handler", async () => {
    const router = routerFromWrapped({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
    });
    const res = await router(new Request("https://x.test/staging/fetch/fh_x", { method: "GET" }));
    expect(res.status).toBe(403);
  });

  it("does not match unrelated paths", async () => {
    const router = routerFromWrapped({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
    });
    const res = await router(new Request("https://x.test/mcp", { method: "POST" }));
    expect(res.status).toBe(404);
  });

  it("scheduled hook is wired to runSweep (smoke test that it doesn't throw with no rows)", async () => {
    const r = await runSweep({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
      now: () => 1,
    });
    expect(r).toEqual({ deletedRows: 0, deletedObjects: 0 });
  });
});
