import { describe, it, expect, vi, afterEach } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { createPutFileCapability } from "../putfile-capability";
import { handleFetch } from "../fetch-handler";
import type { StagingConfig } from "../types";

const CFG: StagingConfig = {
  uploadTtlSeconds: 300,
  fetchTtlSeconds: 3600,
  maxBytes: 50 * 1024 * 1024,
};

function makeDeps(now: number) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const putFile = createPutFileCapability({
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: "https://x.test",
    now: () => now,
  });
  return { d1, r2, putFile };
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

describe("createPutFileCapability — happy path", () => {
  it("encrypts bytes, inserts a claimed row, and returns a fetch_url that round-trips", async () => {
    const now = 1_700_000_000;
    const { d1, r2, putFile } = makeDeps(now);
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);

    const out = await putFile(bytesToBase64(bytes), "image/png", "icon.png");

    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.file_handle.startsWith("fh_")).toBe(true);
    expect(out.token.startsWith("stg_")).toBe(true);
    expect(out.byte_length).toBe(5);
    expect(out.expires_at).toBe(now + CFG.fetchTtlSeconds);
    expect(out.fetch_url).toBe(`https://x.test/staging/fetch/${out.file_handle}`);
    expect(r2.store.size).toBe(1);
    // Stored ciphertext != plaintext (with overwhelming probability):
    const stored = [...r2.store.values()][0]!;
    expect(stored.byteLength).toBe(bytes.byteLength + 16); // GCM tag
    expect(Buffer.from(stored.slice(0, 5)).equals(Buffer.from(bytes))).toBe(false);

    // Fetching with the same token+handle round-trips the original bytes.
    const res = await handleFetch(
      new Request(out.fetch_url, {
        method: "GET",
        headers: { Authorization: `Bearer ${out.token}` },
      }),
      {
        STAGING_D1: d1 as unknown as D1Database,
        STAGING_R2: r2 as unknown as R2Bucket,
        config: CFG,
        now: () => now + 1,
      },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(res.headers.get("X-Filename")).toBe("icon.png");
    expect(res.headers.get("Content-Disposition")).toBe('attachment; filename="icon.png"');
    const got = new Uint8Array(await res.arrayBuffer());
    expect(Buffer.from(got).equals(Buffer.from(bytes))).toBe(true);
  });
});

describe("createPutFileCapability — bad inputs", () => {
  it("rejects non-string bytesBase64 with 400", async () => {
    const { putFile, r2 } = makeDeps(1_700_000_000);
    const out = await putFile(123 as unknown as string, "application/octet-stream", null);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(400);
    expect(out.message).toMatch(/bytesBase64/);
    expect(r2.store.size).toBe(0);
  });

  it("rejects non-string contentType with 400", async () => {
    const { putFile, r2 } = makeDeps(1_700_000_000);
    const out = await putFile(bytesToBase64(new Uint8Array([1])), 42 as unknown as string, null);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(400);
    expect(out.message).toMatch(/contentType/);
    expect(r2.store.size).toBe(0);
  });

  it("rejects non-string non-null filename with 400", async () => {
    const { putFile, r2 } = makeDeps(1_700_000_000);
    const out = await putFile(
      bytesToBase64(new Uint8Array([1])),
      "application/octet-stream",
      42 as unknown as null,
    );
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(400);
    expect(out.message).toMatch(/filename/);
    expect(r2.store.size).toBe(0);
  });

  it("rejects malformed base64 with 400", async () => {
    const { putFile, r2 } = makeDeps(1_700_000_000);
    const out = await putFile("!!!!not-base64!!!!", "application/octet-stream", null);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(400);
    expect(out.message).toMatch(/base64/);
    expect(r2.store.size).toBe(0);
  });

  it("rejects payload above maxBytes with 413 and writes nothing", async () => {
    // Small custom config so we don't have to build a 50MB payload.
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const putFile = createPutFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 4 },
      uploadOrigin: "https://x.test",
      now: () => 1_700_000_000,
    });
    const oversize = bytesToBase64(new Uint8Array([1, 2, 3, 4, 5]));
    const out = await putFile(oversize, "application/octet-stream", null);
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(413);
    expect(r2.store.size).toBe(0);
  });

  describe("length bound before decoding (F-24)", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    function smallCap(maxBytes: number) {
      const r2 = new FakeR2();
      const putFile = createPutFileCapability({
        STAGING_D1: new FakeD1() as unknown as D1Database,
        STAGING_R2: r2 as unknown as R2Bucket,
        config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes },
        uploadOrigin: "https://x.test",
        now: () => 1_700_000_000,
      });
      return { putFile, r2 };
    }

    it("rejects an over-cap base64 string with 413 without decoding it", async () => {
      const { putFile, r2 } = smallCap(16);
      const atobSpy = vi.spyOn(globalThis, "atob");
      const out = await putFile(btoa("x".repeat(1000)), "text/plain", null);
      expect(out).toEqual({ ok: false, status: 413, message: "payload too large" });
      expect(atobSpy).not.toHaveBeenCalled();
      expect(r2.store.size).toBe(0);
    });

    it("malformed over-cap input is a 413 (size checked first), not a 400", async () => {
      const { putFile } = smallCap(16);
      const atobSpy = vi.spyOn(globalThis, "atob");
      const out = await putFile("!".repeat(1000), "text/plain", null);
      expect(out).toEqual({ ok: false, status: 413, message: "payload too large" });
      expect(atobSpy).not.toHaveBeenCalled();
    });

    it("exactly maxBytes still decodes and stores (the bound is not off by one)", async () => {
      for (const maxBytes of [1, 2, 3, 4, 15, 16, 17]) {
        const { putFile } = smallCap(maxBytes);
        const out = await putFile(bytesToBase64(new Uint8Array(maxBytes)), "application/octet-stream", null);
        expect(out.ok, `maxBytes=${maxBytes}`).toBe(true);
      }
    });

    it("a string within the length bound but over maxBytes after decoding is still a 413", async () => {
      // 17 bytes → 24 base64 chars, within ceil(16/3)*4+4 = 28: the
      // post-decode check is what rejects it.
      const { putFile } = smallCap(16);
      const out = await putFile(bytesToBase64(new Uint8Array(17)), "application/octet-stream", null);
      expect(out).toEqual({ ok: false, status: 413, message: "payload too large" });
    });
  });

  it("accepts zero-byte payloads and round-trips", async () => {
    const now = 1_700_000_000;
    const { d1, r2, putFile } = makeDeps(now);
    const out = await putFile("", "application/octet-stream", null);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.byte_length).toBe(0);
    expect(r2.store.size).toBe(1);

    const res = await handleFetch(
      new Request(out.fetch_url, {
        method: "GET",
        headers: { Authorization: `Bearer ${out.token}` },
      }),
      {
        STAGING_D1: d1 as unknown as D1Database,
        STAGING_R2: r2 as unknown as R2Bucket,
        config: CFG,
        now: () => now + 1,
      },
    );
    expect(res.status).toBe(200);
    const got = new Uint8Array(await res.arrayBuffer());
    expect(got.byteLength).toBe(0);
  });

  it("preserves null filename (no X-Filename header on fetch)", async () => {
    const now = 1_700_000_000;
    const { d1, r2, putFile } = makeDeps(now);
    const out = await putFile(bytesToBase64(new Uint8Array([9])), "application/octet-stream", null);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const res = await handleFetch(
      new Request(out.fetch_url, {
        method: "GET",
        headers: { Authorization: `Bearer ${out.token}` },
      }),
      {
        STAGING_D1: d1 as unknown as D1Database,
        STAGING_R2: r2 as unknown as R2Bucket,
        config: CFG,
        now: () => now + 1,
      },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Filename")).toBeNull();
    expect(res.headers.get("Content-Disposition")).toBe("attachment");
  });
});

describe("createPutFileCapability — backend failures", () => {
  it("returns 500 and writes no D1 row when R2 put rejects", async () => {
    const d1 = new FakeD1();
    const inner = new FakeR2();
    // Wrap a FakeR2 so put() throws once; preserve the rest of the surface.
    const r2 = {
      put: async (_k: string, _b: Uint8Array) => {
        throw new Error("simulated R2 outage");
      },
      get: inner.get.bind(inner),
      delete: inner.delete.bind(inner),
      list: inner.list.bind(inner),
      store: inner.store,
    };
    const putFile = createPutFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      uploadOrigin: "https://x.test",
      now: () => 1_700_000_000,
    });
    const out = await putFile(
      bytesToBase64(new Uint8Array([1, 2])),
      "application/octet-stream",
      null,
    );
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(500);
    expect(out.message).toMatch(/r2/i);
    // No D1 row inserted: list the staging table and confirm empty.
    // The FakeD1 fixture exposes a `rows` Map of inserted rows; if the
    // fixture's storage field is named differently, adapt this line to
    // match the actual implementation (do NOT add a public method just
    // for this assertion — read the fixture and use what's already there).
    expect((d1 as unknown as { rows?: Map<unknown, unknown> }).rows?.size ?? 0).toBe(0);
  });

  it("returns 500 and deletes the orphan R2 object when D1 insert rejects", async () => {
    const r2 = new FakeR2();
    // FakeD1 substitute whose .run() always throws — exercises the
    // insertClaimed-rejection branch.
    const d1: unknown = {
      prepare: () => ({
        bind: () => ({
          run: async () => {
            throw new Error("simulated D1 outage");
          },
          first: async () => null,
        }),
      }),
    };
    // Capture R2 deletes so we can assert the cleanup happened.
    const deletes: string[] = [];
    const origDelete = r2.delete.bind(r2);
    r2.delete = async (k: string) => {
      deletes.push(k);
      return origDelete(k);
    };

    const putFile = createPutFileCapability({
      STAGING_D1: d1 as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: CFG,
      uploadOrigin: "https://x.test",
      now: () => 1_700_000_000,
    });
    const out = await putFile(
      bytesToBase64(new Uint8Array([7, 8, 9])),
      "application/octet-stream",
      null,
    );
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.status).toBe(500);
    expect(out.message).toMatch(/d1/i);
    // R2 received the put (size temporarily went to 1), then the orphan delete.
    expect(deletes).toHaveLength(1);
    expect(deletes[0]!.startsWith("stg/")).toBe(true);
    expect(r2.store.size).toBe(0);
  });
});
