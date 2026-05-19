import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import {
  insertPending,
  insertClaimed,
  atomicClaim,
  lookupByHash,
  markCorrupt,
  listExpired,
  deleteByHash,
} from "../repo";

const TOKEN_HASH = new Uint8Array(32).fill(7);
const TOKEN_HASH_2 = new Uint8Array(32).fill(8);
const HANDLE = "fh_AAAAAAAAAAAAAAAAAAAAAA";  // 16 bytes of 0x00 base64url

describe("insertPending", () => {
  it("creates a row with state='pending'", async () => {
    const d1 = new FakeD1();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH,
      file_handle: HANDLE,
      content_type_hint: "image/png",
      expected_byte_len: 1024,
      filename: "x.png",
      created_at: 100,
      expires_at: 400,
    });
    const row = await lookupByHash(d1 as unknown as D1Database, TOKEN_HASH);
    expect(row).not.toBeNull();
    expect(row!.state).toBe("pending");
    expect(row!.file_handle).toBe(HANDLE);
    expect(row!.content_type_hint).toBe("image/png");
  });

  it("rejects duplicate token_hash", async () => {
    const d1 = new FakeD1();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH,
      file_handle: HANDLE,
      content_type_hint: null,
      expected_byte_len: null,
      filename: null,
      created_at: 100,
      expires_at: 400,
    });
    await expect(insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH,
      file_handle: HANDLE,
      content_type_hint: null,
      expected_byte_len: null,
      filename: null,
      created_at: 100,
      expires_at: 400,
    })).rejects.toThrow(/UNIQUE/);
  });
});

describe("atomicClaim", () => {
  it("succeeds once and only once when row is pending and not expired", async () => {
    const d1 = new FakeD1();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, file_handle: HANDLE, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 400,
    });
    const r1 = await atomicClaim(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, iv: new Uint8Array(12).fill(1),
      content_type: "application/octet-stream", byte_len: 5, r2_key: "abc",
      claimed_at: 200, new_expires_at: 200 + 3600, now: 200,
    });
    expect(r1).toEqual({ file_handle: HANDLE });
    const r2 = await atomicClaim(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, iv: new Uint8Array(12).fill(2),
      content_type: "application/octet-stream", byte_len: 5, r2_key: "def",
      claimed_at: 250, new_expires_at: 250 + 3600, now: 250,
    });
    expect(r2).toBeNull();
  });

  it("returns null when expired", async () => {
    const d1 = new FakeD1();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, file_handle: HANDLE, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 200,
    });
    const r = await atomicClaim(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, iv: new Uint8Array(12), content_type: "x",
      byte_len: 1, r2_key: "k", claimed_at: 300, new_expires_at: 3900, now: 300,
    });
    expect(r).toBeNull();
  });

  it("returns null when no such row", async () => {
    const d1 = new FakeD1();
    const r = await atomicClaim(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, iv: new Uint8Array(12), content_type: "x",
      byte_len: 1, r2_key: "k", claimed_at: 300, new_expires_at: 3900, now: 300,
    });
    expect(r).toBeNull();
  });
});

describe("markCorrupt", () => {
  it("flips state to corrupt", async () => {
    const d1 = new FakeD1();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, file_handle: HANDLE, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 400,
    });
    await markCorrupt(d1 as unknown as D1Database, TOKEN_HASH);
    const row = await lookupByHash(d1 as unknown as D1Database, TOKEN_HASH);
    expect(row!.state).toBe("corrupt");
  });
});

describe("lookupByHash BLOB coercion", () => {
  // Real D1 (under some compat configurations) returns BLOB columns as
  // `Array<number>` rather than `Uint8Array`. WebCrypto then rejects the iv
  // with "Incorrect type for the 'iv' field … not of type 'JsBufferSource'".
  // This test simulates that return shape and confirms repo normalizes to
  // Uint8Array at the boundary.
  it("coerces Array<number> BLOBs into Uint8Array", async () => {
    const ivArray = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8];
    const tokenHashArray = new Array(32).fill(7);
    const fakeRow = {
      token_hash: tokenHashArray,
      file_handle: HANDLE,
      state: "claimed" as const,
      r2_key: "stg/abc",
      iv: ivArray,
      content_type_hint: null,
      content_type: "application/octet-stream",
      expected_byte_len: null,
      byte_len: 1024,
      filename: null,
      created_at: 100,
      claimed_at: 110,
      expires_at: 3700,
    };
    const fake: unknown = {
      prepare: () => ({
        bind: () => ({
          first: async () => fakeRow,
        }),
      }),
    };
    const row = await lookupByHash(fake as D1Database, TOKEN_HASH);
    expect(row).not.toBeNull();
    expect(row!.iv).toBeInstanceOf(Uint8Array);
    expect(row!.iv!.byteLength).toBe(12);
    expect(Array.from(row!.iv!)).toEqual(ivArray);
    expect(row!.token_hash).toBeInstanceOf(Uint8Array);
    expect(row!.token_hash.byteLength).toBe(32);
  });
});

describe("listExpired + deleteByHash", () => {
  it("lists rows with expires_at < cutoff and removes by hash", async () => {
    const d1 = new FakeD1();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, file_handle: HANDLE, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 200,
    });
    await insertPending(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH_2, file_handle: "fh_zz", content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 9999,
    });
    const expired = await listExpired(d1 as unknown as D1Database, 300);
    expect(expired).toHaveLength(1);
    expect(Buffer.from(expired[0]!.token_hash).equals(Buffer.from(TOKEN_HASH))).toBe(true);
    await deleteByHash(d1 as unknown as D1Database, TOKEN_HASH);
    expect(await lookupByHash(d1 as unknown as D1Database, TOKEN_HASH)).toBeNull();
    expect(await lookupByHash(d1 as unknown as D1Database, TOKEN_HASH_2)).not.toBeNull();
  });
});

describe("insertClaimed", () => {
  it("inserts a fully-populated row in state='claimed'", async () => {
    const d1 = new FakeD1();
    const iv = new Uint8Array(12).fill(9);
    await insertClaimed(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH,
      file_handle: HANDLE,
      r2_key: "stg/abcd",
      iv,
      content_type: "image/png",
      byte_len: 1024,
      filename: "x.png",
      created_at: 100,
      claimed_at: 100,
      expires_at: 100 + 3600,
    });
    const row = await lookupByHash(d1 as unknown as D1Database, TOKEN_HASH);
    expect(row).not.toBeNull();
    expect(row!.state).toBe("claimed");
    expect(row!.file_handle).toBe(HANDLE);
    expect(row!.r2_key).toBe("stg/abcd");
    expect(Array.from(row!.iv!)).toEqual(Array.from(iv));
    expect(row!.content_type).toBe("image/png");
    expect(row!.byte_len).toBe(1024);
    expect(row!.filename).toBe("x.png");
    expect(row!.created_at).toBe(100);
    expect(row!.claimed_at).toBe(100);
    expect(row!.expires_at).toBe(100 + 3600);
    expect(row!.content_type_hint).toBeNull();
    expect(row!.expected_byte_len).toBeNull();
  });

  it("rejects duplicate token_hash", async () => {
    const d1 = new FakeD1();
    const iv = new Uint8Array(12);
    await insertClaimed(d1 as unknown as D1Database, {
      token_hash: TOKEN_HASH, file_handle: HANDLE, r2_key: "stg/a", iv,
      content_type: "application/octet-stream", byte_len: 0, filename: null,
      created_at: 1, claimed_at: 1, expires_at: 3601,
    });
    await expect(
      insertClaimed(d1 as unknown as D1Database, {
        token_hash: TOKEN_HASH, file_handle: "fh_zz", r2_key: "stg/b", iv,
        content_type: "application/octet-stream", byte_len: 0, filename: null,
        created_at: 2, claimed_at: 2, expires_at: 3602,
      }),
    ).rejects.toThrow(/UNIQUE/);
  });
});
