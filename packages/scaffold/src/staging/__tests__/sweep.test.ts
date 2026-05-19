import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { runSweep } from "../sweep";
import { insertPending, lookupByHash } from "../repo";

describe("runSweep", () => {
  it("deletes expired rows and their R2 objects", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const expiredHash = new Uint8Array(32).fill(1);
    const freshHash = new Uint8Array(32).fill(2);

    await insertPending(d1 as unknown as D1Database, {
      token_hash: expiredHash, file_handle: "fh_old", content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 200,
    });
    await insertPending(d1 as unknown as D1Database, {
      token_hash: freshHash, file_handle: "fh_new", content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 9999,
    });
    // Pretend the expired row had been claimed with an R2 object:
    const stored = d1.rows.get(Array.from(expiredHash).map((x) => x.toString(16).padStart(2, "0")).join(""))!;
    stored.r2_key = "stg/old-key";
    stored.state = "claimed";
    r2.store.set("stg/old-key", new Uint8Array([0xff]));

    const summary = await runSweep({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, now: () => 1000,
    });
    expect(summary.deletedRows).toBe(1);
    expect(summary.deletedObjects).toBe(1);
    expect(r2.store.has("stg/old-key")).toBe(false);
    expect(await lookupByHash(d1 as unknown as D1Database, expiredHash)).toBeNull();
    expect(await lookupByHash(d1 as unknown as D1Database, freshHash)).not.toBeNull();
  });

  it("skips R2 delete when r2_key is null (row never reached claim)", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: new Uint8Array(32).fill(3), file_handle: "fh_dead", content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 200,
    });
    const summary = await runSweep({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, now: () => 1000,
    });
    expect(summary.deletedRows).toBe(1);
    expect(summary.deletedObjects).toBe(0);
  });

  it("returns zeros when nothing is expired", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: new Uint8Array(32).fill(4), file_handle: "fh_live", content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: 100, expires_at: 9999,
    });
    const summary = await runSweep({
      STAGING_D1: d1 as unknown as D1Database, STAGING_R2: r2 as unknown as R2Bucket, now: () => 1000,
    });
    expect(summary).toEqual({ deletedRows: 0, deletedObjects: 0 });
  });
});
