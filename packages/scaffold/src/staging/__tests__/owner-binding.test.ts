// E-1 (2026-11 review), reduced scope: staged files bound to the principal that created them.
//
// Attacker: user B, an authenticated MCP user of the same deployment, who has learnt user A's
// `{ file_handle, token }` pair (a shared chat, a log, a pasted fetch_url).
// Precondition: A staged a file (putFile / register_file_handle + upload).
// Payload: B's session calls `getFile(A.handle, A.token)` or attaches the pair to a
// `composed` / `multipart[].staged` send (both resolve through `openStagedFile`).
// Control: every staging row carries `owner` (the audit principal, `principalOf`), every
// in-MCP reader requires `row.owner === deps.owner`, and rows without an owner (written before
// migration 0003) are refused by every reader (no shim).
// Why the pre-fix code failed: the row had no owner column at all; the token was the only
// check, so any session holding the pair read or sent A's bytes.

import { describe, it, expect } from "vitest";
import { FakeD1 } from "./__fixtures__/fake-d1";
import { FakeR2 } from "./__fixtures__/fake-r2";
import { createPutFileCapability } from "../putfile-capability";
import { createGetFileCapability } from "../getfile-capability";
import { createStagedFileOpener, openStagedFile } from "../staged-file";
import { handleFetch } from "../fetch-handler";
import { fileRefOf } from "../crypto";
import { insertPending, lookupByHash } from "../repo";
import { sha256Bearer } from "../crypto";
import { mintFileHandle, mintToken } from "../tokens";
import type { StagingConfig } from "../types";
import type { AuditSink } from "../../audit";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 1024 * 1024 };
const NOW = 1_000_000;
const SECRET = new TextEncoder().encode("A's payroll export");
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const base = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    now: () => NOW + 1,
  };
  const putFileAs = (owner: string) => createPutFileCapability({ ...base, owner, uploadOrigin: "https://w" });
  return { d1, r2, base, putFileAs };
}

async function stagedByA() {
  const w = world();
  const out = await w.putFileAs("user-A")(b64(SECRET), "text/csv", "pay.csv");
  if (!out.ok) throw new Error("stage failed");
  return { ...w, out };
}

describe("staged-file ownership (E-1)", () => {
  it("FIXED (E-1): the stored row carries owner = the staging principal, fetch_count 0; putFile returns its file_ref", async () => {
    const { d1, out } = await stagedByA();
    const row = await lookupByHash(d1 as unknown as D1Database, await sha256Bearer(out.token));
    expect(Object.keys(row!)).toContain("owner");
    expect(row!.owner).toBe("user-A");
    expect(row!.fetch_count).toBe(0);
    expect(out.file_ref).toBe(await fileRefOf(out.file_handle));
    expect(out.file_ref).toMatch(/^[0-9a-f]{12}$/);
  });

  it("FIXED (E-1): B's opener refuses A's pair with the wrong-token 403 text; no R2 read", async () => {
    const { r2, base, out } = await stagedByA();
    const gets = r2.getCalls;
    const r = await createStagedFileOpener({ ...base, owner: "user-B" })({ file_handle: out.file_handle, token: out.token });
    expect(r).toEqual({ ok: false, status: 403, message: "file not found or not yours" });
    expect(r2.getCalls).toBe(gets);
  });

  it("REFUTED: A's own opener reads its file, repeatedly (in-MCP reuse is unchanged)", async () => {
    const { base, out } = await stagedByA();
    const open = createStagedFileOpener({ ...base, owner: "user-A" });
    for (let i = 0; i < 2; i++) {
      const r = await open({ file_handle: out.file_handle, token: out.token });
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.file.meta.fileRef).toBe(out.file_ref);
    }
  });

  it("FIXED (E-1): B's getFile(A.handle, A.token) → 403, no R2 read, a staging.read deny line", async () => {
    const { r2, base, out } = await stagedByA();
    const lines: Parameters<AuditSink>[0][] = [];
    const getFile = createGetFileCapability({ ...base, owner: "user-B", audit: (e) => { lines.push(e); } });
    const gets = r2.getCalls;
    const r = await getFile(out.file_handle, out.token);
    expect(r).toEqual({ ok: false, status: 403, message: "file not found or not yours" });
    expect(r2.getCalls).toBe(gets);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      method: "HOST", path: "__stagingHost.getFile", operationId: "staging.read",
      decision: "deny", reason: "staging-refused", staging: { event: "read", status: 403 },
    });
    // A non-owner's line never carries the file's digest: it would confirm the pair is valid.
    expect(lines[0]!.staging).not.toHaveProperty("fileRef");
  });

  it("the owner check precedes state: B on A's pending upload slot gets 403, not 409", async () => {
    const d1 = new FakeD1();
    const token = mintToken();
    const handle = mintFileHandle();
    await insertPending(d1 as unknown as D1Database, {
      token_hash: await sha256Bearer(token), file_handle: handle, content_type_hint: null,
      expected_byte_len: null, filename: null, created_at: NOW, expires_at: NOW + 300, owner: "user-A",
    });
    const deps = { STAGING_D1: d1 as unknown as D1Database, STAGING_R2: new FakeR2() as unknown as R2Bucket, config: CFG, now: () => NOW + 1 };
    expect(await openStagedFile({ ...deps, owner: "user-B" }, { file_handle: handle, token })).toMatchObject({ status: 403 });
    expect(await openStagedFile({ ...deps, owner: "user-A" }, { file_handle: handle, token })).toMatchObject({ status: 409 });
  });

  describe("FIXED (E-1): a legacy row (no owner, pre-0003 shape) is refused by every reader before any R2 read", () => {
    async function legacy() {
      const s = await stagedByA();
      [...s.d1.rows.values()][0]!.owner = null;
      return s;
    }

    it("openStagedFile, for any principal", async () => {
      const { r2, base, out } = await legacy();
      const gets = r2.getCalls;
      for (const owner of ["user-A", "user-B", ""]) {
        const r = await openStagedFile({ ...base, owner }, { file_handle: out.file_handle, token: out.token });
        expect(r).toEqual({ ok: false, status: 403, message: "file not found or not yours" });
      }
      expect(r2.getCalls).toBe(gets);
    });

    it("getFile", async () => {
      const { r2, base, out } = await legacy();
      const gets = r2.getCalls;
      const r = await createGetFileCapability({ ...base, owner: "user-A" })(out.file_handle, out.token);
      expect(r).toMatchObject({ ok: false, status: 403 });
      expect(r2.getCalls).toBe(gets);
    });

    it("the public fetch (bare forbidden)", async () => {
      const { r2, base, out } = await legacy();
      const gets = r2.getCalls;
      const res = await handleFetch(
        new Request(out.fetch_url, { headers: { Authorization: `Bearer ${out.token}` } }),
        base,
      );
      expect(res.status).toBe(403);
      expect(await res.text()).toBe("forbidden");
      expect(r2.getCalls).toBe(gets);
    });
  });

  it("the owner keeps in-MCP access after the public download limit is used up", async () => {
    const { base: b, out } = await stagedByA();
    const base = { ...b, config: { ...CFG, fetchMaxUses: 2 } };
    for (let i = 0; i < 2; i++) {
      const res = await handleFetch(new Request(out.fetch_url, { headers: { Authorization: `Bearer ${out.token}` } }), base);
      expect(res.status).toBe(200);
      await res.arrayBuffer();
    }
    const again = await handleFetch(new Request(out.fetch_url, { headers: { Authorization: `Bearer ${out.token}` } }), base);
    expect(again.status).toBe(410);
    const r = await createGetFileCapability({ ...base, owner: "user-A" })(out.file_handle, out.token);
    expect(r).toMatchObject({ ok: true, byteLength: SECRET.byteLength, bytesBase64: b64(SECRET) });
  });
});

// Review nit (E-1): an empty principal is not an owner. Two sessions whose principal is ""
// must not share files, and nothing may be stored or reserved under "".
describe("empty principal (E-1 defence in depth)", () => {
  it("putFile with owner \"\" is refused and stores nothing", async () => {
    const w = world();
    const out = await w.putFileAs("")(b64(SECRET), "text/csv", null);
    expect(out).toMatchObject({ ok: false, status: 403 });
    expect(w.d1.rows.size).toBe(0);
    expect(w.r2.store.size).toBe(0);
  });

  it("register_file_handle with owner \"\" throws and reserves nothing", async () => {
    const { registerFileHandleTool } = await import("../register-tool");
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({ owner: "", STAGING_D1: d1 as unknown as D1Database, config: CFG, uploadOrigin: "https://w" });
    await expect(tool.handler({})).rejects.toThrow(/principal/);
    expect(d1.rows.size).toBe(0);
  });

  it("a row whose owner is \"\" is refused by every reader, even to a caller whose principal is \"\"", async () => {
    const { r2, base, out } = await stagedByA();
    [...(base.STAGING_D1 as unknown as FakeD1).rows.values()][0]!.owner = "";
    const gets = r2.getCalls;
    for (const owner of ["", "user-A"]) {
      expect(await openStagedFile({ ...base, owner }, { file_handle: out.file_handle, token: out.token }))
        .toMatchObject({ ok: false, status: 403 });
      expect(await createGetFileCapability({ ...base, owner })(out.file_handle, out.token)).toMatchObject({ ok: false, status: 403 });
    }
    const lines: Parameters<AuditSink>[0][] = [];
    const res = await handleFetch(
      new Request(out.fetch_url, { headers: { Authorization: `Bearer ${out.token}` } }),
      { ...base, audit: (e) => { lines.push(e); } },
    );
    expect(res.status).toBe(403);
    expect(lines[0]).not.toHaveProperty("principalId");
    expect(r2.getCalls).toBe(gets);
  });
});
