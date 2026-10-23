// Unit tests for the Xero staging ladder's pure parts and its run logic
// against fake dependencies (issue #59). The ladder itself runs against a live
// xero-dev deployment and so is never run in CI.
//
// Run: node --import tsx --test scripts/harnesses/xero-ladder.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { LadderDeps, Row } from "./staging-ladder.ts";
import {
  DEFAULT_RUNG_BYTES,
  LADDER_ATTACHMENT_NAME,
  LADDER_INVOICE_REFERENCE,
  assertXeroCodeSafe,
  attachCode,
  classifyUpload,
  expectationFor,
  fileDeleteCode,
  filesUploadCode,
  formatXeroRow,
  ladderBytes,
  ladderFileName,
  parseXeroArgs,
  runXeroLadder,
  setupInvoiceCode,
  stageAttachmentDownloadCode,
  stageFileDownloadCode,
} from "./xero-ladder.ts";

const MIB = 1_048_576;
const REF = { file_handle: "fh_abcdef123456", token: "stg_secretsecret" };

// ---------------------------------------------------------------------------
// Rungs and expectations
// ---------------------------------------------------------------------------

test("default rungs: 1 MiB, 4 MiB, under, at and past the measured 10,240,000 B request ceiling, and 10 MiB + 1", () => {
  assert.deepEqual([...DEFAULT_RUNG_BYTES], [MIB, 4 * MIB, 10_000_000, 10_239_999, 10_240_000, 10 * MIB + 1]);
});

test("expectationFor: attachments take a body up to 10,239,999 B; Files lose ~1 KiB to multipart overhead", () => {
  assert.equal(expectationFor(MIB, "attachment"), "accept");
  assert.equal(expectationFor(10_239_999, "attachment"), "accept");
  assert.equal(expectationFor(10_240_000, "attachment"), "reject");
  assert.equal(expectationFor(10_238_999, "files"), "accept");
  assert.equal(expectationFor(10_239_000, "files"), "either");
  assert.equal(expectationFor(10_239_999, "files"), "either");
  assert.equal(expectationFor(10_240_000, "files"), "reject");
  assert.equal(expectationFor(10 * MIB + 1, "files"), "reject");
});

test("ladderBytes: exactly n bytes of printable ASCII (Xero refuses .bin; the ladder sends .txt)", () => {
  for (const n of [1, 3, 4, 1000, MIB + 1]) {
    const b = ladderBytes(n);
    assert.equal(b.byteLength, n);
    assert.ok(b.every((c) => c >= 0x20 && c < 0x7f), `non-printable byte at n=${n}`);
  }
  assert.notDeepEqual(ladderBytes(64), ladderBytes(64));
});

test("names: Files uploads are named per size; every rung overwrites ONE invoice attachment name (Xero caps a document at 10)", () => {
  assert.equal(LADDER_ATTACHMENT_NAME, "codemode-ladder.txt");
  assert.equal(ladderFileName(10_000_000), "codemode-ladder-10000000.txt");
});

// ---------------------------------------------------------------------------
// classifyUpload
// ---------------------------------------------------------------------------

test("classifyUpload: accept rung passes only when Xero accepted", () => {
  assert.equal(classifyUpload("accept", { ok: true, status: 200 }).ok, true);
  const r = classifyUpload("accept", { ok: false, status: 413, error: "too big" });
  assert.equal(r.ok, false);
  assert.match(r.detail, /413/);
  assert.match(r.detail, /too big/);
});

test("classifyUpload: reject rung passes on a clean 4xx and records the error verbatim", () => {
  const r = classifyUpload("reject", { ok: false, status: 413, error: "Request Entity Too Large" });
  assert.equal(r.ok, true);
  assert.match(r.detail, /rejected: status=413 Request Entity Too Large/);
});

test("classifyUpload: reject rung FAILS when Xero accepted past the limit", () => {
  const r = classifyUpload("reject", { ok: true, status: 200 });
  assert.equal(r.ok, false);
  assert.match(r.detail, /ACCEPTED/);
});

test("classifyUpload: a 5xx, a timeout or a thrown error is never a clean rejection", () => {
  assert.equal(classifyUpload("reject", { ok: false, status: 502, error: "bad gateway" }).ok, false);
  assert.equal(classifyUpload("either", { ok: false, thrown: "execute timed out after 180000 ms" }).ok, false);
  assert.equal(classifyUpload("either", { ok: false, status: 500 }).ok, false);
});

test("classifyUpload: a host refusal thrown as a ToolError (not a timeout) counts as a clean rejection", () => {
  const r = classifyUpload("reject", { ok: false, thrown: "composed-too-large: body exceeds 10485760 bytes" });
  assert.equal(r.ok, true);
  assert.match(r.detail, /composed-too-large/);
});

test("classifyUpload: the upstream closing the connection mid-body counts as a clean rejection", () => {
  const thrown =
    "staged transfer failed: upstream closed the connection after 13631488 of 25000000 bytes were sent; the upstream request was aborted";
  const r = classifyUpload("reject", { ok: false, thrown });
  assert.equal(r.ok, true);
  assert.match(r.detail, /upstream closed the connection after 13631488 of 25000000 bytes/);
  assert.equal(classifyUpload("accept", { ok: false, thrown }).ok, false);
});

test("classifyUpload: other aborted transfers are still not clean", () => {
  assert.equal(classifyUpload("reject", { ok: false, thrown: "staged transfer aborted" }).ok, false);
  assert.equal(
    classifyUpload("reject", { ok: false, thrown: "staged transfer failed: a staged file could not be read; the upstream request was aborted" }).ok,
    false,
  );
});

test("classifyUpload: either rung passes on acceptance or a clean rejection", () => {
  assert.equal(classifyUpload("either", { ok: true, status: 200 }).ok, true);
  assert.equal(classifyUpload("either", { ok: false, status: 400, error: "x" }).ok, true);
});

// ---------------------------------------------------------------------------
// Code builders
// ---------------------------------------------------------------------------

test("attachCode: composed identity POST to the by-filename attachment path, no rawBody", () => {
  const code = attachCode("inv-1", "codemode-ladder-1.bin", REF);
  assert.match(code, /method: "POST"/);
  assert.ok(code.includes('"/api.xro/2.0/Invoices/inv-1/Attachments/codemode-ladder-1.bin"'));
  assert.match(code, /encoding: "identity"/);
  assert.ok(code.includes(JSON.stringify(REF)));
  assert.match(code, /contentType: "text\/plain"/);
  assert.doesNotMatch(code, /rawBody|bodyBase64/);
  assert.doesNotThrow(() => new Function(`return (${code})`));
});

test("filesUploadCode: multipart with Name plus one staged part, no contentType", () => {
  const code = filesUploadCode("codemode-ladder-1.bin", REF);
  assert.ok(code.includes('"/files.xro/1.0/Files"'));
  assert.match(code, /multipart: \[/);
  assert.match(code, /name: "Name", value: "codemode-ladder-1.bin"/);
  assert.ok(code.includes(`staged: ${JSON.stringify(REF)}`));
  assert.doesNotMatch(code, /contentType/);
  assert.doesNotThrow(() => new Function(`return (${code})`));
});

test("download builders: returnAs stage with an octet-stream Accept header", () => {
  const a = stageAttachmentDownloadCode("inv-1", "codemode-ladder-1.bin");
  assert.ok(a.includes('"/api.xro/2.0/Invoices/inv-1/Attachments/codemode-ladder-1.bin"'));
  const f = stageFileDownloadCode("file-9");
  assert.ok(f.includes('"/files.xro/1.0/Files/file-9/Content"'));
  for (const code of [a, f]) {
    assert.match(code, /returnAs: "stage"/);
    assert.match(code, /Accept: "application\/octet-stream"/);
    assert.match(code, /method: "GET"/);
    assert.doesNotThrow(() => new Function(`return (${code})`));
  }
});

test("setupInvoiceCode: reuses a DRAFT invoice by Reference, creates one only as DRAFT", () => {
  const code = setupInvoiceCode();
  assert.ok(code.includes(LADDER_INVOICE_REFERENCE));
  assert.match(code, /Status: "DRAFT"/);
  assert.doesNotMatch(code, /AUTHORISED|SentToContact/);
  assert.doesNotThrow(() => assertXeroCodeSafe(code));
  assert.doesNotThrow(() => new Function(`return (${code})`));
});

test("fileDeleteCode: DELETE on the Files API file path", () => {
  const code = fileDeleteCode("file-9");
  assert.match(code, /method: "DELETE"/);
  assert.ok(code.includes('"/files.xro/1.0/Files/file-9"'));
});

test("path segments are URL-encoded", () => {
  assert.ok(attachCode("a/b", "x y.bin", REF).includes('"/api.xro/2.0/Invoices/a%2Fb/Attachments/x%20y.bin"'));
});

// ---------------------------------------------------------------------------
// Safety guard
// ---------------------------------------------------------------------------

test("assertXeroCodeSafe refuses status transitions, emailing and payments", () => {
  for (const bad of [
    'body: { Status: "AUTHORISED" }',
    'body: { Status: "VOIDED" }',
    'body: { Status: "DELETED" }',
    "body: { SentToContact: true }",
    'path: "/api.xro/2.0/Invoices/x/Email"',
    'path: "/api.xro/2.0/Payments"',
  ]) {
    assert.throws(() => assertXeroCodeSafe(`async () => codemode.request({ ${bad} })`), /refuses/, bad);
  }
  for (const code of [
    attachCode("i", "n.bin", REF),
    filesUploadCode("n.bin", REF),
    stageAttachmentDownloadCode("i", "n.bin"),
    stageFileDownloadCode("f"),
    fileDeleteCode("f"),
  ]) {
    assert.doesNotThrow(() => assertXeroCodeSafe(code));
  }
});

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

test("formatXeroRow masks staging tokens and file handles", () => {
  const line = formatXeroRow({ size: "1 MiB", path: "p", ms: 5, ok: false, detail: `${REF.token} ${REF.file_handle}` });
  assert.doesNotMatch(line, /secretsecret|abcdef123456/);
  assert.match(line, /stg_…/);
  assert.match(line, /fh_…/);
  assert.match(line, /FAIL/);
});

// ---------------------------------------------------------------------------
// parseXeroArgs
// ---------------------------------------------------------------------------

test("parseXeroArgs: target is required and trailing slash is trimmed", () => {
  assert.throws(() => parseXeroArgs([]), /--target is required/);
  const a = parseXeroArgs(["--target=https://xero-dev.example.workers.dev/"]);
  assert.equal(a.target, "https://xero-dev.example.workers.dev");
  assert.deepEqual(a.bytes, [...DEFAULT_RUNG_BYTES]);
  assert.equal(a.attachments, true);
  assert.equal(a.files, true);
});

test("parseXeroArgs: --bytes, --only=files|attachments, --execute-timeout-ms", () => {
  const a = parseXeroArgs(["--target=https://x.dev", "--bytes=1024,26214400", "--only=files", "--execute-timeout-ms=5000"]);
  assert.deepEqual(a.bytes, [1024, 26_214_400]);
  assert.equal(a.attachments, false);
  assert.equal(a.files, true);
  assert.equal(a.executeTimeoutMs, 5000);
  assert.throws(() => parseXeroArgs(["--target=https://x.dev", "--bytes=0"]), /--bytes/);
  assert.throws(() => parseXeroArgs(["--target=https://x.dev", "--bytes=52428801"]), /--bytes/);
  assert.throws(() => parseXeroArgs(["--target=https://x.dev", "--only=both"]), /--only/);
  assert.throws(() => parseXeroArgs(["--target=https://x.dev", "--nope"]), /Unrecognised/);
});

// ---------------------------------------------------------------------------
// runXeroLadder against fakes
// ---------------------------------------------------------------------------

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

interface FakeOpts {
  /** Largest byte count Xero accepts for each target. */
  attachLimit?: number;
  filesLimit?: number;
  corruptDownload?: boolean;
  deleteDenied?: boolean;
  setupFails?: boolean;
}

/** A fake server: stores uploads by handle, answers the ladder's execute
 *  codes by pattern, and serves staged downloads back by fetch_url. */
function fakeDeps(opts: FakeOpts = {}) {
  const attachLimit = opts.attachLimit ?? 10 * MIB;
  const filesLimit = opts.filesLimit ?? 10 * MIB;
  const staged = new Map<string, Uint8Array>(); // handle → bytes
  const xero = new Map<string, Uint8Array>(); // attachment name / file id → bytes
  const codes: string[] = [];
  let n = 0;
  const text = (v: unknown, isError = false): CallToolResult => ({
    content: [{ type: "text", text: JSON.stringify(v) }],
    ...(isError ? { isError: true } : {}),
  });
  const stage = (bytes: Uint8Array) => {
    const h = `fh_dl${++n}`;
    staged.set(h, bytes);
    return { ok: true, status: 200, fetch_url: `https://x.dev/staging/fetch/${h}`, token: `stg_dl${n}`, byte_length: bytes.byteLength };
  };
  const deps: LadderDeps = {
    async callTool(name, args) {
      if (name === "register_file_handle") {
        const h = `fh_up${++n}`;
        return text({ upload_url: `https://x.dev/staging/upload/${h}`, token: `stg_up${n}`, file_handle: h });
      }
      const code = String(args.code);
      codes.push(code);
      if (code.includes("LADDER_SETUP")) {
        return opts.setupFails ? text({ ok: false, status: 401, error: "unauthorised" }) : text({ ok: true, invoiceId: "inv-1", reused: true });
      }
      const handle = /"file_handle":"(fh_up\d+)"/.exec(code)?.[1];
      if (code.includes("/Attachments/") && code.includes("composed")) {
        const b = staged.get(handle!)!;
        const name = /Attachments\/([^"]+)"/.exec(code)![1]!;
        if (b.byteLength > attachLimit) return text({ ok: false, status: 413, error: "Request Entity Too Large" });
        xero.set(name, b);
        return text({ ok: true, status: 200, attachmentId: "att-1", contentLength: b.byteLength });
      }
      if (code.includes("multipart")) {
        const b = staged.get(handle!)!;
        if (b.byteLength > filesLimit) return text({ ok: false, status: 413, error: "too large" });
        const id = `file-${++n}`;
        xero.set(id, b);
        return text({ ok: true, status: 201, fileId: id, size: b.byteLength });
      }
      if (code.includes('returnAs: "stage"')) {
        const key = /Attachments\/([^"]+)"/.exec(code)?.[1] ?? /Files\/([^/"]+)\/Content/.exec(code)![1]!;
        const b = xero.get(key)!;
        return text(stage(opts.corruptDownload ? b.subarray(1) : b));
      }
      if (code.includes('method: "DELETE"')) {
        if (opts.deleteDenied ?? true) {
          return text({ ok: false, thrown: "Operation xero.files.deleteFile not in surface review" });
        }
        return text({ ok: true, status: 204 });
      }
      throw new Error(`fake: unexpected code ${code.slice(0, 80)}`);
    },
    fetch: (async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      const h = u.slice(u.lastIndexOf("/") + 1);
      if (u.includes("/staging/upload/")) {
        staged.set(h, new Uint8Array(init!.body as Uint8Array));
        return new Response(null, { status: 204 });
      }
      return new Response(staged.get(h)!, { status: 200 });
    }) as typeof fetch,
    fetchTimeoutMs: () => 1000,
    executeTimeoutMs: () => 1000,
  };
  return { deps, codes };
}

const plan = (bytes: number[]) => ({ bytes, attachments: true, files: true });

test("runXeroLadder: an accepted rung uploads, attaches, files, round-trips both by sha256 and tries cleanup", async () => {
  const { deps, codes } = fakeDeps();
  const rows: Row[] = [];
  await runXeroLadder(deps, plan([1024]), rows);
  const paths = rows.map((r) => r.path);
  assert.deepEqual(paths, [
    "setup ladder invoice",
    "upload",
    "invoice attachment (composed identity)",
    "attachment → stage → fetch (sha256)",
    "files.uploadFile (multipart staged)",
    "file → stage → fetch (sha256)",
    "files.deleteFile (cleanup)",
  ]);
  assert.ok(rows.every((r) => r.ok), JSON.stringify(rows));
  assert.match(rows.at(-1)!.detail, /left in the Files Inbox/);
  assert.ok(codes.some((c) => c.includes("/Attachments/codemode-ladder.txt\"")), "attachment uses the fixed name");
  for (const c of codes) assert.doesNotThrow(() => assertXeroCodeSafe(c));
});

test("runXeroLadder: a rung past the limit passes on a clean rejection and skips its download", async () => {
  const { deps } = fakeDeps({ attachLimit: 10 * MIB, filesLimit: 10 * MIB });
  const rows: Row[] = [];
  await runXeroLadder(deps, plan([10 * MIB + 1]), rows);
  assert.deepEqual(rows.map((r) => r.path), [
    "setup ladder invoice",
    "upload",
    "invoice attachment (composed identity)",
    "files.uploadFile (multipart staged)",
  ]);
  assert.ok(rows.every((r) => r.ok), JSON.stringify(rows));
  assert.match(rows[2]!.detail, /413 Request Entity Too Large/);
});

test("runXeroLadder: a sha256 mismatch on download fails that row", async () => {
  const { deps } = fakeDeps({ corruptDownload: true });
  const rows: Row[] = [];
  await runXeroLadder(deps, { bytes: [2048], attachments: true, files: false }, rows);
  const dl = rows.find((r) => r.path === "attachment → stage → fetch (sha256)")!;
  assert.equal(dl.ok, false);
  assert.match(dl.detail, /hash mismatch/);
});

test("runXeroLadder: a deleted file reports deleted", async () => {
  const { deps } = fakeDeps({ deleteDenied: false });
  const rows: Row[] = [];
  await runXeroLadder(deps, { bytes: [512], attachments: false, files: true }, rows);
  const del = rows.at(-1)!;
  assert.equal(del.path, "files.deleteFile (cleanup)");
  assert.equal(del.ok, true);
  assert.match(del.detail, /deleted/);
});

test("runXeroLadder: a failed invoice setup fails its row and skips attachments but still runs Files", async () => {
  const { deps } = fakeDeps({ setupFails: true });
  const rows: Row[] = [];
  await runXeroLadder(deps, plan([256]), rows);
  assert.equal(rows[0]!.ok, false);
  assert.ok(!rows.some((r) => r.path.startsWith("invoice attachment")));
  assert.ok(rows.some((r) => r.path.startsWith("files.uploadFile") && r.ok));
});

test("runXeroLadder: rows stream to the sink as they land", async () => {
  const { deps } = fakeDeps();
  const seen: string[] = [];
  await runXeroLadder(deps, plan([128]), { push: (r: Row) => seen.push(r.path) });
  assert.equal(seen[0], "setup ladder invoice");
  assert.ok(seen.length >= 6);
});

test("runXeroLadder: an execute that throws fails its row with the elapsed time and the run continues", async () => {
  const { deps } = fakeDeps();
  const base = deps.callTool;
  deps.callTool = async (name, args, t) => {
    if (name === "execute" && String(args.code).includes("multipart")) throw new Error(`timeout with ${REF.token}`);
    return base(name, args, t);
  };
  const rows: Row[] = [];
  await runXeroLadder(deps, plan([64, 96]), rows);
  const files = rows.filter((r) => r.path === "files.uploadFile (multipart staged)");
  assert.equal(files.length, 2);
  assert.ok(files.every((r) => !r.ok));
  assert.doesNotMatch(files[0]!.detail, /secretsecret/);
});
