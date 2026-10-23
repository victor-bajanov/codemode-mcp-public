// Unit tests for the staging ladder's pure parts (issue #59). The ladder runs
// against a live deployment and so is never run in CI; what CAN be proven
// offline is the property that matters most: the ladder is structurally
// unable to send email, apart from the two deliberately-denied probes, whose
// only recipient is undeliverable.
//
// Run: node --import tsx --test scripts/harnesses/staging-ladder.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  LADDER_DRAFT_SIZES_MIB,
  LADDER_ROUNDTRIP_SIZES_MIB,
  PROBE_RECIPIENT,
  assertLadderCodeSafe,
  base64LinesLength,
  classifyProbe,
  cleanupDraft,
  denialProbeCode,
  draftCreateCode,
  draftDeleteCode,
  draftGetCode,
  draftMime,
  draftSweepCode,
  redactSecrets,
  sizeEstimateClose,
  stageAttachmentCode,
  type Row,
  type LadderDeps,
  defaultExecuteTimeoutMs,
  defaultFetchTimeoutMs,
  parseLadderArgs,
  realDeps,
  runLadder,
} from "./staging-ladder.ts";
import { HARNESS_FETCH, callExecute, createHarnessTransport } from "./mcp-client.ts";
import { fetch as undiciFetch } from "undici";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

const REF = { file_handle: "fh_AAAAAAAAAAAAAAAAAAAAAA", token: "stg_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" };

const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (
  ...args: string[]
) => (...a: unknown[]) => Promise<unknown>;

type Responder = (o: Record<string, unknown>) => unknown;
const defaultResponder: Responder = () => ({ id: "d1", message: { id: "m1" } });

/** Evaluate an execute() code string (an async arrow) against a recording
 *  codemode.request, returning every options object it passed. */
async function record(code: string, respond: Responder = defaultResponder): Promise<Record<string, unknown>[]> {
  const calls: Record<string, unknown>[] = [];
  const codemode = {
    request: async (o: Record<string, unknown>) => {
      calls.push(o);
      return { success: true, status: 200, result: respond(o), errors: [] };
    },
  };
  const __stagingHost = {
    stageFromUpstreamJson: async (...a: unknown[]) => {
      calls.push({ stageFromUpstreamJson: a });
      return { ok: true };
    },
  };
  const fn = new AsyncFunction("codemode", "__stagingHost", `return await (${code})();`);
  await fn(codemode, __stagingHost);
  return calls;
}

test("ladder sizes match the plan (D15)", () => {
  assert.deepEqual([...LADDER_DRAFT_SIZES_MIB], [1, 4, 8, 16, 24]);
  assert.deepEqual([...LADDER_ROUNDTRIP_SIZES_MIB], [1, 8, 24, 50]);
});

test("base64LinesLength matches a reference 76-column, CRLF-after-every-line encoding", () => {
  for (const n of [1, 2, 3, 56, 57, 58, 114, 1000, 1_048_576]) {
    const b64 = Buffer.alloc(n, 7).toString("base64");
    const lines = b64.match(/.{1,76}/g) ?? [];
    const reference = lines.map((l) => l + "\r\n").join("");
    assert.equal(base64LinesLength(n), reference.length, `n=${n}`);
  }
});

test("draftCreateCode posts a composed RFC 822 draft via the media endpoint, with no recipients", async () => {
  const code = draftCreateCode(REF, 4);
  const [call, ...rest] = await record(code);
  assert.equal(rest.length, 0);
  assert.equal(call!.method, "POST");
  assert.equal(call!.path, "/upload/gmail/v1/users/me/drafts");
  assert.deepEqual(call!.query, { uploadType: "media" });
  assert.equal(call!.contentType, "message/rfc822");
  const { head, tail } = draftMime(4);
  assert.deepEqual(call!.composed, {
    segments: [{ text: head }, { staged: REF, encoding: "base64-lines" }, { text: tail }],
  });
  assert.ok(head.includes("\r\n\r\n"), "header block terminated");
  assert.ok(!/^(to|cc|bcc):/im.test(head), "a ladder draft carries no recipient header");
  for (const k of ["body", "bodyBase64", "rawBody", "multipart"]) assert.ok(!(k in call!), k);
});

test("the follow-up steps are reads, a stage and a delete — never a send", async () => {
  const get = await record(draftGetCode("d1"));
  assert.equal(get[0]!.method, "GET");
  assert.equal(get[0]!.path, "/gmail/v1/users/me/drafts/d1");

  const stage = await record(stageAttachmentCode("m1", "att-1"));
  assert.deepEqual(stage[0], {
    stageFromUpstreamJson: [
      { method: "GET", path: "/gmail/v1/users/me/messages/m1/attachments/att-1" },
      "data",
      "base64url",
      "ladder.bin",
      "application/octet-stream",
    ],
  });

  const del = await record(draftDeleteCode("d1"));
  assert.equal(del[0]!.method, "DELETE");
  assert.equal(del[0]!.path, "/gmail/v1/users/me/drafts/d1");

  for (const code of [draftCreateCode(REF, 1), draftGetCode("d1"), stageAttachmentCode("m1", "a"), draftDeleteCode("d1")]) {
    assert.ok(!/\/send\b/.test(code), code);
    assert.doesNotThrow(() => assertLadderCodeSafe(code));
  }
});

test("both denial probes target messages.send.media, addressed only to an undeliverable .invalid recipient", async () => {
  assert.match(PROBE_RECIPIENT, /^[^@\s]+@[a-z0-9.-]+\.invalid$/);
  for (const [kind, uploadType] of [
    ["external-send", "media"],
    ["upload-type-not-media", "resumable"],
  ] as const) {
    const code = denialProbeCode(kind, REF);
    assert.doesNotThrow(() => assertLadderCodeSafe(code), kind);
    const [call] = await record(code);
    assert.equal(call!.method, "POST");
    assert.equal(call!.path, "/upload/gmail/v1/users/me/messages/send");
    assert.deepEqual(call!.query, { uploadType });
    const text = JSON.stringify(call!.composed);
    const addresses = text.match(/[^\s"<>,:]+@[^\s"<>,\\]+/g) ?? [];
    assert.deepEqual([...new Set(addresses)], [PROBE_RECIPIENT], kind);
  }
});

test("the guard refuses any send the ladder did not mint as a denial probe", () => {
  const forged = [
    // Plain JSON send.
    `async () => codemode.request({ method: "POST", path: "/gmail/v1/users/me/messages/send", body: { raw: "x" } })`,
    // Sending a stored draft by id.
    `async () => codemode.request({ method: "POST", path: "/gmail/v1/users/me/drafts/send", body: { id: "d1" } })`,
    // A probe-shaped media send not produced by denialProbeCode.
    denialProbeCode("external-send", REF).replace("ladder", "Ladder"),
  ];
  for (const code of forged) assert.throws(() => assertLadderCodeSafe(code), /refus/i, code);
});

test("the guard refuses any deliverable address, even outside a send", () => {
  const code = draftCreateCode(REF, 1).replace("Subject:", "To: someone@example.com\\r\\nSubject:");
  assert.throws(() => assertLadderCodeSafe(code), /refus/i);
});

test("sizeEstimateClose tolerates Gmail's estimate but not a missing attachment", () => {
  const assembled = 1_000_000;
  assert.equal(sizeEstimateClose(assembled + 900, assembled), true);
  assert.equal(sizeEstimateClose(assembled - 900, assembled), true);
  assert.equal(sizeEstimateClose(2_000, assembled), false);
});

// --- Review fixes (WP-D review) ---

const GENERIC_DENY = "Operation gmail.users.messages.send.media is denied by surface review";
const UPLOAD_TYPE_DENY = 'The Gmail media-upload send needs query { uploadType: "media" }';

test("classifyProbe passes each probe only on ITS expected denial", () => {
  // external-send carries no inspector message, so the sandbox sees the
  // generic surface-review denial; the reason code is only in the audit line.
  assert.equal(classifyProbe("external-send", { denied: true, message: GENERIC_DENY }).ok, true);
  // The sandbox cannot see the reason code, so the PASS row tells the operator
  // where to confirm it.
  assert.equal(
    classifyProbe("external-send", { denied: true, message: GENERIC_DENY }).detail,
    "denied (confirm external-send in the audit line)",
  );
  assert.equal(classifyProbe("upload-type-not-media", { denied: true, message: UPLOAD_TYPE_DENY }).ok, true);
  // Swapped: the right kind of failure for the wrong probe is a FAIL.
  assert.equal(classifyProbe("external-send", { denied: true, message: UPLOAD_TYPE_DENY }).ok, false);
  assert.equal(classifyProbe("upload-type-not-media", { denied: true, message: GENERIC_DENY }).ok, false);
  // Any other error is a FAIL (e.g. staged-not-supported, a ref failure, a gate).
  assert.equal(classifyProbe("external-send", { denied: true, message: "segment 2: file not found or not yours" }).ok, false);
  assert.equal(classifyProbe("external-send", { toolError: true, message: "execute timed out" }).ok, false);
  // Not denied at all: FAIL, whatever the status.
  assert.equal(classifyProbe("external-send", { denied: false, status: 200 }).ok, false);
  assert.equal(classifyProbe("upload-type-not-media", { denied: false, status: 400 }).ok, false);
});

test("redactSecrets masks staging tokens and file handles", () => {
  const out = redactSecrets("token stg_AbC-123_x and fh_ZZ9 in https://h/staging/fetch/fh_ZZ9?x=1");
  assert.ok(!out.includes("stg_AbC"), out);
  assert.ok(!out.includes("fh_ZZ9"), out);
  assert.match(out, /stg_…/);
  assert.match(out, /fh_…/);
});

test("cleanupDraft records a FAIL row instead of throwing when the delete throws", async () => {
  const rows: Row[] = [];
  await cleanupDraft(async () => { throw new Error("boom stg_SECRET"); }, "d1", "4 MiB", rows);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.ok, false);
  assert.equal(rows[0]!.path, "drafts.delete");
  assert.ok(!rows[0]!.detail.includes("stg_SECRET"));
});

test("cleanupDraft records PASS on a successful delete", async () => {
  const rows: Row[] = [];
  await cleanupDraft(async () => ({ ok: true, status: 204 }), "d1", "4 MiB", rows);
  assert.equal(rows[0]!.ok, true);
});

test("draftSweepCode deletes only drafts whose subject is exactly a ladder subject", async () => {
  const subjects: Record<string, string> = {
    a: "codemode staging ladder 4 MiB",
    b: "codemode staging ladder notes from Victor",
    c: "codemode staging ladder 24 MiB",
  };
  const calls = await record(draftSweepCode(), (o) => {
    if (o.method === "GET" && o.path === "/gmail/v1/users/me/drafts") return { drafts: [{ id: "a" }, { id: "b" }, { id: "c" }] };
    const m = /\/drafts\/([a-z])$/.exec(String(o.path));
    if (o.method === "GET" && m) return { message: { payload: { headers: [{ name: "Subject", value: subjects[m[1]!] }] } } };
    return {};
  });
  const list = calls[0]!;
  assert.equal(list.method, "GET");
  assert.match(String((list.query as Record<string, unknown>).q), /subject:"codemode staging ladder"/);
  const deleted = calls.filter((c) => c.method === "DELETE").map((c) => c.path);
  assert.deepEqual(deleted, ["/gmail/v1/users/me/drafts/a", "/gmail/v1/users/me/drafts/c"]);
  assert.doesNotThrow(() => assertLadderCodeSafe(draftSweepCode()));
  assert.ok(!/\/send\b/.test(draftSweepCode()));
});

// --- Live-run fixes (gmail-dev ladder run) ---

const text = (v: unknown): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(v) }] });

/** A fake server: register_file_handle mints slots, uploads are stored, and
 *  execute answers the sweep. `hangDownloads` makes the first N downloads'
 *  bodies never end (they only error when the request's signal aborts). */
function fakeDeps(opts: {
  hangDownloads?: number;
  execute?: (code: string, timeoutMs: number) => Promise<CallToolResult>;
  fetchTimeoutMs?: number;
} = {}) {
  const calls: Array<{ name: string; timeoutMs: number; code?: string }> = [];
  const stored = new Map<string, Uint8Array>();
  let n = 0;
  let hang = opts.hangDownloads ?? 0;
  const deps: LadderDeps = {
    async callTool(name, args, timeoutMs) {
      calls.push({ name, timeoutMs, ...(typeof args.code === "string" ? { code: args.code } : {}) });
      if (name === "register_file_handle") {
        n++;
        return text({ upload_url: "https://srv.test/staging/upload", token: `stg_T${n}`, file_handle: `fh_H${n}` });
      }
      if (opts.execute) return opts.execute(String(args.code), timeoutMs);
      return text({ ok: true, deleted: 0, failed: 0 });
    },
    fetch: (async (url: string | URL, init?: RequestInit) => {
      const auth = new Headers(init?.headers).get("authorization") ?? "";
      if (init?.method === "POST") {
        stored.set(auth, new Uint8Array(init.body as Uint8Array));
        return new Response(null, { status: 204 });
      }
      if (hang > 0) {
        hang--;
        const signal = init?.signal;
        // A real hung body holds an open socket, which keeps the event loop
        // alive. AbortSignal.timeout's timer is unref'd, so without this
        // stand-in Node 22's test runner sees an idle loop and fails the test.
        const socket = setInterval(() => {}, 1_000);
        return new Response(new ReadableStream({
          start(c) {
            signal?.addEventListener("abort", () => { clearInterval(socket); c.error(signal.reason); });
          },
        }));
      }
      return new Response(stored.get(auth) ?? new Uint8Array());
    }) as typeof fetch,
    fetchTimeoutMs: () => opts.fetchTimeoutMs ?? 5_000,
    executeTimeoutMs: (mib) => 1000 + mib,
  };
  return { deps, calls };
}

test("default timeouts scale with size and have generous floors", () => {
  assert.equal(defaultFetchTimeoutMs(1), 120_000);
  assert.equal(defaultFetchTimeoutMs(50), 250_000);
  assert.equal(defaultExecuteTimeoutMs(1), 180_000);
  assert.equal(defaultExecuteTimeoutMs(24), 192_000);
});

test("a download whose body never ends fails that row on the timeout, and the run carries on to the sweep", async () => {
  const { deps, calls } = fakeDeps({ hangDownloads: 1, fetchTimeoutMs: 60 });
  const rows: Row[] = [];
  await runLadder(deps, { draftSizes: [], roundTripSizes: [1, 1], probes: false, sweepOnly: false }, rows);
  assert.equal(rows.length, 3, JSON.stringify(rows));
  assert.equal(rows[0]!.ok, false);
  assert.match(rows[0]!.detail, /timeout|abort/i);
  assert.ok(rows[0]!.ms >= 50, `elapsed ms recorded on failure (got ${rows[0]!.ms})`);
  assert.equal(rows[1]!.ok, true, "the next rung still ran and passed");
  assert.equal(rows[2]!.path, "sweep leftover ladder drafts");
  assert.ok(calls.some((c) => c.name === "execute" && c.code === draftSweepCode()));
});

test("execute calls carry the per-size timeout, and a timed-out execute records real elapsed ms", async () => {
  const { deps, calls } = fakeDeps({
    execute: async (code) => {
      if (code === draftSweepCode()) return text({ ok: true, deleted: 0, failed: 0 });
      await new Promise((r) => setTimeout(r, 40));
      throw new Error("MCP error -32001: Request timed out");
    },
  });
  const rows: Row[] = [];
  await runLadder(deps, { draftSizes: [4], roundTripSizes: [], probes: false, sweepOnly: false }, rows);
  const create = rows.find((r) => r.path.startsWith("drafts.create.media"));
  assert.ok(create, JSON.stringify(rows));
  assert.equal(create!.ok, false);
  assert.match(create!.detail, /timed out/);
  assert.ok(create!.ms >= 30, `got ${create!.ms}`);
  const exec = calls.find((c) => c.name === "execute" && c.code !== draftSweepCode());
  assert.equal(exec!.timeoutMs, 1004);
});

test("callExecute passes an explicit timeout and resets it on progress", async () => {
  const seen: unknown[] = [];
  const client = { callTool: async (...a: unknown[]) => { seen.push(a); return text({}); } };
  await callExecute(client as never, "async () => 1", { timeoutMs: 1234 });
  assert.deepEqual(seen[0], [
    { name: "execute", arguments: { code: "async () => 1" } },
    undefined,
    // Progress resets the timer, but never beyond twice the timeout in total.
    { timeout: 1234, resetTimeoutOnProgress: true, maxTotalTimeout: 2468 },
  ]);
  await callExecute(client as never, "async () => 2");
  const opts = (seen[1] as unknown[])[2] as { timeout: number };
  assert.ok(opts.timeout >= 180_000, "default is well above the SDK's 60 s");
});

test("rows are reported as they happen, not only at the end", async () => {
  const { deps } = fakeDeps();
  const order: string[] = [];
  const sink = { push(r: Row) { order.push(`row:${r.path}`); } };
  const origCallTool = deps.callTool;
  deps.callTool = async (name, args, t) => { order.push(`call:${name}`); return origCallTool(name, args, t); };
  await runLadder(deps, { draftSizes: [], roundTripSizes: [1], probes: false, sweepOnly: false }, sink);
  // The round-trip row is reported before the sweep's execute call is made.
  assert.ok(order.indexOf("row:upload + /staging/fetch (sha256)") < order.lastIndexOf("call:execute"), order.join(" | "));
});

test("--sweep-only runs nothing but the guarded exact-subject sweep", async () => {
  const { deps, calls } = fakeDeps();
  const rows: Row[] = [];
  await runLadder(deps, { draftSizes: [1], roundTripSizes: [1], probes: true, sweepOnly: true }, rows);
  assert.deepEqual(calls.map((c) => c.name), ["execute"]);
  assert.equal(calls[0]!.code, draftSweepCode());
  assert.equal(rows.length, 1);
});

test("parseLadderArgs: --sizes filters both ladders, --sweep-only and --execute-timeout-ms parse, bad input throws", () => {
  const a = parseLadderArgs(["--target=https://h.test/", "--sizes=1,4"]);
  assert.equal(a.target, "https://h.test");
  assert.deepEqual(a.draftSizes, [1, 4]);
  assert.deepEqual(a.roundTripSizes, [1]);
  assert.equal(a.probes, true);
  assert.equal(a.sweepOnly, false);
  const b = parseLadderArgs(["--target=https://h.test", "--sweep-only", "--execute-timeout-ms=300000"]);
  assert.equal(b.sweepOnly, true);
  assert.equal(b.executeTimeoutMs, 300_000);
  const c = parseLadderArgs(["--target=https://h.test"]);
  assert.deepEqual(c.draftSizes, [1, 4, 8, 16, 24]);
  assert.deepEqual(c.roundTripSizes, [1, 8, 24, 50]);
  assert.throws(() => parseLadderArgs(["--target=https://h.test", "--sizes=3"]), /size/i);
  assert.throws(() => parseLadderArgs(["--sizes=1"]), /target/i);
  assert.throws(() => parseLadderArgs(["--target=https://h.test", "--execute-timeout-ms=abc"]), /timeout/i);
});

test("realDeps guards execute itself: unsafe code never reaches the client", async () => {
  const seen: unknown[] = [];
  const client = { callTool: async (...a: unknown[]) => { seen.push(a); return text({}); } };
  const deps = realDeps(client as never, {});
  const unsafe = `async () => codemode.request({ method: "POST", path: "/gmail/v1/users/me/messages/send", body: { raw: "x" } })`;
  await assert.rejects(() => deps.callTool("execute", { code: unsafe }, 1000), /refus/i);
  await assert.rejects(() => deps.callTool("execute", { code: "async () => 'to: a@example.com'" }, 1000), /refus/i);
  assert.equal(seen.length, 0);
  // Safe code passes through with the bounded timeout options.
  await deps.callTool("execute", { code: draftSweepCode() }, 1000);
  assert.deepEqual((seen[0] as unknown[])[2], { timeout: 1000, resetTimeoutOnProgress: true, maxTotalTimeout: 2000 });
});

// --- undici fetch (Node >= 26's built-in fetch never sends the tools/call POST
// while the SDK's standalone GET SSE stream is open) ---

test("the harnesses default to undici's fetch, not the built-in one", () => {
  assert.equal(HARNESS_FETCH, undiciFetch);
  assert.notEqual(HARNESS_FETCH, globalThis.fetch);
});

test("the MCP transport sends through the injected fetch", async () => {
  const seen: Array<{ url: string; method: string }> = [];
  const fakeFetch = (async (url: string | URL, init?: RequestInit) => {
    seen.push({ url: String(url), method: init?.method ?? "GET" });
    return new Response(null, { status: 202 });
  }) as typeof fetch;
  const transport = createHarnessTransport("https://srv.test", { tokens: () => undefined } as never, fakeFetch);
  await transport.start();
  await transport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  assert.deepEqual(seen[0], { url: "https://srv.test/mcp", method: "POST" });
  await transport.close();
});

test("the ladder's real deps upload and download with undici's fetch", () => {
  const deps = realDeps({ callTool: async () => text({}) } as never, {});
  assert.equal(deps.fetch, undiciFetch);
});

// --- Exact-byte draft rungs (25,000,000 B and 25 MiB against the media cap) ---

test("an exact-byte draft rung is labelled in bytes, still carries no recipient, and passes the guard", async () => {
  const { head } = draftMime({ bytes: 25_000_000 });
  assert.match(head, /^Subject: codemode staging ladder 25000000 B\r\n/);
  assert.ok(!/^(to|cc|bcc):/im.test(head));
  const code = draftCreateCode(REF, { bytes: 26_214_400 });
  assert.doesNotThrow(() => assertLadderCodeSafe(code));
  const [call] = await record(code);
  assert.match(JSON.stringify(call!.composed), /codemode staging ladder 26214400 B/);
  // MiB rungs keep their existing subject.
  assert.match(draftMime(4).head, /^Subject: codemode staging ladder 4 MiB\r\n/);
});

test("the sweep also deletes exact-byte ladder drafts, and still nothing else", async () => {
  const subjects: Record<string, string> = {
    a: "codemode staging ladder 25000000 B",
    b: "codemode staging ladder 25000000 B and notes",
    c: "codemode staging ladder 4 MiB",
    d: "codemode staging ladder B",
    e: "codemode staging ladder 26214400 Bytes",
  };
  const calls = await record(draftSweepCode(), (o) => {
    if (o.method === "GET" && o.path === "/gmail/v1/users/me/drafts") return { drafts: Object.keys(subjects).map((id) => ({ id })) };
    const m = /\/drafts\/([a-z])$/.exec(String(o.path));
    if (o.method === "GET" && m) return { message: { payload: { headers: [{ name: "Subject", value: subjects[m[1]!] }] } } };
    return {};
  });
  const deleted = calls.filter((c) => c.method === "DELETE").map((c) => c.path);
  assert.deepEqual(deleted, ["/gmail/v1/users/me/drafts/a", "/gmail/v1/users/me/drafts/c"]);
});

test("an exact-byte draft rung uploads exactly that many bytes, checks part.size against it, and sizes its timeouts from bytes", async () => {
  const draftsCreated: string[] = [];
  let uploaded = -1;
  const { deps, calls } = fakeDeps({
    execute: async (code) => {
      if (code === draftSweepCode()) return text({ ok: true, deleted: 0, failed: 0 });
      if (code.includes("/upload/gmail/v1/users/me/drafts")) { draftsCreated.push(code); return text({ ok: true, draftId: "d1", messageId: "m1" }); }
      if (code.includes('format: "full"')) {
        return text({ ok: true, messageId: "m1", sizeEstimate: 34_200_000, parts: [{ filename: "ladder.bin", size: 25_000_000, attachmentId: "a1" }] });
      }
      if (code.includes("stageFromUpstreamJson")) return text({ ok: false, status: 500, message: "not in this fake" });
      return text({ ok: true, status: 204 });
    },
  });
  const origFetch = deps.fetch;
  deps.fetch = (async (url: string | URL, init?: RequestInit) => {
    if (init?.method === "POST") uploaded = (init.body as Uint8Array).byteLength;
    return origFetch(url, init);
  }) as typeof fetch;
  const rows: Row[] = [];
  await runLadder(deps, { draftSizes: [], draftBytes: [25_000_000], roundTripSizes: [], probes: false, sweepOnly: false }, rows);
  assert.equal(uploaded, 25_000_000);
  assert.equal(draftsCreated.length, 1);
  assert.match(draftsCreated[0]!, /codemode staging ladder 25000000 B/);
  const get = rows.find((r) => r.path === "drafts.get");
  assert.ok(get, JSON.stringify(rows));
  assert.equal(get!.size, "25000000 B");
  assert.match(get!.detail, /part\.size=25000000/);
  assert.ok(rows.some((r) => r.path === "drafts.delete" && r.ok));
  // fakeDeps' execute timeout is 1000 + MiB; 25,000,000 B rounds up to 24 MiB.
  const exec = calls.find((c) => c.name === "execute" && c.code !== draftSweepCode());
  assert.equal(exec!.timeoutMs, 1024);
  const reg = calls.find((c) => c.name === "register_file_handle");
  assert.ok(reg);
});

test("parseLadderArgs: --draft-bytes alone runs only those draft rungs (no MiB drafts, no round trip)", () => {
  const a = parseLadderArgs(["--target=https://h.test", "--draft-bytes=25000000,26214400"]);
  assert.deepEqual(a.draftBytes, [25_000_000, 26_214_400]);
  assert.deepEqual(a.draftSizes, []);
  assert.deepEqual(a.roundTripSizes, []);
  // Combined with --sizes, both apply.
  const b = parseLadderArgs(["--target=https://h.test", "--sizes=1", "--draft-bytes=1000"]);
  assert.deepEqual(b.draftSizes, [1]);
  assert.deepEqual(b.roundTripSizes, [1]);
  assert.deepEqual(b.draftBytes, [1000]);
  // Default: none.
  assert.deepEqual(parseLadderArgs(["--target=https://h.test"]).draftBytes, []);
  for (const bad of ["0", "-5", "1.5", "abc", ""]) {
    assert.throws(() => parseLadderArgs(["--target=https://h.test", `--draft-bytes=${bad}`]), /draft-bytes/, bad);
  }
});
