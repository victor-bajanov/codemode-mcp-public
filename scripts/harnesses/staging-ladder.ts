/**
 * Staged transfer v2 live acceptance ladder (issue #59, plan D15).
 *
 * Drives a DEPLOYED Gmail server (normally gmail-dev) through the staged
 * transfer paths at increasing sizes, using the cached MCP bearer from
 * mcp-client.ts (its `--no-spawn` path; the OAuth dance runs once if no
 * token is cached for the target).
 *
 *   Drafts, F ∈ {1, 4, 8, 16, 24} MiB:
 *     register_file_handle → POST random bytes to upload_url →
 *     execute: composed `drafts.create.media` (one F-byte attachment) →
 *     execute: `drafts.get` (sizeEstimate ≈ assembled length; attachment
 *       body.size === F) →
 *     execute: `stageFromUpstreamJson` of that attachment → GET fetch_url,
 *       SHA-256 must equal the uploaded bytes' →
 *     execute: `drafts.delete` (always attempted once the draft exists).
 *   (`--draft-bytes` adds draft rungs at exact byte sizes, e.g. 25,000,000.)
 *   Round trip, F ∈ {1, 8, 24, 50} MiB:
 *     register → upload → GET /staging/fetch/<handle> → SHA-256 compare.
 *   Inspector, two composed `messages.send.media` probes that MUST be denied:
 *     a non-allowlisted recipient (expected reason `external-send`) and
 *     `uploadType=resumable` (expected reason `upload-type-not-media`).
 *
 * NO EMAIL IS SENT. Every execute() call goes through `execFor`, which
 * refuses any code naming a `/send` path unless it is byte-for-byte one of the
 * two denial probes minted by `denialProbeCode` in this process, and refuses
 * any email address that is not under the reserved `.invalid` TLD (RFC 2606)
 * — so even a wrongly-allowed probe cannot reach a person. Drafts carry no
 * recipient header at all, and `drafts.send` is never called.
 *
 * Prints a table (size, path, ms, status) and exits non-zero on any failure.
 * Afterwards, check Workers Logs for `exceededMemory` over the run's window.
 *
 * Usage:
 *   pnpm exec tsx scripts/harnesses/staging-ladder.ts --target=https://gmail-dev.<subdomain>.workers.dev
 */
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { HARNESS_FETCH, callExecute, connectWithOAuth } from "./mcp-client.js";

const MIB = 1_048_576;

export const LADDER_DRAFT_SIZES_MIB = [1, 4, 8, 16, 24] as const;
export const LADDER_ROUNDTRIP_SIZES_MIB = [1, 8, 24, 50] as const;
/** Plan acceptance: a 24 MiB draft must be created in under 15 s. */
const DRAFT_24_MIB_BUDGET_MS = 15_000;

/** The denial probes' only recipient. `.invalid` is reserved (RFC 2606) and
 *  never resolves, so a probe that was wrongly allowed still reaches no one. */
export const PROBE_RECIPIENT = "ladder-denial-probe@codemode-ladder.invalid";

export interface StagedRef {
  file_handle: string;
  token: string;
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested in staging-ladder.test.ts)
// ---------------------------------------------------------------------------

/** Length of the `base64-lines` encoding of `n` bytes: 57-byte groups become
 *  one 76-char line, and every line (including the last) ends in CRLF. */
export function base64LinesLength(n: number): number {
  const full = Math.floor(n / 57);
  const rem = n % 57;
  return full * 78 + (rem ? Math.ceil(rem / 3) * 4 + 2 : 0);
}

/** Gmail's sizeEstimate is the stored RFC 822 size, which can differ from the
 *  bytes we sent by a few header lines Gmail adds. */
export function sizeEstimateClose(estimate: number, assembled: number): boolean {
  return Math.abs(estimate - assembled) <= Math.max(4096, assembled * 0.01);
}

const CRLF = "\r\n";
const ATTACHMENT_NAME = "ladder.bin";
const ATTACHMENT_TYPE = "application/octet-stream";

function mimeAround(headers: string[], boundary: string, note: string): { head: string; tail: string } {
  const head = [
    ...headers,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    note,
    `--${boundary}`,
    `Content-Type: ${ATTACHMENT_TYPE}; name="${ATTACHMENT_NAME}"`,
    `Content-Disposition: attachment; filename="${ATTACHMENT_NAME}"`,
    "Content-Transfer-Encoding: base64",
    "",
    "",
  ].join(CRLF);
  return { head, tail: `--${boundary}--${CRLF}` };
}

/** A draft rung's attachment size: a preset rung in MiB, or exact bytes. */
export type DraftSize = number | { bytes: number };

const draftBytesOf = (s: DraftSize): number => (typeof s === "number" ? s * MIB : s.bytes);
const draftLabel = (s: DraftSize): string => (typeof s === "number" ? `${s} MiB` : `${s.bytes} B`);

/** The text around the staged attachment in a ladder draft. No To/Cc/Bcc. */
export function draftMime(size: DraftSize): { head: string; tail: string } {
  return mimeAround(
    [`Subject: codemode staging ladder ${draftLabel(size)}`],
    typeof size === "number" ? `ladder-${size}` : `ladder-${size.bytes}b`,
    "codemode staging ladder draft; deleted by the harness.",
  );
}

function segmentsLiteral(head: string, ref: StagedRef, tail: string): string {
  return (
    "{ segments: [\n" +
    `      { text: ${JSON.stringify(head)} },\n` +
    `      { staged: ${JSON.stringify(ref)}, encoding: "base64-lines" },\n` +
    `      { text: ${JSON.stringify(tail)} },\n` +
    "    ] }"
  );
}

export function draftCreateCode(ref: StagedRef, size: DraftSize): string {
  const { head, tail } = draftMime(size);
  return `async () => {
  const r = await codemode.request({
    method: "POST",
    path: "/upload/gmail/v1/users/me/drafts",
    query: { uploadType: "media" },
    contentType: "message/rfc822",
    composed: ${segmentsLiteral(head, ref, tail)},
  });
  if (!r.success) return { ok: false, status: r.status, error: r.errors[0]?.message ?? null };
  return { ok: true, draftId: r.result.id, messageId: r.result.message?.id ?? null };
}`;
}

export function draftGetCode(draftId: string): string {
  return `async () => {
  const r = await codemode.request({
    method: "GET",
    path: ${JSON.stringify(`/gmail/v1/users/me/drafts/${encodeURIComponent(draftId)}`)},
    query: { format: "full" },
  });
  if (!r.success) return { ok: false, status: r.status, error: r.errors[0]?.message ?? null };
  const m = r.result.message ?? {};
  const parts = [];
  const walk = (p) => { if (!p) return; if (p.filename) parts.push({ filename: p.filename, size: p.body?.size ?? null, attachmentId: p.body?.attachmentId ?? null }); (p.parts ?? []).forEach(walk); };
  walk(m.payload);
  return { ok: true, messageId: m.id ?? null, sizeEstimate: m.sizeEstimate ?? null, parts };
}`;
}

export function stageAttachmentCode(messageId: string, attachmentId: string): string {
  const path = `/gmail/v1/users/me/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}`;
  return `async () => {
  const f = await __stagingHost.stageFromUpstreamJson(
    { method: "GET", path: ${JSON.stringify(path)} },
    "data",
    "base64url",
    ${JSON.stringify(ATTACHMENT_NAME)},
    ${JSON.stringify(ATTACHMENT_TYPE)},
  );
  if (!f.ok) return { ok: false, status: f.status, message: f.message };
  return { ok: true, fetch_url: f.fetch_url, token: f.token, byte_length: f.byte_length };
}`;
}

export function draftDeleteCode(draftId: string): string {
  return `async () => {
  const r = await codemode.request({
    method: "DELETE",
    path: ${JSON.stringify(`/gmail/v1/users/me/drafts/${encodeURIComponent(draftId)}`)},
  });
  return { ok: r.success, status: r.status };
}`;
}

export type ProbeKind = "external-send" | "upload-type-not-media";

const SEND_MEDIA_PATH = "/upload/gmail/v1/users/me/messages/send";
// Codes minted by denialProbeCode in this process — the ONLY send-shaped
// code execFor will pass on.
const issuedProbes = new Set<string>();

/** A composed messages.send.media request the server must deny. */
export function denialProbeCode(kind: ProbeKind, ref: StagedRef): string {
  const uploadType = kind === "upload-type-not-media" ? "resumable" : "media";
  const { head, tail } = mimeAround(
    [`To: ${PROBE_RECIPIENT}`, `Subject: codemode ladder denial probe (${kind})`],
    "ladder-probe",
    "codemode staging ladder denial probe; the server must refuse to send this.",
  );
  const code = `async () => {
  try {
    const r = await codemode.request({
      method: "POST",
      path: ${JSON.stringify(SEND_MEDIA_PATH)},
      query: { uploadType: ${JSON.stringify(uploadType)} },
      contentType: "message/rfc822",
      composed: ${segmentsLiteral(head, ref, tail)},
    });
    return { denied: false, status: r.status, success: r.success, error: r.errors?.[0]?.message ?? null };
  } catch (e) {
    return { denied: true, message: String(e?.message ?? e) };
  }
}`;
  issuedProbes.add(code);
  return code;
}

const ADDRESS_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/g;

/** Throws unless `code` is safe for the ladder to run: no deliverable email
 *  address anywhere, and no `/send` path except a probe minted above. */
export function assertLadderCodeSafe(code: string): void {
  for (const addr of code.match(ADDRESS_RE) ?? []) {
    if (!addr.toLowerCase().endsWith(".invalid")) {
      throw new Error(`ladder refuses code naming a deliverable address (${addr})`);
    }
  }
  if (/\/send\b/.test(code)) {
    if (!issuedProbes.has(code)) {
      throw new Error("ladder refuses send-shaped code it did not mint as a denial probe");
    }
    if (!code.includes(JSON.stringify(SEND_MEDIA_PATH)) || /drafts\/send/.test(code)) {
      throw new Error("ladder refuses a probe that targets anything but messages.send.media");
    }
  }
}

export interface ProbeOutcome {
  denied?: boolean;
  toolError?: boolean;
  message?: string;
  status?: number;
}

// What the sandbox sees for each probe's expected denial. The off-allowlist
// send carries no inspector message, so request-handler throws the generic
// surface-review ToolError (the `external-send` reason is only in the audit
// line); the uploadType rule carries its own message (gmail outbound.ts).
const EXPECTED_DENIAL: Record<ProbeKind, string> = {
  "external-send": "Operation gmail.users.messages.send.media is denied by surface review",
  "upload-type-not-media": 'needs query { uploadType: "media" }',
};

/** PASS only when the probe was refused with ITS expected denial; any other
 *  error (or no denial) is a FAIL. */
export function classifyProbe(kind: ProbeKind, v: ProbeOutcome): { ok: boolean; detail: string } {
  const message = v.message ?? "";
  const refused = v.denied === true || v.toolError === true;
  if (!refused) {
    return { ok: false, detail: `NOT DENIED (status=${v.status ?? "?"}); recipient was ${PROBE_RECIPIENT}` };
  }
  if (message.includes(EXPECTED_DENIAL[kind])) {
    return {
      ok: true,
      detail: kind === "external-send"
        ? "denied (confirm external-send in the audit line)"
        : "denied as expected (upload-type-not-media)",
    };
  }
  return { ok: false, detail: `refused, but not with the expected ${kind} denial: ${message.slice(0, 160)}` };
}

/** Mask staging tokens and file handles in anything the ladder prints. */
export function redactSecrets(text: string): string {
  return text.replace(/\b(stg|fh)_[A-Za-z0-9_-]+/g, "$1_…");
}

const LADDER_SUBJECT_RE = "^codemode staging ladder \\d+ (MiB|B)$";

/** Deletes leftover ladder drafts (from an earlier crashed run, or a delete
 *  that failed). Gmail's `q` match is word-based, so each candidate's Subject
 *  is re-checked exactly before it is deleted. */
export function draftSweepCode(): string {
  return `async () => {
  const exact = new RegExp(${JSON.stringify(LADDER_SUBJECT_RE)});
  const ids = [];
  let pageToken;
  for (let page = 0; page < 10; page++) {
    const r = await codemode.request({
      method: "GET",
      path: "/gmail/v1/users/me/drafts",
      query: { q: 'subject:"codemode staging ladder"', maxResults: 100, ...(pageToken ? { pageToken } : {}) },
    });
    if (!r.success) return { ok: false, status: r.status, deleted: 0, failed: 0 };
    for (const d of r.result.drafts ?? []) ids.push(d.id);
    pageToken = r.result.nextPageToken;
    if (!pageToken) break;
  }
  let deleted = 0, failed = 0;
  for (const id of ids) {
    const g = await codemode.request({
      method: "GET",
      path: "/gmail/v1/users/me/drafts/" + encodeURIComponent(id),
      query: { format: "metadata", metadataHeaders: "Subject" },
    });
    const subject = (g.result?.message?.payload?.headers ?? []).find((h) => /^subject$/i.test(h.name))?.value ?? "";
    if (!g.success || !exact.test(subject)) continue;
    const del = await codemode.request({ method: "DELETE", path: "/gmail/v1/users/me/drafts/" + encodeURIComponent(id) });
    if (del.success) deleted++; else failed++;
  }
  return { ok: failed === 0, deleted, failed };
}`;
}

export interface Row {
  size: string;
  path: string;
  ms: number;
  ok: boolean;
  detail: string;
}

function toolJson(result: CallToolResult): unknown {
  const text = result.content?.find((c) => c.type === "text") as { text?: string } | undefined;
  const raw = text?.text ?? "";
  try {
    return JSON.parse(raw);
  } catch {
    const i = raw.indexOf("{");
    if (i >= 0) {
      try {
        return JSON.parse(raw.slice(i));
      } catch {
        /* fall through */
      }
    }
    return { unparsed: raw.slice(0, 300) };
  }
}

type Exec = (code: string) => Promise<Record<string, unknown>>;

/** Where rows go: an array in tests, a live printer in the CLI. */
export interface RowSink {
  push(row: Row): unknown;
}

/** Everything the run touches outside this process, injectable for tests. */
export interface LadderDeps {
  callTool(name: string, args: Record<string, unknown>, timeoutMs: number): Promise<CallToolResult>;
  fetch: typeof fetch;
  fetchTimeoutMs(mib: number): number;
  executeTimeoutMs(mib: number): number;
}

/** Raw HTTP to /staging/*: a stalled body fails its row instead of hanging. */
export const defaultFetchTimeoutMs = (mib: number): number => Math.max(120_000, mib * 5_000);
/** One execute() call: well above the MCP SDK's 60 s default. */
export const defaultExecuteTimeoutMs = (mib: number): number => Math.max(180_000, mib * 8_000);

const errText = (err: unknown): string => redactSecrets(err instanceof Error ? err.message : String(err));

type Settled<T> = { ms: number } & ({ ok: true; value: T } | { ok: false; error: string });

/** Run `fn`, measuring elapsed time whether it resolves or throws. */
async function settle<T>(fn: () => Promise<T>): Promise<Settled<T>> {
  const t0 = performance.now();
  try {
    const value = await fn();
    return { ms: Math.round(performance.now() - t0), ok: true, value };
  } catch (err) {
    return { ms: Math.round(performance.now() - t0), ok: false, error: errText(err) };
  }
}

/** The only path to the execute tool: every code string passes the no-send
 *  guard first. */
function execFor(deps: LadderDeps, mib: number): Exec {
  return async (code) => {
    assertLadderCodeSafe(code);
    const result = await deps.callTool("execute", { code }, deps.executeTimeoutMs(mib));
    const parsed = toolJson(result) as Record<string, unknown>;
    if (result.isError) return { ...parsed, toolError: true };
    return parsed;
  };
}

/** Delete one ladder draft, recording the outcome as a row; never throws. */
export async function cleanupDraft(exec: Exec, draftId: string, size: string, rows: RowSink): Promise<void> {
  const r = await settle(() => exec(draftDeleteCode(draftId)));
  const d = (r.ok ? r.value : {}) as { ok?: boolean; status?: number };
  rows.push({
    size,
    path: "drafts.delete",
    ms: r.ms,
    ok: r.ok && Boolean(d.ok),
    detail: !r.ok ? r.error : d.ok ? "" : `status=${d.status ?? "?"}`,
  });
}

const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

async function registerAndUpload(deps: LadderDeps, mib: number, bytes: Uint8Array<ArrayBuffer>, filename: string) {
  const res = await deps.callTool(
    "register_file_handle",
    { content_type: ATTACHMENT_TYPE, expected_byte_len: bytes.byteLength, filename },
    60_000,
  );
  const reg = toolJson(res) as { upload_url?: string; token?: string; file_handle?: string };
  if (!reg.upload_url || !reg.token || !reg.file_handle) {
    throw new Error("register_file_handle returned no upload slot");
  }
  const put = await deps.fetch(reg.upload_url, {
    method: "POST",
    headers: { Authorization: `Bearer ${reg.token}`, "Content-Type": ATTACHMENT_TYPE },
    body: bytes,
    signal: AbortSignal.timeout(deps.fetchTimeoutMs(mib)),
  });
  if (put.status !== 204) throw new Error(`upload returned HTTP ${put.status}`);
  return { ref: { file_handle: reg.file_handle, token: reg.token }, origin: new URL(reg.upload_url).origin };
}

async function download(deps: LadderDeps, mib: number, url: string, token: string): Promise<Uint8Array> {
  // The signal also covers reading the body, so a body that never ends fails.
  const r = await deps.fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(deps.fetchTimeoutMs(mib)),
  });
  if (!r.ok) throw new Error(`fetch returned HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

export async function draftRung(deps: LadderDeps, draftSize: DraftSize, rows: RowSink): Promise<void> {
  const size = draftLabel(draftSize);
  // Timeouts scale per MiB; an exact-byte rung rounds up to whole MiB.
  const mib = Math.ceil(draftBytesOf(draftSize) / MIB);
  const exec = execFor(deps, mib);
  const bytes = randomBytes(draftBytesOf(draftSize));
  const { head, tail } = draftMime(draftSize);
  const assembled =
    Buffer.byteLength(head) + base64LinesLength(bytes.byteLength) + Buffer.byteLength(tail);

  const up = await settle(() => registerAndUpload(deps, mib, bytes, ATTACHMENT_NAME));
  rows.push({ size, path: "upload", ms: up.ms, ok: up.ok, detail: up.ok ? "" : up.error });
  if (!up.ok) return;

  let draftId: string | undefined;
  try {
    const created = await settle(() => exec(draftCreateCode(up.value.ref, draftSize)));
    if (!created.ok) {
      rows.push({ size, path: "drafts.create.media (composed)", ms: created.ms, ok: false, detail: created.error });
      return;
    }
    const c = created.value as { ok?: boolean; draftId?: string; status?: number; error?: string };
    const overBudget = draftSize === 24 && created.ms > DRAFT_24_MIB_BUDGET_MS;
    if (c.ok && c.draftId) draftId = c.draftId;
    rows.push({
      size,
      path: "drafts.create.media (composed)",
      ms: created.ms,
      ok: Boolean(draftId) && !overBudget,
      detail: draftId
        ? overBudget ? `over the ${DRAFT_24_MIB_BUDGET_MS} ms budget` : ""
        : `status=${c.status ?? "?"} ${c.error ?? JSON.stringify(c).slice(0, 160)}`,
    });
    if (!draftId) return;

    const got = await settle(() => exec(draftGetCode(draftId!)));
    if (!got.ok) {
      rows.push({ size, path: "drafts.get", ms: got.ms, ok: false, detail: got.error });
      return;
    }
    const g = got.value as {
      ok?: boolean; messageId?: string; sizeEstimate?: number;
      parts?: Array<{ filename: string; size: number | null; attachmentId: string | null }>;
    };
    const part = g.parts?.find((p) => p.filename === ATTACHMENT_NAME);
    rows.push({
      size,
      path: "drafts.get",
      ms: got.ms,
      ok:
        Boolean(g.ok) &&
        typeof g.sizeEstimate === "number" &&
        sizeEstimateClose(g.sizeEstimate, assembled) &&
        part?.size === bytes.byteLength,
      detail: `sizeEstimate=${g.sizeEstimate ?? "?"} assembled=${assembled} part.size=${part?.size ?? "?"}`,
    });
    if (!g.messageId || !part?.attachmentId) return;

    const staged = await settle(async () => {
      const s = (await exec(stageAttachmentCode(g.messageId!, part.attachmentId!))) as {
        ok?: boolean; fetch_url?: string; token?: string; status?: number; message?: string;
      };
      if (!s.ok || !s.fetch_url || !s.token) return { ok: false, detail: `status=${s.status ?? "?"} ${s.message ?? ""}` };
      const back = await download(deps, mib, s.fetch_url, s.token);
      return { ok: sha256(back) === sha256(bytes), detail: `bytes=${back.byteLength}` };
    });
    rows.push({
      size,
      path: "stageFromUpstreamJson + fetch (sha256)",
      ms: staged.ms,
      ...(staged.ok ? staged.value : { ok: false, detail: staged.error }),
    });
  } finally {
    if (draftId) await cleanupDraft(exec, draftId, size, rows);
  }
}

export async function roundTripRung(deps: LadderDeps, mib: number, rows: RowSink): Promise<void> {
  const size = `${mib} MiB`;
  const bytes = randomBytes(mib * MIB);
  const r = await settle(async () => {
    const { ref, origin } = await registerAndUpload(deps, mib, bytes, ATTACHMENT_NAME);
    const back = await download(deps, mib, `${origin}/staging/fetch/${ref.file_handle}`, ref.token);
    return sha256(back) === sha256(bytes);
  });
  rows.push({
    size,
    path: "upload + /staging/fetch (sha256)",
    ms: r.ms,
    ok: r.ok && r.value,
    detail: !r.ok ? r.error : r.value ? "" : "hash mismatch",
  });
}

export async function sweep(deps: LadderDeps, rows: RowSink): Promise<void> {
  const r = await settle(() => execFor(deps, 1)(draftSweepCode()));
  const v = (r.ok ? r.value : {}) as { ok?: boolean; deleted?: number; failed?: number; status?: number };
  rows.push({
    size: "-",
    path: "sweep leftover ladder drafts",
    ms: r.ms,
    ok: r.ok && Boolean(v.ok),
    detail: !r.ok
      ? r.error
      : `deleted=${v.deleted ?? "?"} failed=${v.failed ?? "?"}${v.status ? ` status=${v.status}` : ""}`,
  });
}

export async function probes(deps: LadderDeps, rows: RowSink): Promise<void> {
  const up = await settle(() => registerAndUpload(deps, 1, randomBytes(1024), ATTACHMENT_NAME));
  if (!up.ok) {
    rows.push({ size: "1 KiB", path: "denial probes (upload)", ms: up.ms, ok: false, detail: up.error });
    return;
  }
  const exec = execFor(deps, 1);
  for (const kind of ["external-send", "upload-type-not-media"] as const) {
    const r = await settle(() => exec(denialProbeCode(kind, up.value.ref)));
    rows.push({
      size: "1 KiB",
      path: `messages.send.media probe (${kind})`,
      ms: r.ms,
      ...(r.ok ? classifyProbe(kind, r.value as ProbeOutcome) : { ok: false, detail: r.error }),
    });
  }
}

export interface LadderPlan {
  draftSizes: readonly number[];
  /** Extra draft rungs at exact byte sizes, run after the MiB rungs. */
  draftBytes?: readonly number[];
  roundTripSizes: readonly number[];
  probes: boolean;
  sweepOnly: boolean;
}

/** The whole run. Every rung records its own rows and never throws; the
 *  exact-subject sweep always runs last. */
export async function runLadder(deps: LadderDeps, plan: LadderPlan, rows: RowSink): Promise<void> {
  if (plan.sweepOnly) {
    await sweep(deps, rows);
    return;
  }
  try {
    for (const mib of plan.draftSizes) await draftRung(deps, mib, rows);
    for (const bytes of plan.draftBytes ?? []) await draftRung(deps, { bytes }, rows);
    for (const mib of plan.roundTripSizes) await roundTripRung(deps, mib, rows);
    if (plan.probes) await probes(deps, rows);
  } finally {
    await sweep(deps, rows);
  }
}

export interface LadderArgs extends LadderPlan {
  draftBytes: readonly number[];
  target: string;
  executeTimeoutMs?: number;
}

const USAGE = `Usage: tsx scripts/harnesses/staging-ladder.ts --target=<deployed server URL> [options]

  --sizes=1,4               run only these rungs (MiB; drafts ${LADDER_DRAFT_SIZES_MIB.join("/")}, round trip ${LADDER_ROUNDTRIP_SIZES_MIB.join("/")})
  --draft-bytes=25000000    also run draft rungs at these exact byte sizes; given
                            without --sizes, ONLY these draft rungs run (plus probes)
  --sweep-only              only delete leftover ladder drafts (exact subject match)
  --execute-timeout-ms=<n>  per execute() call; default max(180000, MiB × 8000)

Drafts only — no email is sent. See scripts/harnesses/README.md.
`;

export function parseLadderArgs(argv: readonly string[]): LadderArgs {
  let target: string | undefined;
  let sizes: number[] | undefined;
  let draftBytes: number[] = [];
  let sweepOnly = false;
  let executeTimeoutMs: number | undefined;
  for (const a of argv) {
    if (a === "--") continue;
    if (a === "--sweep-only") { sweepOnly = true; continue; }
    const eq = a.indexOf("=");
    const key = eq < 0 ? a : a.slice(0, eq);
    const value = eq < 0 ? "" : a.slice(eq + 1);
    switch (key) {
      case "--target":
        target = value.replace(/\/$/, "");
        break;
      case "--sizes": {
        const known = new Set<number>([...LADDER_DRAFT_SIZES_MIB, ...LADDER_ROUNDTRIP_SIZES_MIB]);
        sizes = value.split(",").map((s) => Number(s.trim()));
        const bad = sizes.filter((n) => !known.has(n));
        if (bad.length) throw new Error(`--sizes: unknown size ${bad.join(",")} (known: ${[...known].join(",")})\n${USAGE}`);
        break;
      }
      case "--draft-bytes": {
        draftBytes = value.split(",").map((s) => (s.trim() === "" ? NaN : Number(s.trim())));
        const bad = draftBytes.filter((n) => !Number.isSafeInteger(n) || n <= 0);
        if (bad.length || !draftBytes.length) throw new Error(`--draft-bytes: invalid byte size in "${value}"\n${USAGE}`);
        break;
      }
      case "--execute-timeout-ms": {
        const n = Number(value);
        if (!Number.isInteger(n) || n <= 0) throw new Error(`Invalid --execute-timeout-ms: ${value}\n${USAGE}`);
        executeTimeoutMs = n;
        break;
      }
      default:
        throw new Error(`Unrecognised argument: ${a}\n${USAGE}`);
    }
  }
  if (!target) throw new Error(`--target is required\n${USAGE}`);
  // --draft-bytes alone narrows the run to just those draft rungs.
  const only = sizes ?? (draftBytes.length ? [] : undefined);
  const pick = (all: readonly number[]) => (only ? all.filter((n) => only.includes(n)) : [...all]);
  return {
    target,
    draftSizes: pick(LADDER_DRAFT_SIZES_MIB),
    roundTripSizes: pick(LADDER_ROUNDTRIP_SIZES_MIB),
    draftBytes,
    probes: true,
    sweepOnly,
    ...(executeTimeoutMs ? { executeTimeoutMs } : {}),
  };
}

/** The real dependencies. The execute branch runs the no-send guard itself,
 *  so nothing that reaches the client can bypass it, whichever caller built
 *  the code. */
export function realDeps(
  client: Pick<Client, "callTool">,
  opts: { executeTimeoutMs?: number },
): LadderDeps {
  return {
    callTool: async (name, toolArgs, timeoutMs) => {
      if (name === "execute") {
        const code = String(toolArgs.code);
        assertLadderCodeSafe(code);
        return callExecute(client, code, { timeoutMs });
      }
      return (await client.callTool({ name, arguments: toolArgs }, undefined, {
        timeout: timeoutMs,
        resetTimeoutOnProgress: true,
        maxTotalTimeout: 2 * timeoutMs,
      })) as CallToolResult;
    },
    // undici's fetch, like the MCP transport (see HARNESS_FETCH).
    fetch: HARNESS_FETCH,
    fetchTimeoutMs: defaultFetchTimeoutMs,
    executeTimeoutMs: opts.executeTimeoutMs ? () => opts.executeTimeoutMs! : defaultExecuteTimeoutMs,
  };
}

function formatRow(r: Row): string {
  const w = (s: string, n: number) => s.padEnd(n);
  return `${w(r.size, 8)} ${w(r.path, 42)} ${w(String(r.ms), 8)} ${r.ok ? "PASS" : "FAIL"}${r.detail ? `  ${redactSecrets(r.detail)}` : ""}\n`;
}

const HEADER = `${"size".padEnd(8)} ${"path".padEnd(42)} ${"ms".padEnd(8)} status\n`;

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  const args = parseLadderArgs(process.argv.slice(2));
  const client = await connectWithOAuth(args.target);
  const deps = realDeps(client, args.executeTimeoutMs ? { executeTimeoutMs: args.executeTimeoutMs } : {});
  const rows: Row[] = [];
  // Stream each row as it lands, then repeat the full table at the end.
  const live: RowSink = {
    push(r) {
      rows.push(r);
      process.stdout.write(formatRow(r));
    },
  };
  const started = new Date().toISOString();
  process.stdout.write(HEADER);
  try {
    await runLadder(deps, args, live);
  } finally {
    await client.close().catch(() => {});
  }
  process.stdout.write(`\nSummary:\n${HEADER}${rows.map(formatRow).join("")}`);
  process.stdout.write(
    `\nWindow: ${started} → ${new Date().toISOString()}. Check Workers Logs for exceededMemory in this window.\n`,
  );
  process.exit(rows.every((r) => r.ok) ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    process.stderr.write(`[ladder] fatal: ${redactSecrets(err instanceof Error ? (err.stack ?? err.message) : String(err))}\n`);
    process.exit(2);
  });
}

