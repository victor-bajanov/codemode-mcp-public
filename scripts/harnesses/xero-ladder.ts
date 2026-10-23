/**
 * Staged transfer v2 live ladder for Xero (issue #59, WP-D).
 *
 * Drives a DEPLOYED Xero server (normally xero-dev, connected to Xero's
 * "Demo Company") through the staged paths in both directions, at sizes up
 * to and just past Xero's request ceiling (measured on the Demo Company: a
 * request body of 10,239,999 B is accepted, 10,240,000 B is refused with 413;
 * see README "Xero limits"):
 *
 *   setup (once): find the ladder's DRAFT invoice by Reference, or create it
 *     (and its contact). Invoices cannot be voided or deleted through this
 *     server (the draft inspector denies those statuses), so one invoice is
 *     reused across runs. Xero caps a document at 10 attachments and has no
 *     attachment delete, so every rung POSTs the same name, which overwrites.
 *     Files API uploads are named per size.
 *   per size N:
 *     register_file_handle → POST N random bytes to upload_url →
 *     execute: POST …/Invoices/{id}/Attachments/{name} with `composed`
 *       (one identity segment) → execute: GET it back with
 *       `returnAs: "stage"` → GET fetch_url, SHA-256 must match →
 *     execute: POST /files.xro/1.0/Files with `multipart[].staged` →
 *       GET …/Files/{id}/Content with `returnAs: "stage"` → SHA-256 →
 *       DELETE the file (xero.files.deleteFile is not in the surface review,
 *       so this is expected to be denied; the file stays in the Inbox).
 *
 * Bodies under the ceiling must be accepted; at or past it they must be
 * refused cleanly (a 4xx or a host refusal, never a 5xx or a timeout), and the
 * exact error is recorded. A Files upload adds multipart overhead, so the last
 * KiB under the ceiling may go either way there.
 *
 * Every execute() call passes `assertXeroCodeSafe`: no status transition
 * beyond DRAFT, no emailing, no payments.
 *
 * Usage:
 *   pnpm exec tsx scripts/harnesses/xero-ladder.ts --target=https://xero-dev.<subdomain>.workers.dev
 */
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { connectWithOAuth } from "./mcp-client.js";
import { realDeps, redactSecrets, type LadderDeps, type Row, type RowSink } from "./staging-ladder.js";

const MIB = 1_048_576;
/** Matches STAGING_MAX_BYTES on the deployments. */
const STAGING_MAX_BYTES = 50 * MIB;

/** Xero documents "10 MB"; measured, a request body must be below this. */
const XERO_REQUEST_CEILING = 10_240_000;
/** Room left for the Files API multipart framing around the file. */
const MULTIPART_SLACK = 1_000;

export const DEFAULT_RUNG_BYTES = [MIB, 4 * MIB, 10_000_000, XERO_REQUEST_CEILING - 1, XERO_REQUEST_CEILING, 10 * MIB + 1] as const;

export const LADDER_INVOICE_REFERENCE = "codemode staging ladder (one attachment)";
export const LADDER_ATTACHMENT_NAME = "codemode-ladder.txt";
const LADDER_CONTACT_NAME = "codemode staging ladder";
// Xero refuses unknown extensions such as .bin (Files API: 400 "not a valid File
// extension"), so the ladder sends printable text as .txt.
const FILE_TYPE = "text/plain";

export interface StagedRef {
  file_handle: string;
  token: string;
}

export type Expectation = "accept" | "reject" | "either";

export function expectationFor(bytes: number, target: "attachment" | "files"): Expectation {
  if (bytes >= XERO_REQUEST_CEILING) return "reject";
  if (target === "files" && bytes >= XERO_REQUEST_CEILING - MULTIPART_SLACK) return "either";
  return "accept";
}

export function ladderFileName(bytes: number): string {
  return `codemode-ladder-${bytes}.txt`;
}

/** Exactly `n` random printable ASCII bytes (base64 alphabet). */
export function ladderBytes(n: number): Uint8Array<ArrayBuffer> {
  const text = randomBytes(Math.ceil((n * 3) / 4) + 3).toString("base64").slice(0, n);
  return new Uint8Array(Buffer.from(text, "latin1"));
}

const sizeLabel = (bytes: number): string => (bytes % MIB === 0 ? `${bytes / MIB} MiB` : `${bytes} B`);

// ---------------------------------------------------------------------------
// Outcome classification
// ---------------------------------------------------------------------------

export interface UploadOutcome {
  ok?: boolean;
  status?: number;
  error?: string | null;
  /** A ToolError the sandbox caught from codemode.request. */
  thrown?: string;
}

const NOT_CLEAN_THROW = /timed? ?out|deadline|abort|internal error|exceeded/i;
/** The upstream refused by closing mid-body (Xero's edge does this for
 *  oversized bodies) and its 413 did not arrive within the host's grace. */
const UPSTREAM_CLOSED = /upstream closed the connection after \d+ of \d+ bytes/;

export function classifyUpload(expect: Expectation, o: UploadOutcome): { ok: boolean; detail: string } {
  if (o.ok === true) {
    return expect === "reject"
      ? { ok: false, detail: `ACCEPTED past the documented limit (status=${o.status ?? "?"})` }
      : { ok: true, detail: `accepted (status=${o.status ?? "?"})` };
  }
  const clean =
    (typeof o.status === "number" && o.status >= 400 && o.status < 500) ||
    (typeof o.thrown === "string" && (UPSTREAM_CLOSED.test(o.thrown) || !NOT_CLEAN_THROW.test(o.thrown)));
  const what = o.thrown !== undefined
    ? `rejected: ${o.thrown}`
    : `rejected: status=${o.status ?? "?"} ${o.error ?? ""}`.trimEnd();
  if (!clean) return { ok: false, detail: `not a clean rejection: ${what}` };
  return { ok: expect !== "accept", detail: what };
}

// ---------------------------------------------------------------------------
// Sandbox code builders
// ---------------------------------------------------------------------------

const attachmentPath = (invoiceId: string, name: string): string =>
  `/api.xro/2.0/Invoices/${encodeURIComponent(invoiceId)}/Attachments/${encodeURIComponent(name)}`;

/** Wraps a request body so a ToolError from codemode.request comes back as
 *  `{ ok: false, thrown }` instead of failing the whole execute() call. */
const guarded = (body: string): string => `async () => {
  try {
${body}
  } catch (e) {
    return { ok: false, thrown: String(e?.message ?? e) };
  }
}`;

const errorReturn =
  "if (!r.success) return { ok: false, status: r.status, error: r.errors?.[0]?.message ?? null };";

export function attachCode(invoiceId: string, name: string, ref: StagedRef): string {
  return guarded(`    const r = await codemode.request({
      method: "POST",
      path: ${JSON.stringify(attachmentPath(invoiceId, name))},
      contentType: ${JSON.stringify(FILE_TYPE)},
      composed: { segments: [{ staged: ${JSON.stringify(ref)}, encoding: "identity" }] },
    });
    ${errorReturn}
    const a = r.result?.Attachments?.[0] ?? {};
    return { ok: true, status: r.status, attachmentId: a.AttachmentID ?? null, contentLength: a.ContentLength ?? null };`);
}

export function filesUploadCode(name: string, ref: StagedRef): string {
  return guarded(`    const r = await codemode.request({
      method: "POST",
      path: "/files.xro/1.0/Files",
      multipart: [
        { name: "Name", value: ${JSON.stringify(name)} },
        { name: "file", staged: ${JSON.stringify(ref)} },
      ],
    });
    ${errorReturn}
    return { ok: true, status: r.status, fileId: r.result?.Id ?? null, size: r.result?.Size ?? null };`);
}

function stageDownloadCode(path: string): string {
  return guarded(`    const r = await codemode.request({
      method: "GET",
      path: ${JSON.stringify(path)},
      headers: { Accept: "application/octet-stream" },
      returnAs: "stage",
    });
    ${errorReturn}
    return { ok: true, status: r.status, fetch_url: r.result.fetch_url, token: r.result.token, byte_length: r.result.byte_length };`);
}

export function stageAttachmentDownloadCode(invoiceId: string, name: string): string {
  return stageDownloadCode(attachmentPath(invoiceId, name));
}

export function stageFileDownloadCode(fileId: string): string {
  return stageDownloadCode(`/files.xro/1.0/Files/${encodeURIComponent(fileId)}/Content`);
}

export function fileDeleteCode(fileId: string): string {
  return guarded(`    const r = await codemode.request({
      method: "DELETE",
      path: ${JSON.stringify(`/files.xro/1.0/Files/${encodeURIComponent(fileId)}`)},
    });
    ${errorReturn}
    return { ok: true, status: r.status };`);
}

/** Find the ladder's DRAFT invoice, or create it (and its contact) as DRAFT. */
export function setupInvoiceCode(): string {
  const ref = JSON.stringify(LADDER_INVOICE_REFERENCE);
  const contact = JSON.stringify(LADDER_CONTACT_NAME);
  return guarded(`    // LADDER_SETUP: one reusable DRAFT invoice; it cannot be voided or deleted here.
    const found = await codemode.request({
      method: "GET",
      path: "/api.xro/2.0/Invoices",
      query: { where: 'Reference==' + JSON.stringify(${ref}) + ' AND Status=="DRAFT"' },
    });
    if (!found.success) return { ok: false, status: found.status, error: found.errors?.[0]?.message ?? null };
    const existing = (found.result?.Invoices ?? [])[0];
    if (existing) return { ok: true, invoiceId: existing.InvoiceID, reused: true };
    const c = await codemode.request({
      method: "GET",
      path: "/api.xro/2.0/Contacts",
      query: { where: 'Name==' + JSON.stringify(${contact}) },
    });
    if (!c.success) return { ok: false, status: c.status, error: c.errors?.[0]?.message ?? null };
    let contactId = (c.result?.Contacts ?? [])[0]?.ContactID;
    if (!contactId) {
      const made = await codemode.request({
        method: "PUT",
        path: "/api.xro/2.0/Contacts",
        body: { Contacts: [{ Name: ${contact} }] },
      });
      if (!made.success) return { ok: false, status: made.status, error: made.errors?.[0]?.message ?? null };
      contactId = made.result.Contacts[0].ContactID;
    }
    const r = await codemode.request({
      method: "PUT",
      path: "/api.xro/2.0/Invoices",
      body: { Invoices: [{
        Type: "ACCREC",
        Status: "DRAFT",
        Contact: { ContactID: contactId },
        Reference: ${ref},
        LineAmountTypes: "NoTax",
        LineItems: [{ Description: "codemode staging ladder: holds test attachments; never sent", Quantity: 1, UnitAmount: 0 }],
      }] },
    });
    ${errorReturn}
    return { ok: true, invoiceId: r.result.Invoices[0].InvoiceID, reused: false };`);
}

/** Throws unless `code` stays inside what the ladder may do in Xero: no
 *  status transition past DRAFT, no emailing the contact, no payments. */
export function assertXeroCodeSafe(code: string): void {
  const rules: Array<[RegExp, string]> = [
    [/\b(AUTHORISED|VOIDED|DELETED|PAID|SUBMITTED)\b/, "a status transition"],
    [/SentToContact\s*:\s*true/, "SentToContact"],
    [/\/Email\b/, "an email endpoint"],
    [/Payments\b/, "a payment endpoint"],
  ];
  for (const [re, what] of rules) {
    if (re.test(code)) throw new Error(`xero ladder refuses code containing ${what}`);
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

function toolJson(result: CallToolResult): Record<string, unknown> {
  const text = result.content?.find((c) => c.type === "text") as { text?: string } | undefined;
  const raw = text?.text ?? "";
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    const i = raw.indexOf("{");
    if (i >= 0) {
      try {
        return JSON.parse(raw.slice(i)) as Record<string, unknown>;
      } catch {
        /* fall through */
      }
    }
    return { unparsed: raw.slice(0, 300) };
  }
}

type Exec = (code: string) => Promise<Record<string, unknown>>;

function execFor(deps: LadderDeps, mib: number): Exec {
  return async (code) => {
    assertXeroCodeSafe(code);
    const result = await deps.callTool("execute", { code }, deps.executeTimeoutMs(mib));
    const parsed = toolJson(result);
    if (result.isError) {
      return { ok: false, thrown: typeof parsed.unparsed === "string" ? parsed.unparsed : JSON.stringify(parsed) };
    }
    return parsed;
  };
}

const errText = (err: unknown): string => redactSecrets(err instanceof Error ? err.message : String(err));

type Settled<T> = { ms: number } & ({ ok: true; value: T } | { ok: false; error: string });

async function settle<T>(fn: () => Promise<T>): Promise<Settled<T>> {
  const t0 = performance.now();
  try {
    const value = await fn();
    return { ms: Math.round(performance.now() - t0), ok: true, value };
  } catch (err) {
    return { ms: Math.round(performance.now() - t0), ok: false, error: errText(err) };
  }
}

const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

async function registerAndUpload(deps: LadderDeps, mib: number, bytes: Uint8Array<ArrayBuffer>, filename: string): Promise<StagedRef> {
  const res = await deps.callTool(
    "register_file_handle",
    { content_type: FILE_TYPE, expected_byte_len: bytes.byteLength, filename },
    60_000,
  );
  const reg = toolJson(res) as { upload_url?: string; token?: string; file_handle?: string };
  if (!reg.upload_url || !reg.token || !reg.file_handle) throw new Error("register_file_handle returned no upload slot");
  const put = await deps.fetch(reg.upload_url, {
    method: "POST",
    headers: { Authorization: `Bearer ${reg.token}`, "Content-Type": FILE_TYPE },
    body: bytes,
    signal: AbortSignal.timeout(deps.fetchTimeoutMs(mib)),
  });
  if (put.status !== 204) throw new Error(`upload returned HTTP ${put.status}`);
  return { file_handle: reg.file_handle, token: reg.token };
}

/** execute a returnAs:"stage" download, then GET fetch_url and compare. */
async function stageAndCompare(deps: LadderDeps, mib: number, exec: Exec, code: string, expected: string) {
  const s = (await exec(code)) as { ok?: boolean; fetch_url?: string; token?: string; status?: number; error?: string; thrown?: string };
  if (!s.ok || !s.fetch_url || !s.token) {
    return { ok: false, detail: s.thrown ?? `status=${s.status ?? "?"} ${s.error ?? ""}`.trimEnd() };
  }
  const r = await deps.fetch(s.fetch_url, {
    headers: { Authorization: `Bearer ${s.token}` },
    signal: AbortSignal.timeout(deps.fetchTimeoutMs(mib)),
  });
  if (!r.ok) return { ok: false, detail: `fetch returned HTTP ${r.status}` };
  const back = new Uint8Array(await r.arrayBuffer());
  const same = sha256(back) === expected;
  return { ok: same, detail: same ? `bytes=${back.byteLength}` : `hash mismatch (bytes=${back.byteLength})` };
}

const DENIED = /not in surface review|denied by surface review/i;

export interface XeroPlan {
  bytes: readonly number[];
  attachments: boolean;
  files: boolean;
}

async function setupInvoice(deps: LadderDeps, rows: RowSink): Promise<string | undefined> {
  const r = await settle(() => execFor(deps, 1)(setupInvoiceCode()));
  const v = (r.ok ? r.value : {}) as { ok?: boolean; invoiceId?: string; reused?: boolean; status?: number; error?: string; thrown?: string };
  const ok = r.ok && Boolean(v.ok && v.invoiceId);
  rows.push({
    size: "-",
    path: "setup ladder invoice",
    ms: r.ms,
    ok,
    detail: !r.ok
      ? r.error
      : ok
        ? `${v.reused ? "reused" : "created"} DRAFT ${v.invoiceId}`
        : v.thrown ?? `status=${v.status ?? "?"} ${v.error ?? ""}`.trimEnd(),
  });
  return ok ? v.invoiceId : undefined;
}

async function rung(deps: LadderDeps, bytesN: number, invoiceId: string | undefined, plan: XeroPlan, rows: RowSink): Promise<void> {
  const size = sizeLabel(bytesN);
  const mib = Math.ceil(bytesN / MIB);
  const exec = execFor(deps, mib);
  const name = ladderFileName(bytesN);
  const bytes = ladderBytes(bytesN);
  const digest = sha256(bytes);

  const up = await settle(() => registerAndUpload(deps, mib, bytes, name));
  rows.push({ size, path: "upload", ms: up.ms, ok: up.ok, detail: up.ok ? "" : up.error });
  if (!up.ok) return;
  const ref = up.value;

  if (plan.attachments && invoiceId) {
    const a = await settle(() => exec(attachCode(invoiceId, LADDER_ATTACHMENT_NAME, ref)));
    const outcome = (a.ok ? a.value : {}) as UploadOutcome & { contentLength?: number };
    const c = a.ok ? classifyUpload(expectationFor(bytesN, "attachment"), outcome) : { ok: false, detail: a.error };
    rows.push({ size, path: "invoice attachment (composed identity)", ms: a.ms, ...c });
    if (a.ok && outcome.ok) {
      const d = await settle(() => stageAndCompare(deps, mib, exec, stageAttachmentDownloadCode(invoiceId, LADDER_ATTACHMENT_NAME), digest));
      rows.push({ size, path: "attachment → stage → fetch (sha256)", ms: d.ms, ...(d.ok ? d.value : { ok: false, detail: d.error }) });
    }
  }

  if (plan.files) {
    const f = await settle(() => exec(filesUploadCode(name, ref)));
    const outcome = (f.ok ? f.value : {}) as UploadOutcome & { fileId?: string };
    const c = f.ok ? classifyUpload(expectationFor(bytesN, "files"), outcome) : { ok: false, detail: f.error };
    rows.push({ size, path: "files.uploadFile (multipart staged)", ms: f.ms, ...c });
    const fileId = f.ok && outcome.ok ? outcome.fileId : undefined;
    if (fileId) {
      const d = await settle(() => stageAndCompare(deps, mib, exec, stageFileDownloadCode(fileId), digest));
      rows.push({ size, path: "file → stage → fetch (sha256)", ms: d.ms, ...(d.ok ? d.value : { ok: false, detail: d.error }) });
      const del = await settle(() => exec(fileDeleteCode(fileId)));
      const v = (del.ok ? del.value : {}) as UploadOutcome;
      const denied = typeof v.thrown === "string" && DENIED.test(v.thrown);
      rows.push({
        size,
        path: "files.deleteFile (cleanup)",
        ms: del.ms,
        ok: del.ok && (v.ok === true || denied),
        detail: !del.ok
          ? del.error
          : v.ok
            ? "deleted"
            : denied
              ? `denied by surface review; left in the Files Inbox as ${name}`
              : v.thrown ?? `status=${v.status ?? "?"} ${v.error ?? ""}`.trimEnd(),
      });
    }
  }
}

/** The whole run. Every step records its own row and never throws. */
export async function runXeroLadder(deps: LadderDeps, plan: XeroPlan, rows: RowSink): Promise<void> {
  const invoiceId = plan.attachments ? await setupInvoice(deps, rows) : undefined;
  for (const n of plan.bytes) await rung(deps, n, invoiceId, plan, rows);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export interface XeroArgs extends XeroPlan {
  target: string;
  executeTimeoutMs?: number;
}

const USAGE = `Usage: tsx scripts/harnesses/xero-ladder.ts --target=<deployed Xero server URL> [options]

  --bytes=1048576,10485761   run only these sizes, in bytes (1..${STAGING_MAX_BYTES})
                             default ${DEFAULT_RUNG_BYTES.join(",")}
  --only=attachments|files   run one target only (default both)
  --execute-timeout-ms=<n>   per execute() call; default max(180000, MiB × 8000)

Writes to Xero's Demo Company only. See scripts/harnesses/README.md.
`;

export function parseXeroArgs(argv: readonly string[]): XeroArgs {
  let target: string | undefined;
  let bytes: number[] = [...DEFAULT_RUNG_BYTES];
  let attachments = true;
  let files = true;
  let executeTimeoutMs: number | undefined;
  for (const a of argv) {
    if (a === "--") continue;
    const eq = a.indexOf("=");
    const key = eq < 0 ? a : a.slice(0, eq);
    const value = eq < 0 ? "" : a.slice(eq + 1);
    switch (key) {
      case "--target":
        target = value.replace(/\/$/, "");
        break;
      case "--bytes":
        bytes = value.split(",").map((s) => Number(s.trim()));
        for (const n of bytes) {
          if (!Number.isInteger(n) || n < 1 || n > STAGING_MAX_BYTES) {
            throw new Error(`--bytes: ${n} is not an integer in 1..${STAGING_MAX_BYTES}\n${USAGE}`);
          }
        }
        break;
      case "--only":
        if (value !== "attachments" && value !== "files") throw new Error(`--only: expected attachments or files\n${USAGE}`);
        attachments = value === "attachments";
        files = value === "files";
        break;
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
  return { target, bytes, attachments, files, ...(executeTimeoutMs ? { executeTimeoutMs } : {}) };
}

const HEADER = `${"size".padEnd(12)} ${"path".padEnd(40)} ${"ms".padEnd(8)} status\n`;

export function formatXeroRow(r: Row): string {
  return `${r.size.padEnd(12)} ${r.path.padEnd(40)} ${String(r.ms).padEnd(8)} ${r.ok ? "PASS" : "FAIL"}${r.detail ? `  ${redactSecrets(r.detail)}` : ""}\n`;
}

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  const args = parseXeroArgs(process.argv.slice(2));
  const client = await connectWithOAuth(args.target);
  const deps = realDeps(client, args.executeTimeoutMs ? { executeTimeoutMs: args.executeTimeoutMs } : {});
  const rows: Row[] = [];
  const live: RowSink = {
    push(r) {
      rows.push(r);
      process.stdout.write(formatXeroRow(r));
    },
  };
  const started = new Date().toISOString();
  process.stdout.write(HEADER);
  try {
    await runXeroLadder(deps, args, live);
  } finally {
    await client.close().catch(() => {});
  }
  process.stdout.write(`\nSummary:\n${HEADER}${rows.map(formatXeroRow).join("")}`);
  process.stdout.write(
    `\nWindow: ${started} → ${new Date().toISOString()}. Check Workers Logs for exceededMemory in this window.\n`,
  );
  process.exit(rows.every((r) => r.ok) ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    process.stderr.write(`[xero-ladder] fatal: ${redactSecrets(err instanceof Error ? (err.stack ?? err.message) : String(err))}\n`);
    process.exit(2);
  });
}
