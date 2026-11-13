// F2-5 regression, end to end: the real request handler with the real Xero
// provider (spec, surface review, attachment inspector, requestHeaders hook).
// Only the edges are mocked: upstream `fetch`, the token broker, and the MCP
// server's `elicitInput` (never called: every outcome is an allow or a deny).
//
// Attacker: a prompt-injected LLM in a legitimate Xero user's session.
// Precondition: a connected Xero tenant and an issued customer invoice whose
//   id any read lists (its online-invoice link is what the customer opens).
// Payload: `PUT /Invoices/<id>/Attachments/Updated-bank-details.pdf
//   ?IncludeOnline=true` with `contentType: application/pdf` and the bytes of
//   a PDF telling the customer to pay a new bank account — published on the
//   customer's online invoice, next to the real invoice; variants with
//   `IncludeOnline` as `"True"` / `1`, under another letter case, and on the
//   `update*` POSTs; an executable MIME type; a JSON body; a bytes update
//   (POST) replacing a file that may already be published online.
// Control: the two `create{Invoice,CreditNote}AttachmentByFileName` PUTs
//   run `inspectAttachmentUpload` (`IncludeOnline` with any value
//   other than `false` → `attachment-include-online`; MIME outside the
//   accepted set → `attachment-bad-mime`; a JSON or multipart body →
//   `attachment-not-bytes`; over 25 MiB → `attachment-too-large`) with
//   `acceptsStaged` so the composed staged upload the provider hint recommends
//   still works. An upload without `IncludeOnline` stays allowed: the file is
//   internal. D-2 (`undeclared-query-param`) already refuses `includeonline`
//   under another spelling; that probe is a control and asserts D-2's reason,
//   not the inspector's. The two `update*` POSTs are removed from the surface
//   review (wave-3 security review): a bytes update could overwrite a file
//   already published online with no way to check or reset IncludeOnline.
// Pre-fix: the four attachment entries were bare `{ decision: "allow", category:
//   "standard_write" }` with the inspector written, tested and wired nowhere:
//   the PUT with `?IncludeOnline=true` left the Worker with a plain `allow`
//   audit line. Each `FIXED` probe asserts the inspector's deny reason or the
//   exact URL/bytes sent, so it fails against those entries (verified by
//   reverting the entries to the bare allow and watching the suite fail).

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";
import { inspectAttachmentUpload } from "../inspectors/attachments";

interface Wire {
  url: string;
  method: string;
  body: string | undefined;
  headers: Record<string, string>;
}

// Invented ids (GUID-shaped so they look like Xero's).
const INVOICE_ID = "a77a77a7-0000-4000-8000-000000000001";
const CREDIT_NOTE_ID = "cccccccc-0000-4000-8000-000000000001";
const FILE = "Updated-bank-details.pdf";
const INVOICE_ATTACHMENT_PATH = `/api.xro/2.0/Invoices/${INVOICE_ID}/Attachments/${FILE}`;
const INVOICE_ATTACHMENT_URL = `${xeroProvider.apiBaseUrl}${INVOICE_ATTACHMENT_PATH}`;
const CREDIT_NOTE_ATTACHMENT_PATH = `/api.xro/2.0/CreditNotes/${CREDIT_NOTE_ID}/Attachments/${FILE}`;
const OP_CREATE_INVOICE = "xero.accounting.createInvoiceAttachmentByFileName";
const OP_UPDATE_INVOICE = "xero.accounting.updateInvoiceAttachmentByFileName";
const OP_CREATE_CREDIT_NOTE = "xero.accounting.createCreditNoteAttachmentByFileName";
const OP_UPDATE_CREDIT_NOTE = "xero.accounting.updateCreditNoteAttachmentByFileName";

// The review's file: a PDF that tells the customer to pay somewhere else.
const PDF_TEXT = "%PDF-1.4 Our bank details have changed. Please remit all payments to BSB 062-000 account 13371337.";
const PDF_B64 = Buffer.from(PDF_TEXT).toString("base64");

function harness(opts: { capabilities?: Record<string, unknown> } = {}) {
  const wire: Wire[] = [];
  const audits: Array<Record<string, unknown>> = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const b = init?.body;
      const body =
        typeof b === "string" ? b
          : b instanceof Uint8Array ? new TextDecoder().decode(b)
            : b == null ? undefined : String(b);
      wire.push({ url: String(url), method: String(init?.method), body, headers: { ...(init?.headers as Record<string, string>) } });
      return new Response(JSON.stringify({ Status: "OK" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    if (typeof line === "string" && line.startsWith("AUDIT ")) {
      audits.push(JSON.parse(line.slice(6)) as Record<string, unknown>);
    }
  });

  const elicitInput = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
  const server = {
    server: {
      getClientCapabilities: () => opts.capabilities ?? { elicitation: {} },
      elicitInput,
    },
  };
  const props: XeroProps = { refreshToken: "rt", tenantId: "tenant-a", userId: "user-a" };

  const call = (ctx: UpstreamCtx) =>
    handleUpstreamRequest<XeroProps>({
      ctx,
      spec: xeroProvider.spec,
      surfaceReview: xeroProvider.surfaceReview,
      apiBaseUrl: xeroProvider.apiBaseUrl,
      deploymentName: "test",
      props,
      server: server as never,
      oauth: {
        refreshTokenAccessor: (p) => p.refreshToken,
        userIdAccessor: (p) => p.userId,
        broker: { getOrRefreshAccessToken: async () => "AT" },
      },
      ...(xeroProvider.requestHeaders ? { requestHeaders: xeroProvider.requestHeaders } : {}),
      ...(xeroProvider.elicitRenderers ? { elicitRenderers: xeroProvider.elicitRenderers } : {}),
      audit: {},
      env: { ALLOW_PII_IN_LOGS: "true" },
    });

  return { call, wire, audits, elicitInput };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const pdfUpload = (path: string, query?: UpstreamCtx["query"]): UpstreamCtx => ({
  method: "PUT",
  path,
  ...(query !== undefined ? { query } : {}),
  bodyBase64: PDF_B64,
  contentType: "application/pdf",
});

describe("a file cannot be published on the customer's online invoice (F2-5)", () => {
  it("FIXED (F2-5): `?IncludeOnline=true` is denied `attachment-include-online`; nothing sent, no dialog", async () => {
    const h = harness();
    await expect(h.call(pdfUpload(INVOICE_ATTACHMENT_PATH, { IncludeOnline: true })))
      .rejects.toThrow(/IncludeOnline publishes the attachment on the customer's online invoice/);
    expect(h.wire).toHaveLength(0);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audits.at(-1)).toMatchObject({
      operationId: OP_CREATE_INVOICE,
      decision: "deny",
      category: "external_data_flow",
      reason: "attachment-include-online",
    });
  });

  it("FIXED (F2-5): the same on a credit note is denied the same way", async () => {
    const h = harness();
    await expect(h.call(pdfUpload(CREDIT_NOTE_ATTACHMENT_PATH, { IncludeOnline: "true" })))
      .rejects.toThrow(/IncludeOnline publishes/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ operationId: OP_CREATE_CREDIT_NOTE, decision: "deny", reason: "attachment-include-online" });
  });

  it("FIXED (F2-5): `IncludeOnline: \"True\"`, `1` and `\"yes\"` are denied by the inspector (only `false` is off)", async () => {
    const h = harness();
    for (const v of ["True", 1, "yes", ""]) {
      await expect(h.call(pdfUpload(INVOICE_ATTACHMENT_PATH, { IncludeOnline: v })), JSON.stringify(v))
        .rejects.toThrow(/IncludeOnline publishes/);
      expect(h.audits.at(-1), JSON.stringify(v)).toMatchObject({ decision: "deny", reason: "attachment-include-online" });
    }
    expect(h.wire).toHaveLength(0);
  });

  it("REFUTED: the same upload without the query is sent — URL without a query, bytes verbatim, content-type application/pdf", async () => {
    const h = harness();
    await h.call(pdfUpload(INVOICE_ATTACHMENT_PATH));
    expect(h.wire).toHaveLength(1);
    const sent = h.wire[0]!;
    expect(sent.method).toBe("PUT");
    expect(sent.url).toBe(INVOICE_ATTACHMENT_URL);
    expect(sent.url).not.toContain("?");
    expect(sent.body).toBe(PDF_TEXT);
    expect(sent.headers["content-type"]).toBe("application/pdf");
    expect(sent.headers["Authorization"]).toBe("Bearer AT");
    expect(sent.headers["xero-tenant-id"]).toBe("tenant-a");
    expect(h.audits).toHaveLength(1);
    expect(h.audits[0]).toMatchObject({ operationId: OP_CREATE_INVOICE, decision: "allow" });
  });

  it("REFUTED: `IncludeOnline: false` and `\"false\"` are sent with the pair on the URL", async () => {
    for (const v of [false, "false", "FALSE"] as const) {
      const h = harness();
      await h.call(pdfUpload(INVOICE_ATTACHMENT_PATH, { IncludeOnline: v }));
      expect(h.wire.map((w) => w.url), JSON.stringify(v)).toEqual([`${INVOICE_ATTACHMENT_URL}?IncludeOnline=${String(v)}`]);
      expect(h.audits.at(-1), JSON.stringify(v)).toMatchObject({ decision: "allow", queryKeys: ["IncludeOnline"] });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("REFUTED: `?includeonline=true` (another letter case) is refused `undeclared-query-param` by D-2 before the inspector (control)", async () => {
    const h = harness();
    await expect(h.call(pdfUpload(INVOICE_ATTACHMENT_PATH, { includeonline: true })))
      .rejects.toThrow(/does not accept query parameter "includeonline"/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", category: "url_safety", reason: "undeclared-query-param" });
  });

  // Wave-3 security review: a bytes update (POST) replaces an attachment that
  // may already be shown on the customer's online invoice, and the POST cannot
  // carry (so cannot check or reset) IncludeOnline. Both update routes were
  // removed from the surface review; re-upload under a new name via the PUT.
  it("FIXED (wave-3 review): the update POSTs are not in the surface review; nothing is sent, with or without IncludeOnline", async () => {
    const h = harness();
    for (const [path, op] of [[INVOICE_ATTACHMENT_PATH, OP_UPDATE_INVOICE], [CREDIT_NOTE_ATTACHMENT_PATH, OP_UPDATE_CREDIT_NOTE]] as const) {
      await expect(h.call({ ...pdfUpload(path), method: "POST" }), op).rejects.toThrow(/not in surface review/);
      expect(h.audits.at(-1), op).toMatchObject({ operationId: op, decision: "deny", reason: "not-in-surface-review" });
      await expect(h.call({ ...pdfUpload(path, { IncludeOnline: true }), method: "POST" }), op).rejects.toThrow();
      expect(h.audits.at(-1), op).toMatchObject({ operationId: op, decision: "deny" });
    }
    expect(h.wire).toHaveLength(0);
    expect(h.elicitInput).not.toHaveBeenCalled();
  });
});

describe("MIME and body shape are inspected end to end (F2-5)", () => {
  it("FIXED (F2-5): `application/x-msdownload` on the PUT is denied `attachment-bad-mime`; nothing sent", async () => {
    const h = harness();
    await expect(h.call({ ...pdfUpload(INVOICE_ATTACHMENT_PATH), contentType: "application/x-msdownload" })).rejects.toThrow();
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ operationId: OP_CREATE_INVOICE, decision: "deny", reason: "attachment-bad-mime" });
  });

  it("FIXED (F2-5): a JSON `body` on the PUT is denied `attachment-not-bytes`", async () => {
    const h = harness();
    await expect(h.call({ method: "PUT", path: INVOICE_ATTACHMENT_PATH, body: { Attachments: [{ FileName: FILE }] } }))
      .rejects.toThrow(/takes the file's bytes as the whole body/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "attachment-not-bytes" });
  });

  it("FIXED (F2-5): an untyped bodyBase64 (no contentType) is denied `attachment-bad-mime` rather than sent as octet-stream", async () => {
    const h = harness();
    await expect(h.call({ method: "PUT", path: INVOICE_ATTACHMENT_PATH, bodyBase64: PDF_B64 })).rejects.toThrow();
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "attachment-bad-mime" });
  });

  it("REFUTED: a composed staged PDF (the provider hint's upload shape) passes the inspector by its assembled length", () => {
    // The end-to-end staged path needs a staging store (not built here);
    // `acceptsStaged: true` on the two PUT entries is pinned by the wiring test.
    const r = inspectAttachmentUpload({
      staged: [{ index: 0, byteLength: 1024, contentType: "application/pdf", filename: FILE, encoding: "identity" }],
      rawBody: "￼",
      contentType: "application/pdf",
      assembledByteLength: 1024,
    });
    expect(r).toEqual({ decision: "allow" });
    expect(inspectAttachmentUpload({
      staged: [{ index: 0, byteLength: 25 * 1024 * 1024 + 1, contentType: "application/pdf", filename: FILE, encoding: "identity" }],
      rawBody: "￼",
      contentType: "application/pdf",
      assembledByteLength: 25 * 1024 * 1024 + 1,
    })).toMatchObject({ decision: "deny", reason: "attachment-too-large" });
  });
});
