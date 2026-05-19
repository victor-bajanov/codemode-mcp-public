import type { ApiProvider } from "@local/scaffold";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import specJson from "./spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { xeroElicitRenderers } from "./elicit-renderers.js";

const spec = specJson as unknown as OpenApiSpec;

const XERO_ATTACHMENT_HINT =
  "Step 3 — forward `f.bytesBase64` to the upstream Xero endpoint matching your operation.\n\n" +
  "Invoice attachment by filename (raw octet-stream PUT):\n" +
  "  await codemode.request({\n" +
  "    method: \"PUT\",\n" +
  "    path: `/api.xro/2.0/Invoices/${invoiceId}/Attachments/${encodeURIComponent(f.filename ?? \"file.pdf\")}`,\n" +
  "    contentType: f.contentType ?? \"application/pdf\",   // forwarded verbatim\n" +
  "    bodyBase64: f.bytesBase64,                          // host decodes before fetching\n" +
  "  });\n\n" +
  "Files API upload (multipart/form-data POST /files.xro/1.0/Files):\n" +
  "  await codemode.request({\n" +
  "    method: \"POST\",\n" +
  "    path: \"/files.xro/1.0/Files\",\n" +
  "    multipart: [\n" +
  "      { name: \"Name\", value: f.filename ?? \"upload.pdf\" },\n" +
  "      { name: \"file\", filename: f.filename ?? \"upload.pdf\", contentType: f.contentType ?? \"application/pdf\", bodyBase64: f.bytesBase64 },\n" +
  "    ],\n" +
  "    // Do NOT set contentType here — the host generates the multipart boundary + Content-Type header.\n" +
  "  });\n\n" +
  "Notes:\n" +
  "- Both operations are allowed by the Xero surface review (createInvoiceAttachmentByFileName, updateInvoiceAttachmentByFileName, xero.files.uploadFile).\n" +
  "- Never pass `f.bytesBase64` through `rawBody` — that path is for text/XML and will silently corrupt binary.\n\n" +
  "## Downloading an attachment FROM Xero\n\n" +
  "Xero's attachment endpoints return raw bytes when `Accept: application/octet-stream` is set: `GET /api.xro/2.0/Invoices/{InvoiceId}/Attachments/{FileName}` and `GET /files.xro/1.0/Files/{FileId}/Content`. Use `codemode.request` with `returnAs: \"stage\"` — the host streams the bytes straight from upstream into R2 server-side; you get back a file-handle envelope without the bytes ever entering your context.\n\n" +
  "  const r = await codemode.request({\n" +
  "    method: \"GET\",\n" +
  "    path: `/api.xro/2.0/Invoices/${invoiceId}/Attachments/${encodeURIComponent(fileName)}`,\n" +
  "    headers: { Accept: \"application/octet-stream\" },\n" +
  "    returnAs: \"stage\",\n" +
  "  });\n" +
  "  if (!r.success) throw new Error(`stage: ${r.status}`);\n" +
  "  return {\n" +
  "    file_handle: r.result.file_handle,\n" +
  "    token: r.result.token,\n" +
  "    fetch_url: r.result.fetch_url,\n" +
  "    byte_length: r.result.byte_length,\n" +
  "  };\n\n" +
  "Notes:\n" +
  "- Content-Type comes from the upstream response header; filename, if present in `Content-Disposition`, is also passed through to the stage row.\n" +
  "- On non-2xx upstream (e.g. 404), the normal error envelope is returned — staging only runs on success.\n" +
  "- The surface review must permit the read endpoint (Invoices/Attachments by-name, Files/Content) — check `surface-review.ts` if `codemode.request` rejects the path.";

export interface XeroProps extends Record<string, unknown> {
  refreshToken: string;
  tenantId: string;
  userId: string;
  email?: string;
}

export const xeroProvider: ApiProvider<XeroProps> = {
  name: "xero",
  displayName: "Xero",
  oauth: {
    authorizeUrl: "https://login.xero.com/identity/connect/authorize",
    tokenUrl: "https://identity.xero.com/connect/token",
    scopes: [
      "openid", "profile", "email", "offline_access",
      // Accounting reads — granular, replacing deprecated accounting.transactions.read + accounting.reports.read
      "accounting.invoices.read",
      "accounting.payments.read",
      "accounting.banktransactions.read",
      "accounting.manualjournals.read",
      "accounting.contacts.read",
      "accounting.attachments.read",
      "accounting.settings.read",
      // accounting.journals.read intentionally omitted — Xero rejects it with invalid_scope
      // for this client_id despite the documented auto-assignment for post-March-2026 PKCE apps.
      // Pending resolution via Xero developer portal / support; bisect history on debug/xero-scope-bisect.
      "accounting.budgets.read",
      "accounting.reports.aged.read",
      "accounting.reports.balancesheet.read",
      "accounting.reports.banksummary.read",
      "accounting.reports.budgetsummary.read",
      "accounting.reports.executivesummary.read",
      "accounting.reports.profitandloss.read",
      "accounting.reports.trialbalance.read",
      "accounting.reports.taxreports.read",
      // Accounting writes — granular, replacing deprecated accounting.transactions
      // Only the families with Tier 1 surface entries plus payments (createBatchPayment lights up in slice 3).
      // accounting.manualjournals (write) intentionally omitted — no surface entry.
      "accounting.invoices",
      "accounting.banktransactions",
      "accounting.payments",
      "accounting.contacts",
      "accounting.attachments",
      // Files
      "files.read", "files",
      // Payroll AU (read-only)
      "payroll.employees.read", "payroll.payruns.read", "payroll.payslip.read",
      "payroll.timesheets.read", "payroll.settings.read",
    ],
    clientIdSecretName: "XERO_CLIENT_ID",
    clientSecretSecretName: "XERO_CLIENT_SECRET",
    userInfoUrl: "https://identity.xero.com/connect/userinfo",
  },
  spec,
  surfaceReview,
  elicitRenderers: xeroElicitRenderers,
  apiBaseUrl: "https://api.xero.com",
  attachmentHint: XERO_ATTACHMENT_HINT,

  tokenRotation: "rotating",
  requestHeaders: (props) => ({ "xero-tenant-id": props.tenantId }),

  completeAuthHook: async ({ tokens }) => {
    const r = await fetch("https://api.xero.com/connections", {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!r.ok) {
      throw new Error(`Xero /connections: ${r.status}`);
    }
    const conns = (await r.json()) as Array<{ tenantId: string; tenantName: string }>;
    if (!Array.isArray(conns) || conns.length === 0) {
      throw new Error("Xero grant has no tenant connections");
    }
    if (conns.length > 1) {
      const names = conns.map((c) => c.tenantName).join(", ");
      throw new Error(
        `Multiple tenants granted (${names}); please re-authorise selecting only one`,
      );
    }
    return { tenantId: conns[0]!.tenantId };
  },

  audit: {
    principalIdAccessor: (props) => props.userId,
    contextAccessor: (props) =>
      typeof props.tenantId === "string" ? { tenantId: props.tenantId } : undefined,
  },
};

export { spec, surfaceReview };
