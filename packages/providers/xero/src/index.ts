import type { ApiProvider } from "@local/scaffold";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import specJson from "./spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { xeroElicitRenderers } from "./elicit-renderers.js";

const spec = specJson as unknown as OpenApiSpec;

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
