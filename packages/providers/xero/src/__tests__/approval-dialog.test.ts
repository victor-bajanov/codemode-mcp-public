// D-1 / F2-3 regression, end to end: the real request handler with the real
// Xero provider (spec, surface review, elicit renderers, requestHeaders hook).
// Only the edges are mocked: upstream `fetch`, the token broker, and the MCP
// server's `elicitInput` (captured exactly as a client would receive it).
//
// Attacker: a prompt-injected LLM in a legitimate Xero user's session, whose
//   task plausibly ends in "email an invoice" or "record a batch payment", so
//   an approval prompt is expected.
// Precondition: an MCP client that supports elicitation.
// Payload: a batch payment to an account and amount of the attacker's choice;
//   an emailInvoice on an invoice the attacker built; a decoy top-level
//   `Payments` key; the same batch as raw XML / text/plain / untyped bytes.
// Control: the dialog message carries the request line and the resolved facts
//   (invoice id from the path, batch count/total/accounts/payee bank accounts/
//   invoices from the real `BatchPayments[].Payments[]` shape); the form is
//   confirm-only and only `{ confirm: true }` approves; bodies that cannot be
//   shown are denied before any dialog.
// Pre-fix: the dialog was a constant string plus empty typed inputs, the
//   emailInvoice renderer read an inspector summary no inspector produced, the
//   batch renderer read `body.Payments` (absent on a real batch, steerable by a
//   decoy), any type-correct answer approved, and raw bodies were approvable
//   behind an "cannot be shown" headline.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";

interface Dialog {
  message: string;
  requestedSchema: unknown;
}

interface Wire {
  url: string;
  method: string;
  body: string | undefined;
}

const CONFIRM_ONLY = {
  type: "object",
  properties: { confirm: { type: "boolean" } },
  required: ["confirm"],
  additionalProperties: false,
};

const BATCH_PATH = "/api.xro/2.0/BatchPayments";

function harness(opts: {
  answer?: (d: Dialog) => unknown;
  capabilities?: Record<string, unknown>;
} = {}) {
  const dialogs: Dialog[] = [];
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
      wire.push({ url: String(url), method: String(init?.method), body });
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

  const elicitInput = vi.fn(async (params: unknown) => {
    const d = params as Dialog;
    dialogs.push(d);
    return opts.answer ? opts.answer(d) : { action: "accept", content: { confirm: true } };
  });
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
      // So the audit line carries the facts verbatim and can be compared.
      env: { ALLOW_PII_IN_LOGS: "true" },
    });

  return { call, dialogs, wire, audits, elicitInput };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const realBatch = {
  BatchPayments: [
    {
      Account: { AccountID: "ac993f75-035b-433c-82e0-7b7a2d40802c" },
      Date: "2026-11-10",
      Reference: "Nov supplier run",
      Payments: [
        { Invoice: { InvoiceID: "11111111-0000-4000-8000-000000000001" }, BankAccountNumber: "062-000 13371337", Amount: 92500 },
        { Invoice: { InvoiceID: "11111111-0000-4000-8000-000000000002" }, BankAccountNumber: "062-000 13371337", Amount: 92500 },
      ],
    },
  ],
};

describe("createBatchPayment dialog shows what is being paid (D-1 #3, F2-3b, C-elicit)", () => {
  it("FIXED (D-1): a 1.00 batch and a 99,999.00 batch to another account get different dialogs naming both", async () => {
    const h = harness();
    const batch = (accountId: string, amount: number) => ({
      BatchPayments: [
        { Account: { AccountID: accountId }, Date: "2026-11-09", Payments: [{ Invoice: { InvoiceID: "inv-1" }, Amount: amount }] },
      ],
    });
    await h.call({ method: "PUT", path: BATCH_PATH, body: batch("operating-account", 1.0) });
    await h.call({ method: "PUT", path: BATCH_PATH, body: batch("ATTACKER-CHOSEN-ACCOUNT", 99999.0) });

    expect(h.dialogs).toHaveLength(2);
    expect(h.dialogs[1]!.message).not.toBe(h.dialogs[0]!.message);
    expect(h.dialogs[0]!.message).toContain("total: 1\n");
    expect(h.dialogs[0]!.message).toContain('accounts: "operating-account"');
    expect(h.dialogs[1]!.message).toContain("total: 99999\n");
    expect(h.dialogs[1]!.message).toContain('accounts: "ATTACKER-CHOSEN-ACCOUNT"');
    expect(h.wire).toHaveLength(2);
  });

  it("FIXED (F2-3): a $185,000 two-payment batch shows count, total, payee bank account and invoices", async () => {
    const h = harness();
    await h.call({ method: "PUT", path: BATCH_PATH, body: realBatch });

    expect(h.dialogs).toHaveLength(1);
    const d = h.dialogs[0]!;
    expect(d.requestedSchema).toEqual(CONFIRM_ONLY);
    expect(d.message.split("\n")).toEqual([
      "Confirm Xero financial op (xero.accounting.createBatchPayment)",
      `Request: PUT ${BATCH_PATH}`,
      "batches: 1",
      "payments: 2",
      "total: 185000",
      'accounts: "ac993f75-035b-433c-82e0-7b7a2d40802c"',
      'bankAccounts: "062-000 13371337"',
      'targets: "Invoice 11111111-0000-4000-8000-000000000001, Invoice 11111111-0000-4000-8000-000000000002"',
      "Approve only if this is exactly the request you intended.",
    ]);
    // The audit records exactly the facts the dialog showed.
    const accepted = h.audits.find((a) => a.elicitationOutcome === "accepted");
    expect(accepted?.elicitFields).toMatchObject({ payments: 2, total: 185000, bankAccounts: "062-000 13371337" });
    expect(h.wire).toHaveLength(1);
    expect(JSON.parse(h.wire[0]!.body!)).toEqual(realBatch);
  });

  it("FIXED (F2-3): a decoy top-level `Payments` key is flagged and its amount never becomes the total", async () => {
    const h = harness();
    await h.call({ method: "PUT", path: BATCH_PATH, body: { ...realBatch, Payments: [{ Amount: 1 }] } });

    const m = h.dialogs[0]!.message;
    expect(m).toContain('unexpectedKeys: "Payments"');
    expect(m).toContain('total: "not numeric"');
    expect(m).toContain("payments: 2");
    expect(m).not.toContain("total: 1\n");
  });

  it("FIXED (D-1): a bare single batch (no BatchPayments wrapper) paying 99999 never shows total 0", async () => {
    const h = harness();
    await h.call({
      method: "PUT",
      path: BATCH_PATH,
      body: {
        Account: { AccountID: "ATTACKER-CHOSEN-ACCOUNT" },
        Payments: [{ Invoice: { InvoiceID: "inv-1" }, BankAccountNumber: "06-0001-0666666-00", Amount: 99999 }],
      },
    });
    const m = h.dialogs[0]!.message;
    expect(m).not.toContain("total: 0");
    expect(m).toContain("total: 99999");
    expect(m).toContain('accounts: "ATTACKER-CHOSEN-ACCOUNT"');
    expect(m).toContain('bankAccounts: "06-0001-0666666-00"');
  });

  it("FIXED (D-1): warning facts come before the lists, so the 8-fact cap never hides them", async () => {
    const h = harness();
    await h.call({
      method: "PUT",
      path: BATCH_PATH,
      body: {
        BatchPayments: [{
          Account: { AccountID: "acct-1" },
          Payments: [
            { Invoice: { InvoiceID: "inv-1" }, BankAccountNumber: "bank-1", Amount: 100000 },
            { CreditNote: { CreditNoteID: "cn-1" }, BankAccountNumber: "bank-2", Amount: -99999 },
            { Invoice: { InvoiceID: "inv-2" }, BankAccountNumber: "bank-3", Amount: 1, amount: 2 },
          ],
        }],
        Decoy: true,
      },
    });
    const m = h.dialogs[0]!.message;
    expect(m).toContain('total: "not numeric"');
    expect(m).toContain("nonPositiveAmounts: 1");
    expect(m).toContain('unexpectedKeys: "Decoy"');
    expect(m).toContain('ambiguousKeys: "Amount"');
    expect(m).toContain('accounts: "acct-1"');
    expect(m).toContain('bankAccounts: "bank-1, bank-2, bank-3"');
  });

  it("FIXED (C-elicit): the payee account, amount and invoice of a single attacker payment are shown", async () => {
    const h = harness();
    const attackerInvoice = "11111111-2222-3333-4444-555555555555";
    await h.call({
      method: "PUT",
      path: BATCH_PATH,
      body: {
        BatchPayments: [{
          Account: { AccountID: "00000000-0000-0000-0000-00000000aaaa" },
          Reference: "Supplier run",
          Date: "2026-11-09",
          Payments: [{
            Invoice: { InvoiceID: attackerInvoice },
            BankAccountNumber: "06-0001-0666666-00",
            Details: "to attacker",
            Amount: 48750.0,
          }],
        }],
      },
    });
    const m = h.dialogs[0]!.message;
    expect(m).toContain(`Request: PUT ${BATCH_PATH}`);
    expect(m).toContain("total: 48750");
    expect(m).toContain('bankAccounts: "06-0001-0666666-00"');
    expect(m).toContain(`targets: "Invoice ${attackerInvoice}`);
  });

  it("FIXED (F2-3): the old type-correct placeholder answers (`count: 0`, `confirm: false`) no longer approve", async () => {
    for (const content of [{ count: 0 }, { confirm: false }, { confirm: "true" }, { confirm: true, count: 0 }]) {
      const h = harness({ answer: () => ({ action: "accept", content }) });
      await expect(h.call({ method: "PUT", path: BATCH_PATH, body: realBatch }))
        .rejects.toThrow(/requires user approval; outcome: declined/);
      expect(h.wire, JSON.stringify(content)).toHaveLength(0);
      expect(h.audits.find((a) => a.decision === "elicit")?.elicitationOutcome).toBe("declined");
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("REFUTED: a declined dialog sends nothing (control)", async () => {
    const h = harness({ answer: () => ({ action: "decline" }) });
    await expect(h.call({ method: "PUT", path: BATCH_PATH, body: realBatch }))
      .rejects.toThrow(/requires user approval; outcome: declined/);
    expect(h.wire).toHaveLength(0);
  });

  it("REFUTED: a client without elicitation (Claude.ai) is denied before any dialog (control)", async () => {
    const h = harness({ capabilities: {} });
    await expect(h.call({ method: "PUT", path: BATCH_PATH, body: realBatch }))
      .rejects.toThrow(/requires user approval; outcome: unsupported/);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.wire).toHaveLength(0);
  });
});

describe("emailInvoice dialog names the invoice from the path (F2-3a)", () => {
  it("FIXED (F2-3): two different invoices get different dialogs, each naming its path invoice id", async () => {
    const h = harness();
    const expected = "aaaaaaaa-0000-4000-8000-00000000000a";
    const attackerBuilt = "bbbbbbbb-0000-4000-8000-00000000000b";
    await h.call({ method: "POST", path: `/api.xro/2.0/Invoices/${expected}/Email`, body: {} });
    await h.call({ method: "POST", path: `/api.xro/2.0/Invoices/${attackerBuilt}/Email`, body: {} });

    expect(h.dialogs).toHaveLength(2);
    expect(h.dialogs[1]!.message).not.toBe(h.dialogs[0]!.message);
    expect(h.dialogs[1]!.message.split("\n")).toEqual([
      "Confirm Xero email invoice (xero.accounting.emailInvoice)",
      `Request: POST /api.xro/2.0/Invoices/${attackerBuilt}/Email`,
      `invoiceId: "${attackerBuilt}"`,
      "Approve only if this is exactly the request you intended.",
    ]);
    expect(h.dialogs[0]!.message).toContain(`invoiceId: "${expected}"`);
    expect(h.dialogs[1]!.requestedSchema).toEqual(CONFIRM_ONLY);
  });

  it("FIXED (F2-3): an invoice id planted in the body is not what the dialog names", async () => {
    const h = harness();
    await h.call({
      method: "POST",
      path: "/api.xro/2.0/Invoices/THE-INVOICE-ACTUALLY-EMAILED/Email",
      body: { InvoiceID: "harmless-invoice-id" },
    });
    expect(h.dialogs[0]!.message).toContain('invoiceId: "THE-INVOICE-ACTUALLY-EMAILED"');
    expect(h.dialogs[0]!.message).not.toContain('invoiceId: "harmless-invoice-id"');
  });
});

describe("payroll dialogs show the pay run and employee being changed", () => {
  it("FIXED (D-1): updatePayRun shows the path pay run id and the status being set", async () => {
    const h = harness();
    await h.call({
      method: "POST",
      path: "/payroll.xro/1.0/PayRuns/pr-1234",
      body: [{ PayRunStatus: "POSTED" }],
    });
    const m = h.dialogs[0]!.message;
    expect(m).toContain("Request: POST /payroll.xro/1.0/PayRuns/pr-1234");
    expect(m).toContain('payRunId: "pr-1234"');
    expect(m).toContain('status: "POSTED"');
  });

  it("FIXED (D-1): updateEmployee shows the path employee id and the name being written", async () => {
    const h = harness();
    await h.call({
      method: "POST",
      path: "/payroll.xro/1.0/Employees/emp-42",
      body: [{ FirstName: "Ada", LastName: "Lovelace" }],
    });
    const m = h.dialogs[0]!.message;
    expect(m).toContain('employeeId: "emp-42"');
    expect(m).toContain('FirstName: "Ada"');
    expect(m).toContain('LastName: "Lovelace"');
  });
});

describe("bodies that cannot be shown are denied before any dialog (D-1 #7)", () => {
  const xml =
    "<BatchPayments><BatchPayment><Account><AccountID>ATTACKER-CHOSEN-ACCOUNT</AccountID></Account>" +
    "<Payments><Payment><Amount>99999.00</Amount></Payment></Payments></BatchPayment></BatchPayments>";
  const json = JSON.stringify({ BatchPayments: [{ Payments: [{ Amount: 99999 }] }] });

  const cases: Array<[string, UpstreamCtx]> = [
    ["raw XML", { method: "PUT", path: BATCH_PATH, rawBody: true, contentType: "application/xml", body: xml }],
    ["JSON text labelled text/plain", { method: "PUT", path: BATCH_PATH, rawBody: true, contentType: "text/plain", body: json }],
    ["untyped base64 bytes", { method: "PUT", path: BATCH_PATH, bodyBase64: Buffer.from(json).toString("base64") }],
  ];

  for (const [label, ctx] of cases) {
    it(`FIXED (D-1): ${label} is denied as opaque, elicitInput never called, nothing on the wire`, async () => {
      const h = harness();
      await expect(h.call(ctx)).rejects.toThrow(
        /requires approval but its body cannot be shown; send it as JSON/,
      );
      expect(h.elicitInput).not.toHaveBeenCalled();
      expect(h.wire).toHaveLength(0);
      expect(h.audits.at(-1)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "opaque-body-on-approval-op",
        operationId: "xero.accounting.createBatchPayment",
      });
    });
  }
});
