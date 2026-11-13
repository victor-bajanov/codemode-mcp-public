// packages/providers/xero/src/__tests__/surface-review-drafts.test.ts
//
// Inspector for createInvoices / updateOrCreateInvoices.
// Both ACCREC (invoices to clients) and ACCPAY (bills from suppliers) come through the
// same endpoint; the body's `Type` field distinguishes them and is not what we gate on.
//
// Policy:
//   - Status ∈ {DRAFT, SUBMITTED} → allow.
//   - Status omitted or null → deny invoice-status-required, with or without an
//     InvoiceID (F2-4: "omitted means keep the current status" let an update of a
//     posted invoice through on the belief that Xero would refuse it). Whether the
//     STORED invoice is a draft is checked by the stored-status hook
//     (stored-status.test.ts), not here.
//   - any other Status (AUTHORISED, PAID, VOIDED, DELETED) → deny.
//   - SentToContact set (anything but absent/null/false) → deny regardless of Status.
//   - By-id update: a body InvoiceID must equal the path id (F2-4, invoice-id-mismatch).
//   - The inline Contact may not carry bank, batch-payment, email, status, tax-number
//     or contact-person details (invoice-inline-contact-details).
//   - Gated keys (wrapper, Status, InvoiceID, SentToContact) are read case-insensitively,
//     as Xero does; two spellings of one gated key → deny invoice-ambiguous-key (F-10).

import { describe, it, expect } from "vitest";
import { inspectInvoiceDraft, readItems } from "../inspectors/drafts";

describe("inspectInvoiceDraft", () => {
  it("allows a DRAFT ACCREC invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT", Contact: { Name: "Acme" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows a SUBMITTED ACCPAY bill", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCPAY", Status: "SUBMITTED", Contact: { Name: "Supplier" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows a DRAFT ACCPAY bill", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCPAY", Status: "DRAFT", Contact: { Name: "Supplier" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies an AUTHORISED invoice (irreversible — issued to ledger)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies a PAID invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "PAID" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies SentToContact:true (mail-out trigger; off-channel exfil)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT", SentToContact: true }] },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
  });

  it("denies when Status is missing", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  it("denies when Invoices array is empty", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [] },
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-no-payload" });
  });

  it("denies when Invoices key is missing", () => {
    expect(inspectInvoiceDraft({ body: {} })).toMatchObject({
      decision: "deny", category: "malformed", reason: "invoice-no-payload",
    });
  });

  it("denies when ANY invoice in a batch is non-draft (most-restrictive across the batch)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT" }, { Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
  });

  it("treats Status case-insensitively (Xero may return mixed case)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "draft" }] },
    })).toEqual({ decision: "allow" });
  });

  // === F2-4: Status-omitted updates are no longer "preserve existing state" ===

  it("FIXED (F2-4): denies a bulk update with InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [{
          InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
          LineAmountTypes: "Exclusive",
          LineItems: [{ Description: "edit", Quantity: 1, UnitAmount: 28.23, AccountCode: "490" }],
        }],
      },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  it("FIXED (F2-4): denies an ACCPAY bulk update with InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCPAY", InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  it("FIXED (F2-4): the approved-bill repoint with no Status is denied, telling the caller Status is required", () => {
    const res = inspectInvoiceDraft({
      body: {
        Invoices: [{
          InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
          Contact: { ContactID: "0f3d1c2e-4b5a-4c6d-8e7f-9a0b1c2d3e4f" },
          LineItems: [{ Description: "Consulting", Quantity: 1, UnitAmount: 48500, AccountCode: "400" }],
          DueDate: "2026-11-20",
        }],
      },
    });
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
    expect(res.message).toContain('"DRAFT" or "SUBMITTED"');
    expect(res.message).toContain("no longer means");
  });

  it("FIXED (F2-4): any non-empty id string no longer grants anything (\"x\", no Status)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: "x", Type: "ACCPAY" }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-status-required" });
  });

  it("still denies a bulk update when InvoiceID is present but Status is AUTHORISED", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("still denies SentToContact:true on an update (the omitted Status is denied first)", () => {
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [{
          InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
          SentToContact: true,
        }],
      },
    })).toMatchObject({ decision: "deny", reason: "invoice-status-required" });
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [{
          InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
          Status: "DRAFT",
          SentToContact: true,
        }],
      },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
  });

  it("denies a bulk update with empty-string InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: "" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  it("denies a batch where one item has InvoiceID+no-Status and another has no InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [
          { InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de" },
          { Type: "ACCREC" },
        ],
      },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  // === Singular by-ID update (POST /Invoices/{ID}) — flat body, no Invoices wrapper ===

  it("allows a DRAFT singular flat-body invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "DRAFT", Contact: { Name: "Acme" } },
    })).toEqual({ decision: "allow" });
  });

  it("allows a SUBMITTED singular flat-body invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "SUBMITTED" },
    })).toEqual({ decision: "allow" });
  });

  it("denies an AUTHORISED singular flat-body invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "AUTHORISED" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies a singular flat-body invoice with SentToContact:true", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "DRAFT", SentToContact: true },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
  });

  it("denies a singular flat-body invoice with no Status and no InvoiceID", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  it("FIXED (F2-4): denies a singular flat-body update with InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: {
        Type: "ACCREC",
        InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
        LineItems: [{ Description: "edit", Quantity: 1, UnitAmount: 10, AccountCode: "490" }],
      },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-status-required" });
  });

  it("still denies a singular flat-body update when InvoiceID is present but Status is AUTHORISED", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Status: "AUTHORISED" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  // === F-10: Xero reads property names case-insensitively and coerces "true" ===

  const ID = "8576f4cf-e24d-4e3a-83ff-c6f30418a7de";

  it.each(["status", "STATUS", "sTaTuS"])("reads a %s key as Status (AUTHORISED on an update is denied)", (key) => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, [key]: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("reads a lower-case status key on a flat by-ID body", () => {
    expect(inspectInvoiceDraft({
      body: { InvoiceID: ID, status: "AUTHORISED" },
    })).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
  });

  it("allows a create whose Status is spelt status: DRAFT", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", status: "DRAFT" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies two spellings of Status as ambiguous, naming the key", () => {
    const res = inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT", status: "AUTHORISED" }] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-ambiguous-key" });
    expect(res.message).toContain('"Status"');
  });

  it("denies a non-ASCII lookalike of Status as ambiguous (U+017F long s)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, "\u017Ftatus": "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT", "\uFB06atus": "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
  });

  it("FIXED (F2-4): treats a null Status like an absent one (denied with and without an id)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: null }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-status-required" });
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: null }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-status-required" });
  });

  it("reads the id field case-insensitively (the path tie sees it)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ invoiceid: ID, Status: "DRAFT" }] },
      pathParams: { InvoiceID: ID },
    })).toEqual({ decision: "allow" });
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ invoiceid: "other", Status: "DRAFT" }] },
      pathParams: { InvoiceID: ID },
    })).toMatchObject({ decision: "deny", reason: "invoice-id-mismatch" });
  });

  it("denies two spellings of InvoiceID as ambiguous", () => {
    const res = inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, invoiceID: "other" }] },
    });
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
    expect(res.message).toContain('"InvoiceID"');
  });

  it.each([["the string \"true\"", "true"], ["1", 1], ["the string \"false\"", "false"], ["an object", {}]])(
    "denies SentToContact given as %s (lenient boolean, fail closed)",
    (_label, value) => {
      expect(inspectInvoiceDraft({
        body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT", SentToContact: value }] },
      })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
    },
  );

  it.each([["false", false], ["null", null]])("allows SentToContact: %s", (_label, value) => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT", SentToContact: value }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies a lower-case sentToContact: true", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT", sentToContact: true }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-sent-to-contact" });
  });

  it("denies two spellings of SentToContact as ambiguous", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT", SentToContact: false, senttocontact: true }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
  });

  it("treats a lower-case invoices wrapper as bulk (not as a flat by-ID update)", () => {
    expect(inspectInvoiceDraft({
      body: { invoices: [{ Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
    expect(inspectInvoiceDraft({
      body: { INVOICES: [{ Status: "DRAFT" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies an empty or non-array wrapper under any casing as no payload", () => {
    expect(inspectInvoiceDraft({ body: { invoices: [] } })).toMatchObject({
      decision: "deny", category: "malformed", reason: "invoice-no-payload",
    });
    expect(inspectInvoiceDraft({
      body: { invoices: { Status: "AUTHORISED" } },
    })).toMatchObject({ decision: "deny", reason: "invoice-no-payload" });
  });

  it("denies two spellings of the Invoices wrapper as ambiguous", () => {
    const res = inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT" }], invoices: [{ Status: "AUTHORISED" }] },
    });
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
    expect(res.message).toContain('"Invoices"');
  });

  // === F2-4: by-id endpoint, the body id must equal the path id ===

  it("FIXED (F2-4): denies a by-id update whose body InvoiceID names another invoice", () => {
    const res = inspectInvoiceDraft({
      body: { InvoiceID: "0f3d1c2e-4b5a-4c6d-8e7f-9a0b1c2d3e4f", Status: "DRAFT" },
      pathParams: { InvoiceID: ID },
    });
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-id-mismatch" });
    expect(res.message).toContain("InvoiceID");
  });

  it("ties a bulk-shaped body on the by-id endpoint too", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: "other", Status: "DRAFT" }] },
      pathParams: { InvoiceID: ID },
    })).toMatchObject({ decision: "deny", reason: "invoice-id-mismatch" });
  });

  it("FIXED (F2-4 review): denies more than one item on the by-id endpoint (the hook reads only the path id)", () => {
    for (const items of [
      [{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceNumber: "INV-POSTED", Status: "DRAFT" }],
      [{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceID: ID, Status: "DRAFT" }],
    ]) {
      const res = inspectInvoiceDraft({ body: { Invoices: items }, pathParams: { InvoiceID: ID } });
      expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-by-id-multiple-items" });
      expect(res.message).toContain("one invoice");
    }
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT" }] },
      pathParams: { InvoiceID: ID },
    })).toEqual({ decision: "allow" });
  });

  it("FIXED (F2-4 review): denies a key beside the Invoices wrapper (fail closed: Xero's reading of it is unverified)", () => {
    for (const body of [
      { Invoices: [{ Status: "DRAFT" }], InvoiceID: ID, Status: "AUTHORISED" },
      { invoices: [{ Status: "DRAFT" }], pagination: {} },
    ]) {
      const res = inspectInvoiceDraft({ body });
      expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-unexpected-key" });
      expect(res.message).toContain('"Invoices"');
    }
  });

  it("FIXED (F2-4 review): denies an InvoiceNumber with surrounding whitespace (the by-number read could miss it)", () => {
    for (const InvoiceNumber of ["INV-1 ", " INV-1", "INV-1\t", "\u00a0INV-1"]) {
      const res = inspectInvoiceDraft({ body: { Invoices: [{ InvoiceNumber, Status: "DRAFT" }] } });
      expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-bad-number" });
      expect(res.message).toContain("InvoiceNumber");
    }
    expect(inspectInvoiceDraft({ body: { Invoices: [{ invoicenumber: " x", Status: "DRAFT" }] } })).toMatchObject({
      reason: "invoice-bad-number",
    });
    expect(inspectInvoiceDraft({ body: { Invoices: [{ InvoiceNumber: 42, Status: "DRAFT" }] } })).toMatchObject({
      reason: "invoice-bad-number",
    });
    expect(inspectInvoiceDraft({ body: { Invoices: [{ InvoiceNumber: "A", invoiceNumber: "B", Status: "DRAFT" }] } })).toMatchObject({
      reason: "invoice-ambiguous-key",
    });
    expect(inspectInvoiceDraft({ body: { Invoices: [{ InvoiceNumber: "SUP 7/1", Status: "DRAFT" }] } })).toEqual({
      decision: "allow",
    });
  });

  it("FIXED (F2-4 review): denies a Status that is not a string (e.g. [\"DRAFT\"])", () => {
    for (const Status of [["DRAFT"], { v: "DRAFT" }, 1, true]) {
      const res = inspectInvoiceDraft({ body: { Invoices: [{ Status }] } });
      expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-bad-status" });
    }
  });

  it("accepts the path id in another letter case or with surrounding spaces, or no body id", () => {
    for (const InvoiceID of [ID.toUpperCase(), ` ${ID} `]) {
      expect(inspectInvoiceDraft({
        body: { InvoiceID, Status: "DRAFT" },
        pathParams: { InvoiceID: ID },
      })).toEqual({ decision: "allow" });
    }
    expect(inspectInvoiceDraft({
      body: { Status: "DRAFT", Reference: "x" },
      pathParams: { InvoiceID: ID },
    })).toEqual({ decision: "allow" });
  });

  it("does not tie ids on the bulk endpoints (no path id)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceID: "other", Status: "DRAFT" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies a present InvoiceID that is not a string (the stored read could not target it)", () => {
    for (const InvoiceID of [123, {}, [ID], true]) {
      expect(inspectInvoiceDraft({
        body: { Invoices: [{ InvoiceID, Status: "DRAFT" }] },
      })).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-bad-id" });
    }
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: null, Status: "DRAFT" }] },
    })).toEqual({ decision: "allow" });
  });

  // === F2-1 (documents): the inline Contact may not carry payee/delivery details ===

  it("FIXED (F2-1): denies an inline Contact carrying BankAccountDetails, naming the field", () => {
    const res = inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT", Contact: { ContactID: ID, BankAccountDetails: "062-000 13371337" } }] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "financial_legal", reason: "invoice-inline-contact-details" });
    expect(res.message).toContain("BankAccountDetails");
    expect(res.message).toContain("/Contacts");
  });

  it("denies a lower-case contact.emailaddress", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT", contact: { emailaddress: "drop@attacker.example" } }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-inline-contact-details" });
  });

  it("allows an inline Contact that only references a contact", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT", Contact: { ContactID: ID } }] },
    })).toEqual({ decision: "allow" });
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT", Contact: { Name: "Acme" } }] },
    })).toEqual({ decision: "allow" });
  });
});

describe("readItems", () => {
  it("reads a bulk wrapper under any casing, or one flat object", () => {
    expect(readItems({ invoices: [{ a: 1 }, { b: 2 }] }, "Invoices")).toEqual({ ok: true, items: [{ a: 1 }, { b: 2 }] });
    expect(readItems({ Status: "DRAFT" }, "Invoices")).toEqual({ ok: true, items: [{ Status: "DRAFT" }] });
  });

  it.each([
    ["no body", undefined],
    ["a string", "x"],
    ["an array", [{ a: 1 }]],
    ["{}", {}],
    ["an empty wrapper", { Invoices: [] }],
    ["a non-array wrapper", { Invoices: { Status: "DRAFT" } }],
    ["a non-object item", { Invoices: [{ a: 1 }, "x"] }],
    ["an array item", { Invoices: [[]] }],
  ])("is no-payload for %s", (_label, body) => {
    expect(readItems(body, "Invoices")).toEqual({ ok: false, reason: "no-payload" });
  });

  it("is ambiguous-wrapper for two spellings of the wrapper", () => {
    expect(readItems({ Invoices: [{}], invoices: [{}] }, "Invoices")).toEqual({ ok: false, reason: "ambiguous-wrapper" });
  });

  it("is unexpected-key for any key beside the wrapper (only response fields sit there in the spec)", () => {
    for (const body of [
      { Invoices: [{ Status: "DRAFT" }], Status: "AUTHORISED" },
      { Invoices: [{ Status: "DRAFT" }], Warnings: [] },
      { invoices: [], x: 1 },
    ]) {
      expect(readItems(body, "Invoices")).toEqual({ ok: false, reason: "unexpected-key" });
    }
  });
});

describe("a flat body keyed by the singular root is refused (wave 3 review)", () => {
  it("FIXED: `{ Invoice: { … } }` is denied invoice-unexpected-key, even with a Status", () => {
    for (const key of ["Invoice", "invoice"]) {
      expect(inspectInvoiceDraft({ body: { [key]: { InvoiceID: "x", Status: "DRAFT" } } }), key)
        .toMatchObject({ decision: "deny", reason: "invoice-unexpected-key" });
    }
    expect(readItems({ Invoice: {} }, "Invoices")).toEqual({ ok: false, reason: "unexpected-key" });
  });

  it("a flat invoice with an inline Contact (a legitimate field) is still allowed", () => {
    expect(inspectInvoiceDraft({ body: { Status: "DRAFT", Contact: { ContactID: "c-1" } } })).toEqual({ decision: "allow" });
  });
});
