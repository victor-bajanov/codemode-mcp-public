// packages/providers/xero/src/__tests__/surface-review-contacts.test.ts
//
// F2-1 (High): contact payee details rewritten with no approval.
//
// Attacker: a prompt-injected model with the Xero contact write routes.
// Precondition: `createContacts` (PUT /Contacts) and `updateOrCreateContacts`
// (POST /Contacts) were bare allows.
// Payload: one POST carrying an existing `ContactID` plus new
// `BankAccountDetails` / `BatchPayments` (repoints a supplier's payments), a new
// `EmailAddress` or `ContactPersons` entry (repoints a customer's invoices), or
// `ContactStatus: "ARCHIVED"` in bulk.
// Control: `inspectContactWrite` (sync) lets creates and plain edits through,
// and turns an edit carrying a sensitive field into an approval (`elicit`,
// financial_legal) limited to one contact per request; `inspectStoredContact`
// (the `inspectUpstream` hook) reads the stored contact first so the dialog
// shows old → new, and denies when it cannot read it.
// Why the pre-fix code failed it: there was no inspector at all, so the write
// went out with a plain `allow` audit line.
//
// These are unit probes: the inspector and the hook are called directly with a
// fake `lookup`. The end-to-end dialog tests are in contact-edits.test.ts.

import { describe, it, expect } from "vitest";
import type { InspectRequest, UpstreamLookup, UpstreamLookupResult } from "@local/shared";
import {
  SENSITIVE_CONTACT_FIELDS,
  inlineContactProblem,
  sensitiveContactKeys,
} from "../inspectors/contact-fields";
import { inspectContactWrite, inspectStoredContact } from "../inspectors/contacts";

describe("contact-fields: SENSITIVE_CONTACT_FIELDS", () => {
  it("names the brief's five payee/delivery fields plus ContactPersons", () => {
    expect([...SENSITIVE_CONTACT_FIELDS]).toEqual([
      "BankAccountDetails",
      "BatchPayments",
      "EmailAddress",
      "ContactStatus",
      "TaxNumber",
      "ContactPersons",
    ]);
  });
});

describe("contact-fields: sensitiveContactKeys", () => {
  it("returns the carried sensitive fields by canonical name, in canonical order", () => {
    expect(
      sensitiveContactKeys({ Name: "Acme", taxnumber: "1", BankAccountDetails: "062-000 1" }),
    ).toEqual({ present: ["BankAccountDetails", "TaxNumber"], ambiguous: [] });
  });

  it("counts a key whose value is null as carried (it clears the field)", () => {
    expect(sensitiveContactKeys({ EmailAddress: null })).toEqual({
      present: ["EmailAddress"],
      ambiguous: [],
    });
  });

  it("reports two spellings, or a non-ASCII lookalike, as ambiguous", () => {
    expect(
      sensitiveContactKeys({ EmailAddress: "a@x.example", emailaddress: "b@x.example" }),
    ).toEqual({ present: [], ambiguous: ["EmailAddress"] });
    // U+017F LATIN SMALL LETTER LONG S folds onto "s".
    expect(sensitiveContactKeys({ "ContactStatuſ": "ARCHIVED" })).toEqual({
      present: [],
      ambiguous: ["ContactStatus"],
    });
  });

  it("returns nothing for a plain edit", () => {
    expect(sensitiveContactKeys({ ContactID: "x", Name: "Acme", Addresses: [] })).toEqual({
      present: [],
      ambiguous: [],
    });
  });
});

describe("contact-fields: inlineContactProblem", () => {
  it("is null when the item has no Contact, or the Contact is not an object", () => {
    expect(inlineContactProblem({ Status: "DRAFT" })).toBeNull();
    expect(inlineContactProblem({ Contact: "Acme" })).toBeNull();
    expect(inlineContactProblem({ Contact: null })).toBeNull();
  });

  it("is null when the inline Contact carries no sensitive field", () => {
    expect(inlineContactProblem({ Contact: { ContactID: "c-1" } })).toBeNull();
    expect(inlineContactProblem({ Contact: { Name: "Acme", ContactNumber: "7" } })).toBeNull();
  });

  it("names the sensitive fields an inline Contact carries", () => {
    expect(
      inlineContactProblem({ Contact: { ContactID: "c-1", BankAccountDetails: "062-000 13371337" } }),
    ).toEqual(["BankAccountDetails"]);
    expect(
      inlineContactProblem({ Contact: { Name: "Mallory", EmailAddress: "drop@attacker.example" } }),
    ).toEqual(["EmailAddress"]);
  });

  it("reads the Contact key and its fields case-insensitively", () => {
    expect(inlineContactProblem({ contact: { emailaddress: "drop@attacker.example" } })).toEqual([
      "EmailAddress",
    ]);
  });

  it("includes ambiguous sensitive fields (the caller denies either way)", () => {
    expect(
      inlineContactProblem({ Contact: { TaxNumber: "1", taxnumber: "2" } }),
    ).toEqual(["TaxNumber"]);
  });

  it("judges every spelling of an ambiguous Contact key (fail closed)", () => {
    expect(
      inlineContactProblem({
        Contact: { ContactID: "c-1" },
        contact: { ContactID: "c-1", BatchPayments: { BankAccountNumber: "1" } },
      }),
    ).toEqual(["BatchPayments"]);
    expect(
      inlineContactProblem({ Contact: { ContactID: "c-1" }, CONTACT: { Name: "x" } }),
    ).toBeNull();
  });
});

// Invented ids (not real Xero accounts).
const ID = "3f1c2a54-7b8e-4d2a-9c61-0e5d4b7a9f10";
const OTHER_ID = "9b0e7d21-5c3a-4f86-8e12-6a4d2c9b1e07";

const STORED_ACME = {
  ContactID: ID,
  Name: "Acme Supplies",
  ContactStatus: "ACTIVE",
  EmailAddress: "accounts@acme.example",
  BankAccountDetails: "062-000 1111",
  BatchPayments: { BankAccountNumber: "062-000 1111", BankAccountName: "Acme Supplies" },
};

/** A fake host-side lookup: records each path and answers `result` (or per path). */
function fakeLookup(
  result: UpstreamLookupResult | ((path: string) => UpstreamLookupResult),
): UpstreamLookup & { paths: string[] } {
  const paths: string[] = [];
  return {
    paths,
    async get(path: string) {
      paths.push(path);
      return typeof result === "function" ? result(path) : result;
    },
  };
}

const stored = (contact: Record<string, unknown>): UpstreamLookupResult => ({
  status: 200,
  body: { Contacts: [contact] },
});

/** Run the sync inspector, then (when it did not deny) the hook, the way the
 *  scaffold does: the hook's summary merges over the sync one. */
async function both(req: InspectRequest, lookup: UpstreamLookup) {
  const sync = inspectContactWrite(req);
  if (sync.decision === "deny") return { sync, hook: undefined };
  const hook = await inspectStoredContact(req, lookup);
  return { sync, hook };
}

describe("inspectContactWrite: creates stay open (user instruction)", () => {
  it("REFUTED: a create with bank, email and batch-payment details is a plain allow", () => {
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            {
              Name: "New Supplier",
              EmailAddress: "ap@supplier.example",
              BankAccountDetails: "062-000 12345678",
              BatchPayments: { BankAccountNumber: "062-000 12345678" },
              ContactPersons: [{ EmailAddress: "p@supplier.example", IncludeInEmails: true }],
            },
          ],
        },
      }),
    ).toEqual({ decision: "allow" });
  });

  it("REFUTED: a bulk of three creates is a plain allow", () => {
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            { Name: "A", EmailAddress: "a@a.example" },
            { Name: "B", BankAccountDetails: "1" },
            { Name: "C", TaxNumber: "12 345 678 901" },
          ],
        },
      }),
    ).toEqual({ decision: "allow" });
  });

  it("REFUTED: a flat create body is a plain allow", () => {
    expect(inspectContactWrite({ body: { Name: "Flat", EmailAddress: "f@f.example" } })).toEqual({
      decision: "allow",
    });
  });
});

describe("inspectContactWrite: plain edits stay open", () => {
  it("REFUTED: an edit that renames and readdresses a contact is a plain allow", () => {
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            {
              ContactID: ID,
              Name: "Acme Supplies Pty Ltd",
              Addresses: [{ AddressType: "POBOX", AddressLine1: "PO Box 1" }],
              Phones: [{ PhoneType: "DEFAULT", PhoneNumber: "5550100" }],
            },
          ],
        },
      }),
    ).toEqual({ decision: "allow" });
  });

  it("REFUTED: a bulk of plain edits (no Name, no XeroNetworkKey) is a plain allow", () => {
    expect(
      inspectContactWrite({
        body: { Contacts: [{ ContactID: ID, Website: "x" }, { ContactNumber: "42", Website: "w" }] },
      }),
    ).toEqual({ decision: "allow" });
  });
});

describe("inspectContactWrite: sensitive edits need approval (F2-1)", () => {
  it("FIXED (F2-1): a ContactID edit of bank and batch-payment details elicits with → new facts", () => {
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            {
              ContactID: ID,
              BankAccountDetails: "062-000 13371337",
              BatchPayments: { BankAccountNumber: "062-000 13371337", BankAccountName: "Acme Supplies" },
            },
          ],
        },
      }),
    ).toEqual({
      decision: "elicit",
      category: "financial_legal",
      reason: "contact-sensitive-edit",
      summary: {
        contactId: ID,
        name: "",
        bankAccountDetails: "→ 062-000 13371337",
        batchPayments: "→ BankAccountNumber=062-000 13371337, BankAccountName=Acme Supplies",
      },
    });
  });

  it("FIXED (F2-1): the summary keeps contactId, name, then the fields in canonical order", () => {
    const r = inspectContactWrite({
      body: {
        ContactPersons: [{ EmailAddress: "p@attacker.example" }],
        TaxNumber: "99",
        ContactStatus: "ARCHIVED",
        EmailAddress: "accounts@attacker.example",
        Name: "Acme",
        ContactID: ID,
      },
    });
    expect(r.decision).toBe("elicit");
    expect(Object.keys(r.summary ?? {})).toEqual([
      "contactId",
      "name",
      "emailAddress",
      "contactStatus",
      "taxNumber",
      "contactPersons",
    ]);
    expect(r.summary?.name).toBe("→ Acme");
  });

  it("FIXED (F2-1): an email swap alone elicits", () => {
    const r = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, EmailAddress: "accounts@attacker.example" }] },
    });
    expect(r).toMatchObject({ decision: "elicit", reason: "contact-sensitive-edit" });
    expect(r.summary?.emailAddress).toBe("→ accounts@attacker.example");
  });

  it("FIXED (F2-1): a ContactNumber-keyed sensitive edit elicits, keyed `number <n>`", () => {
    const r = inspectContactWrite({ body: { Contacts: [{ ContactNumber: "SUP-7", TaxNumber: "1" }] } });
    expect(r).toMatchObject({ decision: "elicit", reason: "contact-sensitive-edit" });
    expect(r.summary?.contactId).toBe("number SUP-7");
  });

  it("FIXED (F2-1): a PUT /Contacts body carrying an id is judged the same way", () => {
    // The inspector judges the body, not the verb: createContacts shares it.
    const r = inspectContactWrite({ body: { Contacts: [{ ContactID: ID, ContactStatus: "ARCHIVED" }] } });
    expect(r).toMatchObject({ decision: "elicit", reason: "contact-sensitive-edit" });
    expect(r.summary?.contactStatus).toBe("→ ARCHIVED");
  });

  it("FIXED (F2-1): a cleared field renders (cleared)", () => {
    const r = inspectContactWrite({ body: { Contacts: [{ ContactID: ID, EmailAddress: null }] } });
    expect(r.summary?.emailAddress).toBe("→ (cleared)");
  });

  it("FIXED (F2-1): ContactPersons render every email, marking the ones included in emails", () => {
    const r = inspectContactWrite({
      body: {
        Contacts: [
          {
            ContactID: ID,
            ContactPersons: [
              { EmailAddress: "a@attacker.example", IncludeInEmails: true },
              { FirstName: "No", LastName: "Email" },
              { EmailAddress: "c@attacker.example", IncludeInEmails: false },
            ],
          },
        ],
      },
    });
    expect(r.summary?.contactPersons).toBe(
      "→ a@attacker.example (in emails), (no email) (in emails?), c@attacker.example",
    );
  });

  it("FIXED (F2-1 review): a sensitive edit with more than three ContactPersons is denied, not cut", () => {
    // A fourth person (the attacker's) would hide behind "(+1)" in the dialog.
    const persons = ["a", "b", "c", "d"].map((x) => ({ EmailAddress: `${x}@acme.example`, IncludeInEmails: true }));
    const r = inspectContactWrite({ body: { Contacts: [{ ContactID: ID, ContactPersons: persons }] } });
    expect(r).toMatchObject({ decision: "deny", category: "financial_legal", reason: "contact-too-many-persons" });
    // A create with four persons stays open (no dialog to fit).
    expect(inspectContactWrite({ body: { Contacts: [{ Name: "New", ContactPersons: persons }] } })).toEqual({
      decision: "allow",
    });
  });

  it("denies a ContactPersons entry whose IncludeInEmails is not a boolean", () => {
    const r = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, ContactPersons: [{ EmailAddress: "a@a.example", IncludeInEmails: "yes" }] }] },
    });
    expect(r).toMatchObject({ decision: "deny", reason: "contact-field-unreadable" });
    const amb = inspectContactWrite({
      body: {
        Contacts: [
          { ContactID: ID, ContactPersons: [{ EmailAddress: "a@a.example", IncludeInEmails: false, includeinemails: true }] },
        ],
      },
    });
    expect(amb).toMatchObject({ decision: "deny", reason: "contact-ambiguous-key" });
  });

  it("FIXED (F2-1): an empty BatchPayments object renders (empty)", () => {
    const r = inspectContactWrite({ body: { Contacts: [{ ContactID: ID, BatchPayments: {} }] } });
    expect(r.summary?.batchPayments).toBe("→ (empty)");
  });
});

describe("inspectContactWrite: one contact per sensitive request", () => {
  const ONE_PER = {
    decision: "deny",
    category: "financial_legal",
    reason: "contact-one-per-request",
  };

  it("FIXED (F2-1): an email swap beside a bulk archive (three items) is denied", () => {
    const r = inspectContactWrite({
      body: {
        Contacts: [
          { ContactID: ID, EmailAddress: "accounts@attacker.example" },
          { ContactID: OTHER_ID, Name: "Plain edit" },
          { Name: "A create" },
        ],
      },
    });
    expect(r).toMatchObject(ONE_PER);
    expect(r.message).toMatch(/exactly one contact/);
  });

  it("FIXED (F2-1): two sensitive edits are denied", () => {
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            { ContactID: ID, ContactStatus: "ARCHIVED" },
            { ContactID: OTHER_ID, ContactStatus: "ARCHIVED" },
          ],
        },
      }),
    ).toMatchObject(ONE_PER);
  });

  it("FIXED (F2-1): a sensitive edit with a decoy key beside the Contacts wrapper is denied", () => {
    // Every fact of the change must fit the dialog's eight; a decoy line would
    // push the last one out.
    const r = inspectContactWrite({
      body: {
        Contacts: [{ ContactID: ID, EmailAddress: "accounts@attacker.example" }],
        Payments: [{ Amount: 1 }],
      },
    });
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-unexpected-key" });
  });

  it("FIXED (F2-1 review): any key beside the Contacts wrapper is denied, even beside creates", () => {
    expect(
      inspectContactWrite({ body: { Contacts: [{ Name: "A" }], Payments: [] } }),
    ).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-unexpected-key" });
  });

  it("FIXED (F2-1 review): a flat contact edit beside a Contacts wrapper is denied", () => {
    // Which object Xero applies is unclear: the wrapper's create, or the flat
    // edit of a stored contact's bank details. Both readings must not pass.
    for (const body of [
      { Contacts: [{ Name: "A" }], ContactID: ID, BankAccountDetails: "062-000 13371337" },
      { Contacts: [{ Name: "A" }], contactid: ID, Name: "Renamed" },
      { Contacts: [{ Name: "A" }], pagination: { page: 1 } },
    ]) {
      expect(inspectContactWrite({ body })).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "contact-unexpected-key",
      });
    }
  });
});

describe("inspectContactWrite: lenient parsing, fail closed", () => {
  it("reads lower-case contactid / bankaccountdetails keys", () => {
    const r = inspectContactWrite({
      body: { contacts: [{ contactid: ID, bankaccountdetails: "062-000 13371337" }] },
    });
    expect(r).toMatchObject({ decision: "elicit", reason: "contact-sensitive-edit" });
    expect(r.summary).toMatchObject({ contactId: ID, bankAccountDetails: "→ 062-000 13371337" });
  });

  it("denies two spellings of EmailAddress as ambiguous", () => {
    const r = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, EmailAddress: "a@a.example", emailaddress: "b@b.example" }] },
    });
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-ambiguous-key" });
    expect(r.message).toContain("EmailAddress");
  });

  it("denies two spellings of ContactID, ContactNumber or the wrapper as ambiguous", () => {
    for (const body of [
      { Contacts: [{ ContactID: ID, contactID: OTHER_ID, Name: "x" }] },
      { Contacts: [{ ContactNumber: "1", contactnumber: "2" }] },
      { Contacts: [{ Name: "x" }], contacts: [{ Name: "y" }] },
    ]) {
      expect(inspectContactWrite({ body })).toMatchObject({
        decision: "deny",
        reason: "contact-ambiguous-key",
      });
    }
  });

  it("denies an ambiguous key even on a create (keys are read the way Xero reads them)", () => {
    expect(
      inspectContactWrite({ body: { Contacts: [{ Name: "x", TaxNumber: "1", taxnumber: "2" }] } }),
    ).toMatchObject({ decision: "deny", reason: "contact-ambiguous-key" });
  });

  it("denies an ambiguous EmailAddress inside a ContactPersons entry or BatchPayments key", () => {
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            { ContactID: ID, ContactPersons: [{ EmailAddress: "a@a.example", emailaddress: "b@attacker.example" }] },
          ],
        },
      }),
    ).toMatchObject({ decision: "deny", reason: "contact-ambiguous-key" });
    expect(
      inspectContactWrite({
        body: {
          Contacts: [
            { ContactID: ID, BatchPayments: { BankAccountNumber: "1", bankaccountnumber: "2" } },
          ],
        },
      }),
    ).toMatchObject({ decision: "deny", reason: "contact-ambiguous-key" });
  });

  it("denies a ContactID or ContactNumber that is not a non-empty string", () => {
    for (const item of [
      { ContactID: 123, Name: "x" },
      { ContactID: "", Name: "x" },
      { ContactID: null, Name: "x" },
      { ContactNumber: 7, TaxNumber: "1" },
      { ContactNumber: "  " },
    ]) {
      expect(inspectContactWrite({ body: { Contacts: [item] } })).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "contact-bad-id",
      });
    }
  });

  it("denies a sensitive field whose value has the wrong type", () => {
    for (const item of [
      { ContactID: ID, BankAccountDetails: { Number: "1" } },
      { ContactID: ID, EmailAddress: 5 },
      { ContactID: ID, ContactStatus: ["ARCHIVED"] },
      { ContactID: ID, TaxNumber: true },
      { ContactID: ID, BatchPayments: "062-000 1" },
      { ContactID: ID, BatchPayments: [] },
      { ContactID: ID, ContactPersons: { EmailAddress: "a@a.example" } },
    ]) {
      expect(inspectContactWrite({ body: { Contacts: [item] } })).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "contact-field-unreadable",
      });
    }
  });

  it("denies an empty or non-object payload", () => {
    for (const body of [undefined, null, "x", 5, [], {}, { Contacts: {} }, { Contacts: [] }, { Contacts: [5] }]) {
      expect(inspectContactWrite({ body })).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "contact-no-payload",
      });
    }
  });
});

describe("inspectStoredContact: the stored contact is read first (F2-1)", () => {
  it("FIXED (F2-1): reads /Contacts/{ContactID} and shows old → new with the stored name", async () => {
    const lookup = fakeLookup(stored(STORED_ACME));
    const req: InspectRequest = {
      body: {
        Contacts: [
          {
            ContactID: ID,
            BankAccountDetails: "062-000 13371337",
            BatchPayments: { BankAccountNumber: "062-000 13371337", BankAccountName: "Acme Supplies" },
          },
        ],
      },
    };
    const { sync, hook } = await both(req, lookup);
    expect(sync.decision).toBe("elicit");
    expect(lookup.paths).toEqual([`/api.xro/2.0/Contacts/${ID}`]);
    expect(hook).toEqual({
      decision: "elicit",
      category: "financial_legal",
      reason: "contact-sensitive-edit",
      summary: {
        contactId: ID,
        name: "Acme Supplies",
        bankAccountDetails: "062-000 1111 → 062-000 13371337",
        batchPayments:
          "BankAccountNumber=062-000 1111, BankAccountName=Acme Supplies → " +
          "BankAccountNumber=062-000 13371337, BankAccountName=Acme Supplies",
      },
    });
  });

  it("FIXED (F2-1): an email swap shows the stored address", async () => {
    const { hook } = await both(
      { body: { Contacts: [{ ContactID: ID, EmailAddress: "accounts@attacker.example" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(hook?.summary?.emailAddress).toBe("accounts@acme.example → accounts@attacker.example");
  });

  it("FIXED (F2-1): an archive shows ACTIVE → ARCHIVED", async () => {
    const { hook } = await both(
      { body: { ContactID: ID, ContactStatus: "ARCHIVED" } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(hook?.summary?.contactStatus).toBe("ACTIVE → ARCHIVED");
  });

  it("FIXED (F2-1): an absent stored field shows (none); a cleared one (cleared)", async () => {
    const { hook } = await both(
      {
        body: {
          Contacts: [
            {
              ContactID: ID,
              ContactPersons: [{ EmailAddress: "a@attacker.example", IncludeInEmails: true }],
              EmailAddress: null,
            },
          ],
        },
      },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(hook?.summary?.contactPersons).toBe("(none) → a@attacker.example (in emails)");
    expect(hook?.summary?.emailAddress).toBe("accounts@acme.example → (cleared)");
  });

  it("encodes the id as one path segment", async () => {
    const lookup = fakeLookup({ status: 404, body: {} });
    await both({ body: { Contacts: [{ ContactNumber: "a/b?c#d", TaxNumber: "1" }] } }, lookup);
    expect(lookup.paths).toEqual(["/api.xro/2.0/Contacts/a%2Fb%3Fc%23d"]);
  });

  it("REFUTED: creates and plain edits pay no lookup", async () => {
    for (const body of [
      { Contacts: [{ Name: "New", EmailAddress: "n@n.example", BankAccountDetails: "1" }] },
      { Contacts: [{ ContactID: ID, Website: "https://acme.example" }] },
      { ContactNumber: "SUP-7", Addresses: [] },
    ]) {
      const lookup = fakeLookup(stored(STORED_ACME));
      expect(await inspectStoredContact({ body }, lookup)).toEqual({ decision: "allow" });
      expect(lookup.paths).toEqual([]);
    }
  });

  it("denies contact-not-found on a 404 by ContactID", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID, EmailAddress: "a@attacker.example" }] } },
      fakeLookup({ status: 404, body: { Message: "not found" } }),
    );
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-not-found" });
  });

  it("treats a 404 by ContactNumber as a create: (none) → new, name (new contact)", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactNumber: "SUP-7", EmailAddress: "a@attacker.example" }] } },
      fakeLookup({ status: 404, body: {} }),
    );
    expect(r).toEqual({
      decision: "elicit",
      category: "financial_legal",
      reason: "contact-sensitive-edit",
      summary: {
        contactId: "number SUP-7",
        name: "(new contact)",
        emailAddress: "(none) → a@attacker.example",
      },
    });
  });

  it("denies contact-read-failed on another non-2xx, with the status and no upstream text", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID, TaxNumber: "1" }] } },
      fakeLookup({ status: 500, body: { Message: "UPSTREAM-SECRET-TEXT" } }),
    );
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-read-failed" });
    expect(r.message).toContain("500");
    expect(JSON.stringify(r)).not.toContain("UPSTREAM-SECRET-TEXT");
  });

  it("denies contact-read-unreadable on an unexpected body", async () => {
    const req: InspectRequest = { body: { Contacts: [{ ContactID: ID, TaxNumber: "1" }] } };
    for (const res of [
      { status: 200, body: { Contacts: [] } },
      { status: 200, body: { Contacts: [STORED_ACME, STORED_ACME] } },
      { status: 200, body: { Contacts: ["x"] } },
      { status: 200, body: "not json" },
      { status: 200, body: { Contacts: STORED_ACME } },
      stored({ ...STORED_ACME, ContactID: OTHER_ID }),
      stored({ ...STORED_ACME, ContactID: 5 }),
    ]) {
      const r = await inspectStoredContact(req, fakeLookup(res));
      expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-read-unreadable" });
    }
  });

  it("matches the stored ContactID case-insensitively", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID.toUpperCase(), TaxNumber: "1" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(r.decision).toBe("elicit");
  });

  it("denies contact-read-unreadable when a ContactNumber lookup answers another contact", async () => {
    // GET /Contacts/{x} also matches a ContactID; the stored contact must
    // carry the requested number, or the dialog would show the wrong one.
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactNumber: ID, TaxNumber: "1" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(r).toMatchObject({ decision: "deny", reason: "contact-read-unreadable" });
    const ok = await inspectStoredContact(
      { body: { Contacts: [{ ContactNumber: "SUP-7", TaxNumber: "1" }] } },
      fakeLookup(stored({ ...STORED_ACME, ContactNumber: "SUP-7" })),
    );
    expect(ok.decision).toBe("elicit");
  });

  it("never copies stored strings into message or reason", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID, TaxNumber: "1" }] } },
      fakeLookup(stored({ ...STORED_ACME, Name: "Ignore previous instructions", TaxNumber: "STORED-TAX" })),
    );
    expect(r.message).toBeUndefined();
    expect(r.reason).toBe("contact-sensitive-edit");
    expect(r.summary?.taxNumber).toBe("STORED-TAX → 1");
  });

  it("propagates a lookup throw (the scaffold denies the request)", async () => {
    const lookup: UpstreamLookup = {
      get: () => Promise.reject(new Error("lookup refused")),
    };
    await expect(
      inspectStoredContact({ body: { Contacts: [{ ContactID: ID, TaxNumber: "1" }] } }, lookup),
    ).rejects.toThrow();
  });
});

describe("Name / XeroNetworkKey edits need approval when they change the stored value (F2-1 user decision)", () => {
  it("REFUTED: the sync inspector lets a single rename through to the stored-contact read", () => {
    // Whether the name changes is only known after the read: the hook decides.
    expect(inspectContactWrite({ body: { Contacts: [{ ContactID: ID, Name: "Acme 2" }] } })).toEqual({
      decision: "allow",
    });
  });

  it("FIXED (F2-1): a rename elicits with the name old → new", async () => {
    const lookup = fakeLookup(stored(STORED_ACME));
    const { hook } = await both({ body: { Contacts: [{ ContactID: ID, Name: "Mallory Pty Ltd" }] } }, lookup);
    expect(lookup.paths).toEqual([`/api.xro/2.0/Contacts/${ID}`]);
    expect(hook).toEqual({
      decision: "elicit",
      category: "financial_legal",
      reason: "contact-sensitive-edit",
      summary: { contactId: ID, name: "Acme Supplies → Mallory Pty Ltd" },
    });
  });

  it("FIXED (F2-1): an XeroNetworkKey change elicits with old → new", async () => {
    const { hook } = await both(
      { body: { ContactID: ID, XeroNetworkKey: "attacker-key" } },
      fakeLookup(stored({ ...STORED_ACME, XeroNetworkKey: "acme-key" })),
    );
    expect(hook).toMatchObject({ decision: "elicit", reason: "contact-sensitive-edit" });
    expect(hook?.summary).toEqual({
      contactId: ID,
      name: "Acme Supplies",
      xeroNetworkKey: "acme-key → attacker-key",
    });
  });

  it("FIXED (F2-1): a first XeroNetworkKey (none stored) and a cleared one elicit", async () => {
    const set = await inspectStoredContact(
      { body: { ContactID: ID, xeronetworkkey: "k" } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(set.summary?.xeroNetworkKey).toBe("(none) → k");
    const cleared = await inspectStoredContact(
      { body: { ContactID: ID, XeroNetworkKey: null } },
      fakeLookup(stored({ ...STORED_ACME, XeroNetworkKey: "acme-key" })),
    );
    expect(cleared.summary?.xeroNetworkKey).toBe("acme-key → (cleared)");
  });

  it("REFUTED: an unchanged Name / XeroNetworkKey (model echoes the contact) is a plain allow after the read", async () => {
    const lookup = fakeLookup(stored({ ...STORED_ACME, XeroNetworkKey: "acme-key" }));
    const r = await inspectStoredContact(
      {
        body: {
          Contacts: [
            { ContactID: ID, Name: "Acme Supplies", XeroNetworkKey: "acme-key", Website: "https://acme.example" },
          ],
        },
      },
      lookup,
    );
    expect(r).toEqual({ decision: "allow" });
    expect(lookup.paths).toHaveLength(1);
  });

  it("FIXED (F2-1): a sensitive edit that also renames shows both changes", async () => {
    const { sync, hook } = await both(
      { body: { Contacts: [{ ContactID: ID, Name: "Acme 2", EmailAddress: "accounts@attacker.example" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(sync.summary).toEqual({
      contactId: ID,
      name: "→ Acme 2",
      emailAddress: "→ accounts@attacker.example",
    });
    expect(hook?.summary).toEqual({
      contactId: ID,
      name: "Acme Supplies → Acme 2",
      emailAddress: "accounts@acme.example → accounts@attacker.example",
    });
  });

  it("a sensitive edit carrying the stored Name shows the name plainly", async () => {
    const { hook } = await both(
      { body: { Contacts: [{ ContactID: ID, Name: "Acme Supplies", TaxNumber: "1" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(hook?.summary).toEqual({ contactId: ID, name: "Acme Supplies", taxNumber: "(none) → 1" });
  });

  it("REFUTED: creates with a Name stay a plain allow and pay no lookup", async () => {
    const lookup = fakeLookup(stored(STORED_ACME));
    const req: InspectRequest = { body: { Contacts: [{ Name: "Acme 2", XeroNetworkKey: "k" }, { Name: "B" }] } };
    expect(inspectContactWrite(req)).toEqual({ decision: "allow" });
    expect(await inspectStoredContact(req, lookup)).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([]);
  });

  it("REFUTED: a ContactNumber-keyed rename that is a create (404) is a plain allow", async () => {
    const r = await inspectStoredContact(
      { body: { ContactNumber: "SUP-9", Name: "New Supplier" } },
      fakeLookup({ status: 404, body: {} }),
    );
    expect(r).toEqual({ decision: "allow" });
  });

  it("a ContactNumber create (404) with a sensitive field shows the new name", async () => {
    const r = await inspectStoredContact(
      { body: { ContactNumber: "SUP-9", Name: "New Supplier", TaxNumber: "1" } },
      fakeLookup({ status: 404, body: {} }),
    );
    expect(r.summary).toEqual({ contactId: "number SUP-9", name: "(new contact) → New Supplier", taxNumber: "(none) → 1" });
  });

  it("denies a rename of a ContactID that does not exist, and a failed read", async () => {
    const body = { Contacts: [{ ContactID: ID, Name: "Acme 2" }] };
    expect(await inspectStoredContact({ body }, fakeLookup({ status: 404, body: {} }))).toMatchObject({
      decision: "deny",
      reason: "contact-not-found",
    });
    expect(await inspectStoredContact({ body }, fakeLookup({ status: 503, body: {} }))).toMatchObject({
      decision: "deny",
      reason: "contact-read-failed",
    });
  });

  it("FIXED (F2-1): an edit carrying Name or XeroNetworkKey beside other items is denied (one per request)", () => {
    for (const body of [
      { Contacts: [{ ContactID: ID, Name: "Acme 2" }, { Name: "A create" }] },
      { Contacts: [{ ContactID: ID, Website: "w" }, { ContactNumber: "7", XeroNetworkKey: "k" }] },
    ]) {
      expect(inspectContactWrite({ body })).toMatchObject({
        decision: "deny",
        category: "financial_legal",
        reason: "contact-one-per-request",
      });
    }
  });

  it("denies an edit whose Name or XeroNetworkKey is not a string (or null)", () => {
    for (const item of [
      { ContactID: ID, Name: 5 },
      { ContactID: ID, Name: { First: "x" } },
      { ContactID: ID, XeroNetworkKey: ["k"] },
    ]) {
      expect(inspectContactWrite({ body: { Contacts: [item] } })).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "contact-field-unreadable",
      });
    }
  });

  it("denies two spellings of Name or XeroNetworkKey", () => {
    for (const item of [
      { ContactID: ID, Name: "a", name: "b" },
      { ContactID: ID, XeroNetworkKey: "a", xeronetworkkey: "b" },
    ]) {
      expect(inspectContactWrite({ body: { Contacts: [item] } })).toMatchObject({
        decision: "deny",
        reason: "contact-ambiguous-key",
      });
    }
  });

  it("denies a change carrying every gated field (more facts than the dialog shows)", () => {
    const r = inspectContactWrite({
      body: {
        ContactID: ID,
        Name: "n",
        BankAccountDetails: "1",
        BatchPayments: { Code: "c" },
        EmailAddress: "e@e.example",
        ContactStatus: "ACTIVE",
        TaxNumber: "2",
        ContactPersons: [],
        XeroNetworkKey: "k",
      },
    });
    expect(r).toMatchObject({ decision: "deny", category: "financial_legal", reason: "contact-too-many-fields" });
  });
});

describe("rendered facts must fit the dialog's 200-code-point fact cap (F2-1 review)", () => {
  // The scaffold cuts a fact value at 200 code points after collapsing
  // whitespace (scaffold/src/elicit.ts FACT_VALUE_MAX): "old → new" would
  // lose the attacker's new value.
  const FACT_VALUE_MAX = 200;

  it("FIXED: a new value longer than the cap is denied in the sync inspector", () => {
    const r = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, BankAccountDetails: "1".repeat(FACT_VALUE_MAX - 1) }] },
    });
    expect(r).toMatchObject({ decision: "deny", category: "financial_legal", reason: "contact-value-too-long" });
  });

  it("allows exactly 200 code points (after whitespace collapse) in the sync inspector", () => {
    // "→ " + 198 = 200. Whitespace runs count as one space.
    const ok = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, BankAccountDetails: "1".repeat(196) + "   \t 2" }] },
    });
    expect(ok.decision).toBe("elicit");
    const over = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, BankAccountDetails: "1".repeat(197) + "   \t 2" }] },
    });
    expect(over).toMatchObject({ decision: "deny", reason: "contact-value-too-long" });
  });

  it("collapses zero-width and U+3164 padding runs as the scaffold does (parity)", () => {
    // 190 visible code points; "→ " makes 192. Each padding run is cleaned to
    // one space by the scaffold (U+200B is a format char → space, U+3164 is
    // a filler in the whitespace class), so 8 runs add 8: 200, allowed.
    const pad = (s: string) => s.repeat(5);
    const runs = ["\u200B", "\u3164", "\u200B\u3164", "\u3164 \u200B"];
    let value = "";
    for (let i = 0; i < 8; i++) value += "1".repeat(i === 0 ? 22 : 24) + pad(runs[i % runs.length]!);
    expect(Array.from(value.replace(/[^1]/g, "")).length).toBe(190);
    const ok = inspectContactWrite({ body: { Contacts: [{ ContactID: ID, BankAccountDetails: value }] } });
    expect(ok.decision).toBe("elicit");
    // Same visible content, the runs replaced by plain single characters
    // that do not collapse: 201 code points, denied.
    const plain = value.replace(/[\u200B\u3164 ]+/g, "x") + "x";
    expect(Array.from("→ " + plain).length).toBe(201);
    expect(
      inspectContactWrite({ body: { Contacts: [{ ContactID: ID, BankAccountDetails: plain }] } }),
    ).toMatchObject({ decision: "deny", reason: "contact-value-too-long" });
  });

  it("counts code points, not UTF-16 units", () => {
    const ok = inspectContactWrite({
      body: { Contacts: [{ ContactID: ID, EmailAddress: "😀".repeat(198) }] },
    });
    expect(ok.decision).toBe("elicit");
  });

  it("FIXED: old → new longer than the cap is denied by the hook", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID, EmailAddress: "x".repeat(170) + "@attacker.example" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(r).toMatchObject({ decision: "deny", category: "financial_legal", reason: "contact-value-too-long" });
    expect(JSON.stringify(r)).not.toContain("attacker.example");
  });

  it("FIXED: a rename whose old → new exceeds the cap is denied by the hook", async () => {
    const r = await inspectStoredContact(
      { body: { ContactID: ID, Name: "N".repeat(190) } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(r).toMatchObject({ decision: "deny", reason: "contact-value-too-long" });
  });

  it("a long stored name that does not change is not a reason to deny", async () => {
    const r = await inspectStoredContact(
      { body: { ContactID: ID, TaxNumber: "1" } },
      fakeLookup(stored({ ...STORED_ACME, Name: "L".repeat(250) })),
    );
    expect(r.decision).toBe("elicit");
  });
});

describe("ContactID and ContactNumber together (F2-1 review)", () => {
  it("FIXED: the stored ContactNumber must match the body's too", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID, ContactNumber: "OTHER-1", TaxNumber: "1" }] } },
      fakeLookup(stored({ ...STORED_ACME, ContactNumber: "SUP-7" })),
    );
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "contact-number-mismatch" });
    const none = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID, ContactNumber: "SUP-7", TaxNumber: "1" }] } },
      fakeLookup(stored(STORED_ACME)),
    );
    expect(none).toMatchObject({ decision: "deny", reason: "contact-number-mismatch" });
  });

  it("allows the approval when both match: ContactID case-insensitively, ContactNumber exactly", async () => {
    const r = await inspectStoredContact(
      { body: { Contacts: [{ ContactID: ID.toUpperCase(), ContactNumber: "SUP-7", TaxNumber: "1" }] } },
      fakeLookup(stored({ ...STORED_ACME, ContactNumber: "SUP-7" })),
    );
    expect(r.decision).toBe("elicit");
  });

  it("compares ContactNumber exactly (Xero's case rule for it is unverified)", async () => {
    for (const n of ["sup-7", " SUP-7", "SUP-7 "]) {
      const both = await inspectStoredContact(
        { body: { Contacts: [{ ContactID: ID, ContactNumber: n, TaxNumber: "1" }] } },
        fakeLookup(stored({ ...STORED_ACME, ContactNumber: "SUP-7" })),
      );
      expect(both).toMatchObject({ decision: "deny", reason: "contact-number-mismatch" });
      const byNumber = await inspectStoredContact(
        { body: { Contacts: [{ ContactNumber: n, TaxNumber: "1" }] } },
        fakeLookup(stored({ ...STORED_ACME, ContactNumber: "SUP-7" })),
      );
      expect(byNumber).toMatchObject({ decision: "deny", reason: "contact-read-unreadable" });
    }
  });
});

// Security review (wave 3): Xero's XML-era requests used the singular root
// (`<Contact>`); whether the JSON API still unwraps `{ Contact: {…} }` is
// unverified. Read flat, that body is a create with no id and would be allowed
// with no read, while Xero might apply it as an edit. Fail closed.
describe("a flat body keyed by the singular root `Contact` is refused (wave 3 review)", () => {
  it("FIXED: `{ Contact: { ContactID, BankAccountDetails } }` is denied contact-unexpected-key, any casing", () => {
    for (const key of ["Contact", "contact", "CONTACT"]) {
      expect(inspectContactWrite({ body: { [key]: { ContactID: ID, BankAccountDetails: "062-000 13371337" } } }), key)
        .toMatchObject({ decision: "deny", reason: "contact-unexpected-key" });
    }
  });

  it("a flat create with ordinary fields is still allowed", () => {
    expect(inspectContactWrite({ body: { Name: "New Co", EmailAddress: "a@b.example" } })).toEqual({ decision: "allow" });
  });
});
