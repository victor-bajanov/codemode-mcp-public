// F2-1 regression, end to end: the real request handler with the real Xero
// provider (spec, surface review, contact inspector, stored-contact hook,
// contactChange renderer, requestHeaders hook). Only the edges are mocked:
// upstream `fetch` (routed by URL so the stored-contact GET answers a
// configured contact), the token broker, and the MCP server's `elicitInput`.
//
// Attacker: a prompt-injected LLM in a legitimate Xero user's session, whose
//   task plausibly touches contacts ("update the supplier record").
// Precondition: a connected Xero tenant; for the dialog cases an MCP client
//   that supports elicitation (Claude.ai does not: there the edit is denied).
// Payload: `POST /Contacts` (updateOrCreateContacts) carrying an existing
//   `ContactID` with the attacker's `BankAccountDetails` / `BatchPayments`
//   (every future bill paid to the supplier goes to the attacker's account);
//   an `EmailAddress` swap (every invoice emailed to the attacker); a bulk
//   archive hiding one email swap among harmless items; a rename or a new
//   `XeroNetworkKey` that makes a stored payee look like someone else.
// Control: the contact entries run `inspectContactWrite` (sync) and
//   `inspectStoredContact` (reads `GET /Contacts/{id}` through the same
//   handler, with the bearer token and tenant header), and a gated edit is
//   `elicit` (financial_legal, `contact-sensitive-edit`) whose dialog shows
//   the stored name and `old → new` per field; a sensitive edit beside other
//   items is denied `contact-one-per-request`; a failed or missing read
//   denies; a client without elicitation is denied `unsupported`. Creates
//   and plain edits (no sensitive field, Name/XeroNetworkKey unchanged) stay
//   allowed. The by-id `updateContact`, contact-group, history and
//   attachment routes stay out of the surface review.
// Pre-fix: `createContacts` and `updateOrCreateContacts` were bare
//   `{ decision: "allow", category: "standard_write" }`: no inspector, no
//   read, no dialog, the POST left the Worker and the audit line was a plain
//   `allow`. Every `FIXED` probe below asserts the GET, the dialog or the
//   deny reason, so each fails against that entry (verified by reverting the
//   two entries to the bare allow and watching the suite fail). The deny
//   probes assert the audit `reason` so a deny from another control (D-2
//   query policy, D-3 canonical JSON, "not in surface review") cannot pass
//   them.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";
import { surfaceReview } from "../surface-review";

interface Dialog {
  message: string;
  requestedSchema: unknown;
}

interface Wire {
  url: string;
  method: string;
  body: string | undefined;
  headers: Record<string, string>;
}

/** What the routed upstream answers to one request. */
interface Answer {
  status: number;
  body: unknown;
}

const CONFIRM_ONLY = {
  type: "object",
  properties: { confirm: { type: "boolean" } },
  required: ["confirm"],
  additionalProperties: false,
};

const CONTACTS_PATH = "/api.xro/2.0/Contacts";
const CONTACTS_URL = `${xeroProvider.apiBaseUrl}${CONTACTS_PATH}`;
const OP_POST = "xero.accounting.updateOrCreateContacts";
const OP_PUT = "xero.accounting.createContacts";
/** `GET /Contacts/{x}` matches two plain-allow templates (by id, by number); the matcher picks one. */
const CONTACT_GET_OP = /^xero\.accounting\.getContact(ByContactNumber)?$/;

// Invented ids (GUID-shaped so they look like Xero's).
const SUPPLIER_ID = "c0ffee00-1111-4222-8333-000000000001";
const OTHER_ID = "c0ffee00-1111-4222-8333-000000000002";
const THIRD_ID = "c0ffee00-1111-4222-8333-000000000003";

/** The supplier as Xero stores it: the real payee, the real email. */
const storedSupplier = {
  ContactID: SUPPLIER_ID,
  ContactNumber: "SUP-007",
  ContactStatus: "ACTIVE",
  Name: "Acme Supplies",
  EmailAddress: "accounts@acme.example",
  BankAccountDetails: "062-000 1111",
  BatchPayments: { BankAccountNumber: "062-000 1111", BankAccountName: "Acme Supplies" },
};

function harness(opts: {
  answer?: (d: Dialog) => unknown;
  capabilities?: Record<string, unknown>;
  /** Answers a GET by URL; undefined → `200 {"Status":"OK"}`. */
  routes?: (method: string, url: string) => Answer | undefined;
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
      const method = String(init?.method);
      wire.push({ url: String(url), method, body, headers: { ...(init?.headers as Record<string, string>) } });
      const routed = opts.routes?.(method, String(url)) ?? { status: 200, body: { Status: "OK" } };
      return new Response(JSON.stringify(routed.body), {
        status: routed.status,
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

  const writes = () => wire.filter((w) => w.method !== "GET");
  const reads = () => wire.filter((w) => w.method === "GET");
  return { call, dialogs, wire, audits, elicitInput, writes, reads };
}

/** Routes `GET …/Contacts/<id>` to `contact` (or a status), everything else to the default. */
function storedContact(contact: Record<string, unknown> | number, id = SUPPLIER_ID) {
  return (method: string, url: string): Answer | undefined => {
    if (method !== "GET" || url !== `${CONTACTS_URL}/${id}`) return undefined;
    if (typeof contact === "number") return { status: contact, body: { Title: "nope" } };
    return { status: 200, body: { Contacts: [contact] } };
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// The review's payload: repoint the supplier's payments to the attacker's account.
const bankRepoint = {
  Contacts: [
    {
      ContactID: SUPPLIER_ID,
      BankAccountDetails: "062-000 13371337",
      BatchPayments: { BankAccountNumber: "062-000 13371337", BankAccountName: "Acme Supplies" },
    },
  ],
};

describe("a payee-detail edit is read first and shown old → new (F2-1)", () => {
  it("FIXED (F2-1): the bank repoint reads the stored contact (bearer + tenant header), shows old → new, and the approved POST goes out unchanged", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint });

    // The stored read went through the same handler: bearer token, tenant header.
    expect(h.reads()).toHaveLength(1);
    const read = h.reads()[0]!;
    expect(read.url).toBe(`${CONTACTS_URL}/${SUPPLIER_ID}`);
    expect(read.headers["Authorization"]).toBe("Bearer AT");
    expect(read.headers["xero-tenant-id"]).toBe("tenant-a");

    expect(h.dialogs).toHaveLength(1);
    const d = h.dialogs[0]!;
    expect(d.requestedSchema).toEqual(CONFIRM_ONLY);
    expect(d.message.split("\n")).toEqual([
      `Confirm Xero contact change (${OP_POST})`,
      `Request: POST ${CONTACTS_PATH}`,
      `contactId: "${SUPPLIER_ID}"`,
      'name: "Acme Supplies"',
      'bankAccountDetails: "062-000 1111 → 062-000 13371337"',
      'batchPayments: "BankAccountNumber=062-000 1111, BankAccountName=Acme Supplies → BankAccountNumber=062-000 13371337, BankAccountName=Acme Supplies"',
      "Approve only if this is exactly the request you intended.",
    ]);

    // Approved: the POST is sent exactly as the sandbox wrote it, after the GET.
    expect(h.wire.map((w) => w.method)).toEqual(["GET", "POST"]);
    expect(h.writes()[0]!.url).toBe(CONTACTS_URL);
    expect(JSON.parse(h.writes()[0]!.body!)).toEqual(bankRepoint);

    // Audit: the GET's own allow line, then the POST's elicit line with the new reason.
    // (`/Contacts/{x}` matches both GET templates; the matcher picks one, both plain allows.)
    expect(h.audits.map((a) => a.decision)).toEqual(["allow", "elicit", "allow"]);
    expect(h.audits[0]!.operationId).toMatch(CONTACT_GET_OP);
    expect(h.audits[0]).toMatchObject({ method: "GET", upstreamStatus: 200 });
    expect(h.audits.slice(1).map((a) => a.operationId)).toEqual([OP_POST, OP_POST]);
    const elicit = h.audits.find((a) => a.decision === "elicit")!;
    expect(elicit).toMatchObject({
      reason: "contact-sensitive-edit",
      category: "financial_legal",
      elicitationOutcome: "accepted",
    });
    expect(elicit.elicitFields).toMatchObject({ contactId: SUPPLIER_ID, name: "Acme Supplies" });
  });

  it("FIXED (F2-1): `{ confirm: false }` and a decline send nothing (the GET alone goes out)", async () => {
    for (const answer of [
      () => ({ action: "accept", content: { confirm: false } }),
      () => ({ action: "decline" }),
    ]) {
      const h = harness({ routes: storedContact(storedSupplier), answer });
      await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint }))
        .rejects.toThrow(/requires user approval; outcome: declined/);
      expect(h.writes()).toHaveLength(0);
      expect(h.audits.find((a) => a.decision === "elicit")).toMatchObject({
        reason: "contact-sensitive-edit",
        elicitationOutcome: "declined",
      });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (F2-1): a client without elicitation (Claude.ai) is denied `unsupported`; no POST is sent", async () => {
    const h = harness({ routes: storedContact(storedSupplier), capabilities: {} });
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint }))
      .rejects.toThrow(/requires user approval; outcome: unsupported/);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.writes()).toHaveLength(0);
    expect(h.audits.find((a) => a.decision === "elicit")).toMatchObject({
      reason: "contact-sensitive-edit",
      elicitationOutcome: "unsupported",
    });
  });

  it("FIXED (F2-1): a PUT /Contacts carrying the id is judged the same way (the inspector reads the body, not the verb)", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await h.call({ method: "PUT", path: CONTACTS_PATH, body: bankRepoint });
    expect(h.wire.map((w) => w.method)).toEqual(["GET", "PUT"]);
    expect(h.dialogs[0]!.message).toContain(`Confirm Xero contact change (${OP_PUT})`);
    expect(h.dialogs[0]!.message).toContain('bankAccountDetails: "062-000 1111 → 062-000 13371337"');
    expect(h.audits.find((a) => a.decision === "elicit")).toMatchObject({ operationId: OP_PUT, reason: "contact-sensitive-edit" });
  });

  it("FIXED (F2-1): an email swap shows the stored address → the attacker's", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await h.call({
      method: "POST",
      path: CONTACTS_PATH,
      body: { Contacts: [{ ContactID: SUPPLIER_ID, EmailAddress: "accounts@attacker.example" }] },
    });
    expect(h.dialogs).toHaveLength(1);
    expect(h.dialogs[0]!.message).toContain('emailAddress: "accounts@acme.example → accounts@attacker.example"');
    expect(h.dialogs[0]!.message).toContain('name: "Acme Supplies"');
    expect(h.wire.map((w) => w.method)).toEqual(["GET", "POST"]);
  });

  it("FIXED (F2-1): an archive shows ACTIVE → ARCHIVED; a new contact person shows (none) → its email", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await h.call({ method: "POST", path: CONTACTS_PATH, body: { Contacts: [{ ContactID: SUPPLIER_ID, ContactStatus: "ARCHIVED" }] } });
    expect(h.dialogs[0]!.message).toContain('contactStatus: "ACTIVE → ARCHIVED"');

    await h.call({
      method: "POST",
      path: CONTACTS_PATH,
      body: { Contacts: [{ ContactID: SUPPLIER_ID, ContactPersons: [{ EmailAddress: "a@attacker.example", IncludeInEmails: true }] }] },
    });
    expect(h.dialogs[1]!.message).toContain('contactPersons: "(none) → a@attacker.example (in emails)"');
  });
});

describe("one sensitive contact per request (F2-1)", () => {
  // The review's second payload: one email swap hidden in a bulk archive.
  const swapInBulk = {
    Contacts: [
      { ContactID: OTHER_ID, ContactStatus: "ARCHIVED" },
      { ContactID: SUPPLIER_ID, EmailAddress: "accounts@attacker.example" },
      { ContactID: THIRD_ID, ContactStatus: "ARCHIVED" },
    ],
  };

  it("FIXED (F2-1): an email swap beside a bulk archive is denied `contact-one-per-request`; no read, no dialog, nothing sent", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: swapInBulk }))
      .rejects.toThrow(/must carry exactly one contact/);
    expect(h.wire).toHaveLength(0);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audits.at(-1)).toMatchObject({
      operationId: OP_POST,
      decision: "deny",
      category: "financial_legal",
      reason: "contact-one-per-request",
    });
  });

  it("FIXED (F2-1): a decoy key beside the Contacts array is denied `contact-unexpected-key`, even beside a harmless create", async () => {
    const h = harness();
    await expect(h.call({
      method: "POST",
      path: CONTACTS_PATH,
      body: { Contacts: [{ Name: "New Co" }], ContactID: SUPPLIER_ID, BankAccountDetails: "062-000 13371337" },
    })).rejects.toThrow(/may carry only the "Contacts" array/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "contact-unexpected-key" });
  });
});

// Wave-3 security review: Xero's XML-era requests used the singular root
// `<Contact>`. Whether the JSON API still unwraps `{ Contact: {…} }` is
// unverified; read flat it would be an id-less create (allowed, no read)
// that Xero might apply as an edit of the stored contact. Fail closed.
describe("a singular `Contact` root is refused (wave-3 review)", () => {
  it("FIXED: `{ Contact: { ContactID, BankAccountDetails } }` is denied `contact-unexpected-key`; nothing fetched", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    for (const method of ["POST", "PUT"] as const) {
      await expect(h.call({
        method,
        path: CONTACTS_PATH,
        body: { Contact: { ContactID: SUPPLIER_ID, BankAccountDetails: "062-000 13371337" } },
      }), method).rejects.toThrow(/may carry only the "Contacts" array/);
      expect(h.audits.at(-1), method).toMatchObject({ decision: "deny", reason: "contact-unexpected-key" });
    }
    expect(h.wire).toHaveLength(0);
    expect(h.elicitInput).not.toHaveBeenCalled();
  });
});

describe("the stored read is the control: its failure denies (F2-1)", () => {
  it("FIXED (F2-1): a 404 on the ContactID denies `contact-not-found` after the GET; nothing else is sent", async () => {
    const h = harness({ routes: storedContact(404) });
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint }))
      .rejects.toThrow(/No contact with this ContactID exists/);
    expect(h.wire.map((w) => w.method)).toEqual(["GET"]);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audits.at(-1)).toMatchObject({ operationId: OP_POST, decision: "deny", reason: "contact-not-found" });
  });

  it("FIXED (F2-1): a 500 on the read denies `contact-read-failed` with the status only (no upstream text reaches the caller)", async () => {
    const h = harness({ routes: storedContact(500) });
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint }))
      .rejects.toThrow(/Reading the stored contact failed \(HTTP 500\)/);
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint }))
      .rejects.not.toThrow(/nope/);
    expect(h.writes()).toHaveLength(0);
    expect(h.audits.filter((a) => a.decision === "deny").map((a) => a.reason)).toEqual(["contact-read-failed", "contact-read-failed"]);
  });

  it("FIXED (F2-1): a read that answers another contact denies `contact-read-unreadable` (the dialog would name the wrong payee)", async () => {
    const h = harness({ routes: storedContact({ ...storedSupplier, ContactID: OTHER_ID }) });
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: bankRepoint }))
      .rejects.toThrow(/could not be read as expected/);
    expect(h.writes()).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "contact-read-unreadable" });
  });
});

describe("a rename or a new Xero Network key is a gated edit (F2-1, user decision)", () => {
  it("FIXED (F2-1): a rename reads the stored contact and shows old → new; approval sends it", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    const rename = { Contacts: [{ ContactID: SUPPLIER_ID, Name: "Acme Supplies Pty Ltd" }] };
    await h.call({ method: "POST", path: CONTACTS_PATH, body: rename });
    expect(h.dialogs).toHaveLength(1);
    expect(h.dialogs[0]!.message.split("\n")).toEqual([
      `Confirm Xero contact change (${OP_POST})`,
      `Request: POST ${CONTACTS_PATH}`,
      `contactId: "${SUPPLIER_ID}"`,
      'name: "Acme Supplies → Acme Supplies Pty Ltd"',
      "Approve only if this is exactly the request you intended.",
    ]);
    expect(h.wire.map((w) => w.method)).toEqual(["GET", "POST"]);
    expect(JSON.parse(h.writes()[0]!.body!)).toEqual(rename);
    expect(h.audits.find((a) => a.decision === "elicit")).toMatchObject({ reason: "contact-sensitive-edit", elicitationOutcome: "accepted" });
  });

  it("FIXED (F2-1): a new XeroNetworkKey shows (none) → the key", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await h.call({ method: "POST", path: CONTACTS_PATH, body: { Contacts: [{ ContactID: SUPPLIER_ID, XeroNetworkKey: "attacker-network-key" }] } });
    expect(h.dialogs[0]!.message).toContain('xeroNetworkKey: "(none) → attacker-network-key"');
    expect(h.dialogs[0]!.message).toContain('name: "Acme Supplies"');
    expect(h.wire.map((w) => w.method)).toEqual(["GET", "POST"]);
  });

  it("FIXED (F2-1): the stored Name echoed back unchanged (the read-modify-write shape) is allowed after the read, with no dialog", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await h.call({
      method: "POST",
      path: CONTACTS_PATH,
      body: { Contacts: [{ ContactID: SUPPLIER_ID, Name: "Acme Supplies", Addresses: [{ AddressType: "STREET", City: "Springfield" }] }] },
    });
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.wire.map((w) => w.method)).toEqual(["GET", "POST"]);
    expect(h.audits.map((a) => a.decision)).toEqual(["allow", "allow"]);
    expect(h.audits[0]!.operationId).toMatch(CONTACT_GET_OP);
    expect(h.audits[1]!.operationId).toBe(OP_POST);
  });

  it("FIXED (F2-1): a rename on a client without elicitation (Claude.ai) is denied `unsupported`; nothing is written", async () => {
    const h = harness({ routes: storedContact(storedSupplier), capabilities: {} });
    await expect(h.call({ method: "POST", path: CONTACTS_PATH, body: { Contacts: [{ ContactID: SUPPLIER_ID, Name: "Acme Supplies Pty Ltd" }] } }))
      .rejects.toThrow(/requires user approval; outcome: unsupported/);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.writes()).toHaveLength(0);
    expect(h.audits.find((a) => a.decision === "elicit")).toMatchObject({ reason: "contact-sensitive-edit", elicitationOutcome: "unsupported" });
  });

  it("FIXED (F2-1): a rename beside a second item is denied `contact-one-per-request` before any read", async () => {
    const h = harness({ routes: storedContact(storedSupplier) });
    await expect(h.call({
      method: "POST",
      path: CONTACTS_PATH,
      body: { Contacts: [{ ContactID: SUPPLIER_ID, Name: "Acme Supplies Pty Ltd" }, { ContactID: OTHER_ID, Website: "https://example.test" }] },
    })).rejects.toThrow(/must carry exactly one contact/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "contact-one-per-request" });
  });
});

describe("what stays open (controls)", () => {
  it("REFUTED: creates with bank, email and batch-payment details are sent with no read and no dialog, on PUT and POST", async () => {
    const create = {
      Contacts: [{ Name: "New Supplier", EmailAddress: "ap@new-supplier.example", BankAccountDetails: "062-000 2222",
        BatchPayments: { BankAccountNumber: "062-000 2222", BankAccountName: "New Supplier" } }],
    };
    for (const method of ["PUT", "POST"] as const) {
      const h = harness();
      await h.call({ method, path: CONTACTS_PATH, body: create });
      expect(h.wire.map((w) => w.method)).toEqual([method]);
      expect(JSON.parse(h.wire[0]!.body!)).toEqual(create);
      expect(h.elicitInput).not.toHaveBeenCalled();
      expect(h.audits.at(-1)).toMatchObject({ decision: "allow", operationId: method === "PUT" ? OP_PUT : OP_POST });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("REFUTED: a bulk of three creates is one PUT, no read, no dialog", async () => {
    const h = harness();
    const bulk = { Contacts: [{ Name: "A" }, { Name: "B", EmailAddress: "b@b.example" }, { Name: "C", BankAccountDetails: "1" }] };
    await h.call({ method: "PUT", path: CONTACTS_PATH, body: bulk });
    expect(h.wire.map((w) => w.method)).toEqual(["PUT"]);
    expect(h.elicitInput).not.toHaveBeenCalled();
  });

  it("REFUTED: a plain edit (address, phones; no Name) is sent with no read and no dialog", async () => {
    const h = harness();
    await h.call({
      method: "POST",
      path: CONTACTS_PATH,
      body: { Contacts: [{ ContactID: SUPPLIER_ID, Addresses: [{ AddressType: "POBOX", City: "Springfield" }], Phones: [{ PhoneType: "DEFAULT", PhoneNumber: "5551234" }] }] },
    });
    expect(h.wire.map((w) => w.method)).toEqual(["POST"]);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audits).toHaveLength(1);
    expect(h.audits[0]).toMatchObject({ operationId: OP_POST, decision: "allow" });
  });

  it("REFUTED: the review's contrast cases are unchanged — an AUTHORISED invoice is denied and the payment routes are not exposed", async () => {
    const h = harness();
    await expect(h.call({
      method: "PUT",
      path: "/api.xro/2.0/Invoices",
      body: { Invoices: [{ Type: "ACCPAY", Status: "AUTHORISED", Contact: { ContactID: SUPPLIER_ID }, LineItems: [{ Description: "x", UnitAmount: 48500, AccountCode: "400" }] }] },
    })).rejects.toThrow(/Only DRAFT or SUBMITTED invoices/);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
    for (const [method, path] of [["POST", "/api.xro/2.0/Payments"], ["PUT", "/api.xro/2.0/Payments"]] as const) {
      await expect(h.call({ method, path, body: { Payments: [{ Amount: 1 }] } })).rejects.toThrow(/not in surface review/);
    }
    expect(h.wire).toHaveLength(0);
  });
});

describe("the other contact write routes stay out of the surface review", () => {
  const groupId = "d00d0000-1111-4222-8333-000000000009";
  const cases: Array<[string, UpstreamCtx]> = [
    ["by-id updateContact", { method: "POST", path: `${CONTACTS_PATH}/${SUPPLIER_ID}`, body: { BankAccountDetails: "062-000 13371337" } }],
    ["createContactGroupContacts", { method: "PUT", path: `/api.xro/2.0/ContactGroups/${groupId}/Contacts`, body: { Contacts: [{ ContactID: SUPPLIER_ID }] } }],
    ["deleteContactGroupContacts", { method: "DELETE", path: `/api.xro/2.0/ContactGroups/${groupId}/Contacts` }],
    ["deleteContactGroupContact", { method: "DELETE", path: `/api.xro/2.0/ContactGroups/${groupId}/Contacts/${SUPPLIER_ID}` }],
    ["createContactGroup", { method: "PUT", path: "/api.xro/2.0/ContactGroups", body: { ContactGroups: [{ Name: "VIP" }] } }],
    ["updateContactGroup", { method: "POST", path: `/api.xro/2.0/ContactGroups/${groupId}`, body: { ContactGroups: [{ Name: "VIP" }] } }],
    ["createContactAttachmentByFileName", { method: "PUT", path: `${CONTACTS_PATH}/${SUPPLIER_ID}/Attachments/x.pdf`, bodyBase64: "JVBERi0=", contentType: "application/pdf" }],
  ];

  for (const [label, ctx] of cases) {
    it(`REFUTED: ${label} is rejected "not in surface review"; nothing is sent`, async () => {
      const h = harness();
      await expect(h.call(ctx)).rejects.toThrow(/not in surface review/);
      expect(h.wire).toHaveLength(0);
      expect(h.elicitInput).not.toHaveBeenCalled();
    });
  }

  it("REFUTED: the seven route ids are absent from the surface review (pinned)", () => {
    for (const id of [
      "xero.accounting.updateContact",
      "xero.accounting.createContactGroupContacts",
      "xero.accounting.deleteContactGroupContacts",
      "xero.accounting.deleteContactGroupContact",
      "xero.accounting.createContactGroup",
      "xero.accounting.updateContactGroup",
      "xero.accounting.createContactHistory",
      "xero.accounting.createContactAttachmentByFileName",
    ]) {
      expect(surfaceReview[id], id).toBeUndefined();
    }
  });
});
