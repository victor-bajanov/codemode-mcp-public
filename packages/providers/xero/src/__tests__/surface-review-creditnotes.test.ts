// packages/providers/xero/src/__tests__/surface-review-creditnotes.test.ts
//
// Inspector for createCreditNotes / updateOrCreateCreditNotes / updateCreditNote.
// Mirrors the invoice draft policy (same Status enum, same SentToContact gate):
//   - Status ∈ {DRAFT, SUBMITTED} → allow.
//   - Status omitted + CreditNoteID present → allow (update preserving existing state).
//   - Status omitted + no CreditNoteID → deny (would be a create with no explicit state).
//   - any other Status (AUTHORISED, PAID, VOIDED, DELETED) → deny.
//   - SentToContact === true → deny regardless of Status.
//
// Denials carry a human-readable `message` so the caller sees *why* (only DRAFT/SUBMITTED
// allowed, plus the offending status) instead of the opaque "denied by surface review".

import { describe, it, expect } from "vitest";
import { inspectCreditNoteDraft } from "../inspectors/drafts";

describe("inspectCreditNoteDraft", () => {
  it("allows a DRAFT ACCRECCREDIT credit note", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Type: "ACCRECCREDIT", Status: "DRAFT", Contact: { Name: "Acme" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows a SUBMITTED ACCPAYCREDIT credit note", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Type: "ACCPAYCREDIT", Status: "SUBMITTED" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies an AUTHORISED credit note (irreversible — issued to ledger)", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Type: "ACCRECCREDIT", Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft" });
  });

  it("denies a PAID credit note", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Status: "PAID" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft" });
  });

  it("denies SentToContact:true (mail-out trigger; off-channel exfil)", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Status: "DRAFT", SentToContact: true }] },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "creditnote-sent-to-contact" });
  });

  it("denies when Status is missing and no CreditNoteID (would be a create)", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Type: "ACCRECCREDIT" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft" });
  });

  it("denies when CreditNotes array is empty", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [] },
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "creditnote-no-payload" });
  });

  it("denies when CreditNotes key is missing", () => {
    expect(inspectCreditNoteDraft({ body: {} })).toMatchObject({
      decision: "deny", category: "malformed", reason: "creditnote-no-payload",
    });
  });

  it("denies when ANY credit note in a batch is non-draft (most-restrictive across the batch)", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Status: "DRAFT" }, { Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", reason: "creditnote-not-draft" });
  });

  it("treats Status case-insensitively", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ Status: "draft" }] },
    })).toEqual({ decision: "allow" });
  });

  // === Status-omitted updates: CreditNoteID signals "preserve existing state" ===

  it("allows a bulk update with CreditNoteID and no Status (preserve existing state)", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ CreditNoteID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Reference: "edit" }] },
    })).toEqual({ decision: "allow" });
  });

  it("still denies a bulk update when CreditNoteID is present but Status is AUTHORISED", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ CreditNoteID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft" });
  });

  it("denies a bulk update with empty-string CreditNoteID and no Status", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNotes: [{ CreditNoteID: "" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft" });
  });

  // === Singular by-ID update (POST /CreditNotes/{ID}) — flat body, no CreditNotes wrapper ===

  it("allows a DRAFT singular flat-body credit note", () => {
    expect(inspectCreditNoteDraft({
      body: { Type: "ACCRECCREDIT", Status: "DRAFT" },
    })).toEqual({ decision: "allow" });
  });

  it("allows a singular flat-body update with CreditNoteID and no Status", () => {
    expect(inspectCreditNoteDraft({
      body: { CreditNoteID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Reference: "edit" },
    })).toEqual({ decision: "allow" });
  });

  it("denies a singular flat-body AUTHORISED credit note", () => {
    expect(inspectCreditNoteDraft({
      body: { Type: "ACCRECCREDIT", Status: "AUTHORISED" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft" });
  });

  // === Clear, non-opaque denial messages (the point of this change) ===

  it("emits a clear message on a status denial naming the offending status and the allowed set", () => {
    const result = inspectCreditNoteDraft({
      body: { CreditNotes: [{ Status: "AUTHORISED" }] },
    });
    expect(result.decision).toBe("deny");
    expect(result.message).toBeDefined();
    expect(result.message).toContain("AUTHORISED");
    expect(result.message).toContain("DRAFT");
    expect(result.message).toContain("SUBMITTED");
  });

  it("emits a clear message on a sent-to-contact denial", () => {
    const result = inspectCreditNoteDraft({
      body: { CreditNotes: [{ Status: "DRAFT", SentToContact: true }] },
    });
    expect(result.decision).toBe("deny");
    expect(result.message).toBeDefined();
    expect(result.message?.toLowerCase()).toContain("senttocontact");
  });
});
