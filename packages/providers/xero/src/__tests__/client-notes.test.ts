// STRUCTURAL invariants for Xero `clientNote`s, plus the summary/description
// reachability checks.
//
// What a note SAYS is verified in client-note-semantics.test.ts by running the
// real inspector — string matching was shown to accept notes claiming
// "`IsReconciled: true` is allowed" and listing AUTHORISED as a permitted
// Status. Do not add vocabulary assertions here.

import { describe, it, expect } from "vitest";
// Imported from the scaffold's dependency-free subpath: the main entry pulls in
// `cloudflare:workers` transitively, and this package has no stub for it.
import {
  annotateSpecWithSurfaceReview,
  SURFACE_REVIEW_MARKER,
  SURFACE_REVIEW_SUMMARY_MARKER,
} from "@local/scaffold/annotate-spec";
import specJson from "../spec.json" with { type: "json" };
import { surfaceReview } from "../surface-review";
import { xeroProvider } from "../index";

const inspected = Object.entries(surfaceReview).filter(([, e]) => e.inspect !== undefined);

const INVOICE_OPS = [
  "xero.accounting.createInvoices",
  "xero.accounting.updateOrCreateInvoices",
  "xero.accounting.updateInvoice",
];
const CREDIT_NOTE_OPS = [
  "xero.accounting.createCreditNotes",
  "xero.accounting.updateOrCreateCreditNotes",
  "xero.accounting.updateCreditNote",
];
const BANK_TX_OPS = [
  "xero.accounting.createBankTransactions",
  "xero.accounting.updateBankTransaction",
];
/**
 * Scope reachability for Xero, mechanically.
 *
 * Xero's granular scopes replace the deprecated coarse families in TWO
 * different shapes, and conflating them is what makes a naive audit useless
 * (83 flagged, essentially all false):
 *
 *   RENAME    `accounting.transactions[.read]` → `accounting.invoices[.read]`,
 *             `accounting.banktransactions[.read]`, … — NOT a lexical
 *             refinement, so it needs the explicit map below (sourced from the
 *             comments in index.ts that introduced each granular set).
 *   REFINE    `accounting.reports.read` → `accounting.reports.<report>.read` —
 *             lexically derivable.
 *
 * The discriminator: an operation is unreachable iff no scope it declares is
 * satisfied, where a declared scope is satisfied if it is granted, if a granted
 * scope is a lexical refinement of it, or if a granted scope is a documented
 * rename of it. When an operation declares BOTH a coarse scope and its own
 * granular refinement, the refinement is authoritative — that is what separates
 * getReportTenNinetyNine (declares `accounting.reports.tenninetynine.read`,
 * ungranted → unreachable) from getReportBalanceSheet (declares only the coarse
 * scope, and `accounting.reports.balancesheet.read` IS granted → reachable).
 *
 * Deliberately conservative: where coverage cannot be established mechanically
 * it does NOT flag, because wrongly telling the model an endpoint is dead is
 * worse than staying silent.
 */
const RENAMED_FAMILIES: Record<string, string[]> = {
  "accounting.transactions": [
    "accounting.invoices", "accounting.payments",
    "accounting.banktransactions", "accounting.manualjournals",
  ],
  "accounting.transactions.read": [
    "accounting.invoices.read", "accounting.payments.read",
    "accounting.banktransactions.read", "accounting.manualjournals.read",
  ],
};

const familyOf = (scope: string): string => scope.replace(/\.read$/, "");
const isReadScope = (scope: string): boolean => scope.endsWith(".read");
/** `accounting.reports.balancesheet.read` refines `accounting.reports.read`. */
const refines = (granular: string, coarse: string): boolean =>
  familyOf(granular).startsWith(`${familyOf(coarse)}.`) &&
  isReadScope(granular) === isReadScope(coarse);

/** Scopes per operationId, from the bundled spec's per-op `security`. */
const scopesOf = new Map<string, string[]>();
for (const item of Object.values((specJson as { paths?: Record<string, Record<string, unknown>> }).paths ?? {})) {
  for (const op of Object.values(item)) {
    const o = op as { operationId?: unknown; security?: Array<Record<string, string[]>> };
    if (typeof o?.operationId !== "string") continue;
    const s = new Set<string>();
    for (const e of o.security ?? []) for (const v of Object.values(e)) for (const sc of v) s.add(sc);
    scopesOf.set(o.operationId, [...s]);
  }
}

const grantedScopes = new Set(xeroProvider.oauth.scopes);

function isReachable(declared: string[]): boolean {
  // A granular scope declared alongside the coarse family it refines is the
  // authoritative requirement. When one is present the coarse sibling must NOT
  // be consulted at all — otherwise a granted sibling refinement
  // (accounting.reports.balancesheet.read) would excuse an ungranted exact
  // requirement (accounting.reports.tenninetynine.read).
  const authoritative = declared.filter((s) => declared.some((o) => o !== s && refines(s, o)));
  if (authoritative.length > 0) return authoritative.some((s) => grantedScopes.has(s));

  for (const scope of declared) {
    if (grantedScopes.has(scope)) return true;
    if (RENAMED_FAMILIES[scope]?.some((r) => grantedScopes.has(r))) return true;
    // A granted refinement of a coarse family MAY cover this op; conservatively
    // treat that as reachable rather than risk a false "dead endpoint" claim.
    // NB `refines` requires matching read/write-ness, so a granted `.read`
    // never satisfies a declared write scope.
    for (const g of grantedScopes) if (refines(g, scope)) return true;
  }
  return false;
}

/** Derived, not hand-listed: a scope change or spec regeneration moves this. */
const derivedUnreachable = Object.entries(surfaceReview)
  .filter(([, e]) => e.decision !== "deny")
  .filter(([id]) => {
    const need = scopesOf.get(id) ?? [];
    return need.length > 0 && !isReachable(need);
  })
  .map(([id]) => id)
  .sort();

describe("xero surface review — clientNote on every inspected entry", () => {
  it("has an inspected surface to describe at all", () => {
    expect(inspected.length).toBeGreaterThan(0);
  });

  it("every entry with an inspector carries a clientNote", () => {
    const missing = inspected.filter(([, e]) => !e.clientNote?.trim()).map(([id]) => id);
    expect(missing).toEqual([]);
  });

  it("every un-inspected entry carrying a note is a genuine scope gap", () => {
    // `clientNote` covers any request-time condition deciding whether the call
    // succeeds, not just inspectors. Rather than exempting a hardcoded list,
    // require each such entry to actually have zero granted scopes — so a note
    // cannot be parked on an operation that works fine.
    const noted = Object.entries(surfaceReview)
      .filter(([, e]) => e.inspect === undefined && e.clientNote !== undefined)
      .map(([id]) => id);
    for (const id of noted) {
      expect(derivedUnreachable, `${id} carries a scope note but IS reachable`).toContain(id);
    }
  });

  it("no note claims a recipient allowlist — Xero has no such inspector", () => {
    for (const [id, entry] of inspected) {
      expect(entry.clientNote, id).not.toMatch(/allowlist/i);
    }
  });
});

describe("xero clientNote reaches the annotated spec", () => {
  const annotated = annotateSpecWithSurfaceReview(
    specJson as unknown as { paths?: Record<string, Record<string, unknown>> },
    surfaceReview,
  );

  const descriptionOf = (operationId: string): string => {
    for (const item of Object.values(annotated.paths ?? {})) {
      for (const op of Object.values(item)) {
        const o = op as { operationId?: unknown; description?: unknown };
        if (o?.operationId === operationId) return (o.description as string) ?? "";
      }
    }
    throw new Error(`no operation ${operationId}`);
  };

  it("carries each inspected entry's note onto its operation description", () => {
    for (const [id, entry] of inspected) {
      const d = descriptionOf(id);
      expect(d, id).toContain(SURFACE_REVIEW_MARKER);
      expect(d, id).toContain(entry.clientNote);
    }
  });

  it("EVERY entry with a clientNote has it reach the spec, inspector or not", () => {
    // A note that never reaches a description is pure cost: it looks like the
    // surface is documented while the client sees nothing.
    const unreached = Object.entries(surfaceReview)
      .filter(([, e]) => e.clientNote)
      .filter(([id, e]) => !descriptionOf(id).includes(e.clientNote as string))
      .map(([id]) => id);
    expect(unreached).toEqual([]);
  });

  it("never surfaces the reviewer-facing `reasoning` of any entry", () => {
    const whole = JSON.stringify(annotated);
    for (const [id, entry] of Object.entries(surfaceReview)) {
      if (!entry.reasoning) continue;
      expect(whole.includes(entry.reasoning), `${id} reasoning leaked`).toBe(false);
    }
  });
});

// 260 of Xero's 283 operations carry ONLY a `summary`, 19 carry both, and 4
// carry neither — so a description-only annotation is invisible to search code
// that reads `op.summary`. These assertions are against the real bundled spec,
// not a fixture.
describe("xero annotated spec — the ACCESS fact is reachable from either field", () => {
  // biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
  const annotated = annotateSpecWithSurfaceReview(specJson as any, surfaceReview) as any;

  interface Op { operationId: string; summary?: string; description?: string }
  const ops: Op[] = [];
  for (const item of Object.values(annotated.paths ?? {}) as Record<string, Op>[]) {
    for (const op of Object.values(item)) {
      if (op && typeof op.operationId === "string") ops.push(op);
    }
  }
  // biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
  const raw = specJson as any;
  const hadSummary = new Set<string>();
  for (const item of Object.values(raw.paths ?? {}) as Record<string, Op>[]) {
    for (const op of Object.values(item)) {
      if (op && typeof op.operationId === "string" && typeof op.summary === "string") {
        hadSummary.add(op.operationId);
      }
    }
  }

  /** True when this operation's state warrants any annotation at all: anything
   *  that is not a plain, unconditional, note-free allow. */
  const isAnnotated = (id: string): boolean => {
    const e = surfaceReview[id];
    return (
      !e || e.decision !== "allow" || e.inspect !== undefined || e.clientNote !== undefined
    );
  };

  it("the spec really is summary-dominant (the reason this exists)", () => {
    expect(ops.length).toBe(283);
    expect(hadSummary.size).toBe(279);
  });

  it("every annotated operation that HAS a summary carries the pointer", () => {
    const missing = ops
      .filter((o) => hadSummary.has(o.operationId) && isAnnotated(o.operationId))
      .filter((o) => !(o.summary ?? "").includes(SURFACE_REVIEW_SUMMARY_MARKER))
      .map((o) => o.operationId);
    expect(missing).toEqual([]);
  });

  it("every annotated operation carries the full text on its description", () => {
    const missing = ops
      .filter((o) => isAnnotated(o.operationId))
      .filter((o) => !(o.description ?? "").includes(SURFACE_REVIEW_MARKER))
      .map((o) => o.operationId);
    expect(missing).toEqual([]);
  });

  it("the 4 operations with neither field still end up annotated", () => {
    const neither = ops.filter((o) => !hadSummary.has(o.operationId));
    expect(neither).toHaveLength(4);
    for (const o of neither) {
      // All four are PUT/POST attachment operations, all unlisted in the
      // surface review, so all four are annotated as unavailable. The guard is
      // kept general: whatever their state, an annotated op must have a
      // description, since that is the only field they can carry one on.
      if (isAnnotated(o.operationId)) {
        expect(o.description ?? "", o.operationId).toContain(SURFACE_REVIEW_MARKER);
      }
    }
  });

  it("never invents a summary where the spec had none", () => {
    const invented = ops
      .filter((o) => !hadSummary.has(o.operationId) && typeof o.summary === "string")
      .map((o) => o.operationId);
    expect(invented).toEqual([]);
  });

  it("plain allows get neither a summary pointer nor a description block", () => {
    const plain = ops.filter((o) => !isAnnotated(o.operationId));
    expect(plain.length).toBeGreaterThan(0);
    for (const o of plain) {
      expect(o.summary ?? "", o.operationId).not.toContain(SURFACE_REVIEW_SUMMARY_MARKER);
      expect(o.description ?? "", o.operationId).not.toContain(SURFACE_REVIEW_MARKER);
    }
  });

  it("the summary pointer never carries the clientNote prose", () => {
    for (const [id, entry] of Object.entries(surfaceReview)) {
      if (!entry.clientNote) continue;
      const op = ops.find((o) => o.operationId === id);
      expect(op?.summary ?? "", id).not.toContain(entry.clientNote);
    }
  });
});

// A general spec-scope-vs-granted-scope audit is NOT sound for Xero: the
// bundled spec declares the deprecated coarse families (accounting.transactions,
// accounting.settings, …) while index.ts deliberately requests the granular
// replacements (accounting.invoices.read, accounting.banktransactions.read, …).
// Intersecting the two sets flags 83 of 182 entries, essentially all false
// positives, and no coarse→granular mapping table exists in this repo. So this
// pins the ONE case where the spec's scope string and the omitted scope string
// are identical, and therefore needs no mapping to establish.
describe("xero surface review — operations unreachable with the granted scopes", () => {
  it("the naive audit really is unusable (why the discriminator exists)", () => {
    const naive = Object.entries(surfaceReview)
      .filter(([, e]) => e.decision !== "deny")
      .filter(([id]) => {
        const need = scopesOf.get(id) ?? [];
        return need.length > 0 && !need.some((s) => grantedScopes.has(s));
      });
    // 83 vs 10: the discriminator removes 73 false positives while keeping
    // every genuine gap, which is the whole reason it exists.
    expect(naive.length).toBeGreaterThan(50);
    expect(derivedUnreachable.length).toBeLessThan(naive.length / 5);
  });

  it("derives exactly the unreachable set", () => {
    expect(derivedUnreachable).toEqual([
      "xero.accounting.getBrandingThemePaymentServices",
      "xero.accounting.getJournal",
      "xero.accounting.getJournalByNumber",
      "xero.accounting.getJournals",
      "xero.accounting.getPaymentServices",
      "xero.accounting.getReportTenNinetyNine",
      // Payroll WRITE scopes are not requested — only the `.read` halves are.
      // All four are elicit-gated, so without a note the client is told to seek
      // approval for a call the token could never make.
      "xero.payroll.au.createEmployee",
      "xero.payroll.au.createPayRun",
      "xero.payroll.au.updateEmployee",
      "xero.payroll.au.updatePayRun",
    ]);
  });

  it("EVERY derived-unreachable operation carries a note naming its scope", () => {
    for (const id of derivedUnreachable) {
      const note = surfaceReview[id]?.clientNote ?? "";
      expect(note, id).toMatch(/unreachable as deployed/i);
      const need = scopesOf.get(id) ?? [];
      expect(need.some((s) => note.includes(s)), `${id} names no required scope`).toBe(true);
    }
  });

  it("does NOT flag a report whose granular scope IS granted", () => {
    // The discriminator's discriminating case: same coarse scope as the 1099
    // report, opposite verdict, decided only by the granular replacement.
    for (const id of ["xero.accounting.getReportBalanceSheet", "xero.accounting.getReportProfitAndLoss"]) {
      expect(scopesOf.get(id), id).toContain("accounting.reports.read");
      expect(derivedUnreachable, id).not.toContain(id);
      expect(surfaceReview[id]?.clientNote, id).toBeUndefined();
    }
    expect(grantedScopes.has("accounting.reports.balancesheet.read")).toBe(true);
  });

  it("a granted .read scope never satisfies a declared WRITE scope", () => {
    // How the payroll writes surface: payroll.employees.read is granted,
    // payroll.employees (write) is not, and read must not excuse write.
    expect(grantedScopes.has("payroll.employees.read")).toBe(true);
    expect(grantedScopes.has("payroll.employees")).toBe(false);
    expect(derivedUnreachable).toContain("xero.payroll.au.createEmployee");
  });

  it("does NOT flag ops covered by a RENAMED family", () => {
    // getBankTransactions declares only the deprecated accounting.transactions
    // family; accounting.banktransactions.read is granted in its place.
    expect(scopesOf.get("xero.accounting.getBankTransactions")).toContain("accounting.transactions.read");
    expect(derivedUnreachable).not.toContain("xero.accounting.getBankTransactions");
  });

  it("the paymentservices reads are not the usable half of a denied pair", () => {
    expect(surfaceReview["xero.accounting.createPaymentService"]?.decision).toBe("deny");
    expect(surfaceReview["xero.accounting.createBrandingThemePaymentServices"]?.decision).toBe("deny");
    for (const id of ["xero.accounting.getPaymentServices", "xero.accounting.getBrandingThemePaymentServices"]) {
      expect(surfaceReview[id]?.clientNote, id).toMatch(/write side is denied/i);
    }
  });
});
