// Security-review POC C1 — path normalisation after operation matching.
//
// `resolveOperation` (path-matcher.ts) matches the sandbox-supplied `path`
// against the spec on RAW `/`-split segments: any non-empty segment satisfies a
// `{param}` slot, including `.`, `..`, `%2e` and `%2e%2e`. `buildUpstreamUrl`
// then runs `new URL(path, base)`, and the WHATWG URL parser removes dot
// segments (percent-encoded forms included) BEFORE the request leaves the host.
// The surface review is therefore consulted for the operation the RAW path
// matched, while the upstream receives the NORMALISED path.
//
// This POC enumerates every allow-decision (method, template) in the three
// bundled provider specs, substitutes dot-segment values into every param slot
// (singly and in combination), builds the outbound URL with the real helper and
// re-resolves the normalised path (trailing slash stripped) against the spec.
//
// Status: FIXED (F-1) — `.`/`..` and their percent-encoded forms are refused
// by the matcher, so no candidate below reaches the URL builder any more.
//
// Fix (2026-10-08): `matchOperation` (path-matcher.ts) rejects dot-only
// segments (raw or decoded), the wire path is rebuilt from the matched
// template, `buildUpstreamUrl` refuses any path the parser would rewrite
// (`upstream-url-path-mismatch`), and the handler re-resolves the built URL and
// requires the same operation. The enumeration and concrete payloads are kept
// as regression inputs.
//
// Observed before the fix on the committed specs/reviews:
//   gmail   — PUT/PATCH calendar.events.update/patch with eventId ".." sends
//             `/calendar/v3/calendars/<id>/`, i.e. calendars.update/patch,
//             which are NOT in the surface review (implicit deny). Google
//             serves that trailing-slash route (unauthenticated probe: 401,
//             versus 404 for an unknown path).
//   xero    — PUT/POST *AttachmentByFileName (plain allow, no inspector) with
//             "." / ".." in the two param slots sends `/api.xro/2.0/Invoices/`
//             or `/api.xro/2.0/CreditNotes/` (bulk create/update, gated by the
//             draft-status inspector) or `/api.xro/2.0/Invoices/<id>/`
//             (updateInvoice, same gate); updateBankTransaction with ".." sends
//             `/api.xro/2.0/BankTransactions/` (not in review). Whether Xero
//             routes a trailing-slash URL could not be verified unauthenticated.
//   optical — no stricter-op hit.
// Recommendation (implemented): reject `.`/`..` and their percent-encoded
// forms (and any segment that `new URL` would rewrite) in `resolveOperation`,
// and assert post-build that `url.pathname === ctx.path`.
import { describe, it, expect } from "vitest";
import { resolveOperation } from "../../path-matcher";
import { buildUpstreamUrl } from "../../build-upstream-url";
import { gmailProvider } from "../../../../providers/gmail/src/index";
import { xeroProvider } from "../../../../providers/xero/src/index";
import { opticalProvider } from "../../../../providers/optical/src/index";
import type { ApiProvider } from "../../api-provider";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";

const RANK: Record<string, number> = { allow: 0, elicit: 1, deny: 2 };
const DOT_VALUES = [".", "..", "%2e", "%2e%2e", "%2E%2E", ".%2e"];

interface Hit {
  provider: string;
  method: string;
  template: string;
  fromOp: string;
  sentPath: string;
  toOp: string | null;
  toDecision: string;
  trailingSlashStripped: boolean;
}

function classify(review: ApiProvider["surfaceReview"], opId: string | undefined): string {
  if (!opId) return "deny(not-in-review)";
  const e = review[opId];
  if (!e) return "deny(not-in-review)";
  if (e.decision === "allow" && e.inspect) return "allow+inspect";
  return e.decision;
}

function rankOf(c: string): number {
  if (c.startsWith("deny")) return RANK.deny!;
  if (c === "allow+inspect") return 0.5;
  return RANK[c] ?? 2;
}

function* assignments(nParams: number): Generator<string[]> {
  // Each param slot: a literal placeholder OR one of the dot values.
  const choices = ["LIT", ...DOT_VALUES];
  const idx = new Array(nParams).fill(0);
  while (true) {
    const a = idx.map((i) => choices[i]!);
    if (a.some((v) => v !== "LIT")) yield a;
    let k = nParams - 1;
    while (k >= 0) {
      idx[k]++;
      if (idx[k] < choices.length) break;
      idx[k] = 0;
      k--;
    }
    if (k < 0) return;
  }
}

function enumerate(provider: ApiProvider): { hits: Hit[]; divergent: Hit[]; checked: number; refused: number } {
  const spec = provider.spec as unknown as OpenApiSpec;
  const review = provider.surfaceReview;
  const hits: Hit[] = [];
  const divergent: Hit[] = [];
  let checked = 0;
  let refused = 0; // candidates the matcher rejects outright (F-1): not divergent
  for (const [template, methods] of Object.entries(spec.paths)) {
    for (const [m, op] of Object.entries(methods as Record<string, { operationId?: string }>)) {
      const method = m.toUpperCase();
      const opId = op.operationId;
      if (!opId) continue;
      const entry = review[opId];
      if (!entry || entry.decision !== "allow") continue; // only ops the sandbox may call
      const fromClass = classify(review, opId);
      const segs = template.split("/").filter((s) => s.length > 0);
      const paramIdx = segs.map((s, i) => (/^\{.+\}$/.test(s) ? i : -1)).filter((i) => i >= 0);
      if (paramIdx.length === 0) continue;
      for (const a of assignments(paramIdx.length)) {
        const out = [...segs];
        paramIdx.forEach((pi, j) => {
          out[pi] = a[j] === "LIT" ? "x1" : a[j]!;
        });
        const path = "/" + out.join("/");
        checked++;
        const matched = resolveOperation(spec, method, path);
        if (!matched) { refused++; continue; }                  // refused: never sent
        if (matched.operationId !== opId) continue;             // matcher chose another op
        let sent: string;
        try {
          sent = new URL(buildUpstreamUrl(provider.apiBaseUrl, path)).pathname;
        } catch {
          continue;
        }
        if (sent === path) continue;
        let stripped = false;
        let probe = sent;
        if (probe.endsWith("/") && probe.length > 1) {
          probe = probe.slice(0, -1);
          stripped = true;
        }
        const toOp = resolveOperation(spec, method, probe);
        const toClass = classify(review, toOp?.operationId);
        const hit: Hit = {
          provider: provider.name,
          method,
          template,
          fromOp: opId,
          sentPath: sent,
          toOp: toOp?.operationId ?? null,
          toDecision: toClass,
          trailingSlashStripped: stripped,
        };
        divergent.push(hit);
        if (toOp && toOp.operationId !== opId && rankOf(toClass) > rankOf(fromClass)) hits.push(hit);
        if (!toOp && stripped === false) {
          // Normalised path resolves to nothing in the spec: not a known op, so
          // not a surface-review hit, but the upstream still receives it.
        }
      }
    }
  }
  return { hits, divergent, checked, refused };
}

describe("C1 dot-segment normalisation after operation match (FIXED F-1)", () => {
  for (const provider of [gmailProvider, xeroProvider, opticalProvider] as ApiProvider[]) {
    it(`FIXED (F-1): ${provider.name}: every allow-template candidate with dot segments in param slots is refused`, () => {
      const { hits, divergent, checked, refused } = enumerate(provider);
      // Make the evidence visible in the run output.
      console.log(
        `[C1] ${provider.name}: checked=${checked} refused=${refused} divergent(sent≠matched)=${divergent.length} ` +
          `stricter-op-hits=${hits.length}`,
      );
      for (const h of hits) console.log("[C1 HIT]", JSON.stringify(h));
      const sample = divergent.slice(0, 3);
      for (const d of sample) console.log("[C1 divergent sample]", JSON.stringify(d));

      // FIXED: the matcher refuses every dot-segment candidate, so nothing is
      // sent on a path that differs from the one the review classified.
      // (Before: gmail hit calendar.calendars.patch/update; xero hit the bulk
      // Invoices/CreditNotes/BankTransactions endpoints.)
      expect(checked).toBeGreaterThan(0);
      expect(refused).toBe(checked);
      expect(divergent).toHaveLength(0);
      expect(hits).toHaveLength(0);
    });
  }

  const PATH_MISMATCH = /^upstream-url-path-mismatch:/;

  it("FIXED (F-1): concrete xero example: attachment PUT with '.'/'..' is refused, not sent to the bulk Invoices endpoint", () => {
    const spec = xeroProvider.spec as unknown as OpenApiSpec;
    const path = "/api.xro/2.0/Invoices/./Attachments/..";
    expect(resolveOperation(spec, "PUT", path)).toBeNull();
    // A well-formed attachment path still resolves to the (uninspected) op.
    const ok = resolveOperation(spec, "PUT", "/api.xro/2.0/Invoices/inv-1/Attachments/a.pdf");
    expect(ok?.operationId).toBe("xero.accounting.createInvoiceAttachmentByFileName");
    expect(xeroProvider.surfaceReview[ok!.operationId!]?.inspect).toBeUndefined();
    expect(() => buildUpstreamUrl(xeroProvider.apiBaseUrl, path)).toThrow(PATH_MISMATCH);
  });

  it("FIXED (F-1): concrete gmail example: events.patch with eventId '..' is refused, not sent to the calendars resource", () => {
    const spec = gmailProvider.spec as unknown as OpenApiSpec;
    const path = "/calendar/v3/calendars/primary/events/..";
    expect(resolveOperation(spec, "PATCH", path)).toBeNull();
    expect(() => buildUpstreamUrl(gmailProvider.apiBaseUrl, path)).toThrow(PATH_MISMATCH);
    expect(gmailProvider.surfaceReview["calendar.calendars.patch"]).toBeUndefined();
  });

  it("FIXED (F-1): concrete example: messages.get with id='..' is refused, not sent as the parent collection URL", () => {
    const spec = gmailProvider.spec as unknown as OpenApiSpec;
    const path = "/gmail/v1/users/me/messages/..";
    expect(resolveOperation(spec, "GET", path)).toBeNull();
    expect(() => buildUpstreamUrl(gmailProvider.apiBaseUrl, path, { format: "full" })).toThrow(PATH_MISMATCH);
  });

  it("FIXED (F-1): percent-encoded dot segments are refused the same way", () => {
    const spec = gmailProvider.spec as unknown as OpenApiSpec;
    for (const seg of ["%2e%2e", "%2E%2E", ".%2e", "%2e.", "%2e"]) {
      const path = `/gmail/v1/users/me/messages/${seg}`;
      expect(resolveOperation(spec, "GET", path), seg).toBeNull();
      expect(() => buildUpstreamUrl(gmailProvider.apiBaseUrl, path), seg).toThrow(PATH_MISMATCH);
    }
  });
});
