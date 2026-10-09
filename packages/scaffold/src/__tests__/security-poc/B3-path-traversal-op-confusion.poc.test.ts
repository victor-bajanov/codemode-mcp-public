// B3 — Operation confusion via WHATWG URL path normalisation.
//
// resolveOperation (path-matcher.ts) matches the RAW path string segment by
// segment, where a `{param}` segment accepts ANY non-empty string. The outbound
// URL is then built with `new URL(path, base)` (build-upstream-url.ts), and the
// WHATWG parser rewrites the path before it is sent:
//   • `\` is treated as `/` for special schemes (https)   → "a\b" is TWO segments
//   • `..` / `%2e%2e` / `.%2e` / `%2e.` erase the preceding segment
//   • `.` / `%2e` are dropped
// So a request whose RAW path resolves to an ALLOWED operation can reach the
// wire as a DIFFERENT path — one that belongs to a denied / elicit / inspected
// operation of the same HTTP method. Surface review, the inspector and the
// elicit dialog all run against the allowed operation; the upstream executes
// the gated one. Origin invariance is NOT violated (same host), so the
// `upstream-url-origin-mismatch` guard never fires.
//
// Preconditions: an allowed operation whose template ENDS in a `{param}` (or
// whose literal suffix matches the target's suffix) with the same method as
// the target. Both real provider specs have many.
//
// Status: FIXED (F-1) — the matcher refuses `\`, `.`/`..` and their encoded
// forms, the wire path is built from the matched template, and the built URL
// must re-resolve to the same operation.
//
// Fix (2026-10-08): `matchOperation` (path-matcher.ts) refuses any unsafe
// segment, so every candidate raw path below now resolves to `null`; the
// handler denies it up front with a `url_safety` / `unsafe-path-segment` audit
// line before review, inspection, elicitation or token minting. The original
// payloads are kept as regression inputs.
import { describe, it, expect, vi, afterEach } from "vitest";
import { resolveOperation } from "../../path-matcher";
import { buildUpstreamUrl } from "../../build-upstream-url";
import { handleUpstreamRequest } from "../../request-handler";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";
import { gmailProvider } from "../../../../providers/gmail/src/index";
import { xeroProvider } from "../../../../providers/xero/src/index";
import { opticalProvider } from "../../../../providers/optical/src/index";

interface Hit {
  method: string;
  allowedOp: string;
  rawPath: string;
  wirePath: string;
  targetOp: string;
  targetGate: string;
}

function gateOf(sr: SurfaceReview, opId: string): string | null {
  const e = sr[opId];
  if (!e) return "unlisted(deny)";
  if (e.decision === "deny") return "deny";
  if (e.decision === "elicit") return e.inspect ? "elicit+inspect" : "elicit";
  if (e.inspect) return "allow+inspect";
  return null; // plain allow — not a gate
}

/** Enumerate (allowed → gated) pairs reachable through a backslash/dot-segment
 *  param value. Every candidate is VERIFIED against the real matcher and the
 *  real URL builder, so a hit is a demonstrated confusion, not a projection.
 *  `refused` counts candidates the matcher now rejects outright (F-1). */
function enumerate(spec: OpenApiSpec, sr: SurfaceReview, base: string): { hits: Hit[]; refused: number } {
  const hits: Hit[] = [];
  let refused = 0;
  type Tmpl = { segs: string[]; method: string; opId: string };
  const tmpls: Tmpl[] = [];
  for (const [tmpl, methods] of Object.entries(spec.paths)) {
    const segs = tmpl.split("/").filter((s) => s.length > 0);
    for (const [m, op] of Object.entries(methods as Record<string, { operationId?: string }>)) {
      if (!op || typeof op !== "object" || !op.operationId) continue;
      tmpls.push({ segs, method: m.toUpperCase(), opId: op.operationId });
    }
  }
  const isParam = (s: string) => /^\{.+\}$/.test(s);
  for (const a of tmpls) {
    if (gateOf(sr, a.opId) !== null) continue; // only plain-allow sources
    for (let i = 0; i < a.segs.length; i++) {
      if (!isParam(a.segs[i]!)) continue;
      const suffixA = a.segs.slice(i + 1);
      for (const t of tmpls) {
        if (t.method !== a.method || t.opId === a.opId) continue;
        const gate = gateOf(sr, t.opId);
        if (gate === null) continue;
        if (t.segs.length < suffixA.length) continue;
        // Instantiate the target's segments. Where the target has a param in a
        // position covered by A's literal suffix, use A's literal as the value.
        const tInst = t.segs.map((s) => (isParam(s) ? "X" : s));
        const tailStart = t.segs.length - suffixA.length;
        let ok = true;
        for (let k = 0; k < suffixA.length; k++) {
          const aSeg = suffixA[k]!;
          const tSeg = t.segs[tailStart + k]!;
          if (isParam(aSeg)) {
            // A's trailing param: any value — pick the target's own value
            continue;
          }
          if (isParam(tSeg)) { tInst[tailStart + k] = aSeg; continue; }
          if (tSeg !== aSeg) { ok = false; break; }
        }
        if (!ok) continue;
        const prefixT = tInst.slice(0, tailStart);
        // Erase the i preceding segments of A with `..`, then spell the
        // target's prefix with backslashes so the raw path stays ONE segment.
        const paramValue = Array(i).fill("..").concat(prefixT).join("\\");
        if (paramValue.length === 0) continue;
        const rawSegs = a.segs.map((s, idx) =>
          idx === i ? paramValue : isParam(s) ? tInst[tailStart + (idx - i - 1)] ?? "X" : s,
        );
        const rawPath = "/" + rawSegs.join("/");
        const resolvedA = resolveOperation(spec, a.method, rawPath);
        if (!resolvedA) { refused++; continue; }
        if (resolvedA.operationId !== a.opId) continue;
        let wirePath: string;
        try {
          wirePath = new URL(buildUpstreamUrl(base, rawPath)).pathname;
        } catch {
          continue;
        }
        const resolvedT = resolveOperation(spec, a.method, wirePath);
        if (!resolvedT || resolvedT.operationId !== t.opId) continue;
        hits.push({ method: a.method, allowedOp: a.opId, rawPath, wirePath, targetOp: t.opId, targetGate: gate });
      }
    }
  }
  return { hits, refused };
}

function summarise(hits: Hit[]): string {
  const byTarget = new Map<string, Hit>();
  for (const h of hits) if (!byTarget.has(h.targetOp)) byTarget.set(h.targetOp, h);
  return [...byTarget.values()]
    .map((h) => `  ${h.method} ${h.allowedOp}  ->  ${h.targetOp} [${h.targetGate}]\n      raw:  ${h.rawPath}\n      wire: ${h.wirePath}`)
    .join("\n");
}

describe("B3 — path traversal operation confusion (FIXED F-1)", () => {
  it("FIXED (F-1): Gmail+Calendar: no plain-allow op reaches a gated op — every candidate path is refused", () => {
    const { hits, refused } = enumerate(gmailProvider.spec, gmailProvider.surfaceReview, gmailProvider.apiBaseUrl);
    const targets = new Set(hits.map((h) => h.targetOp));
    // eslint-disable-next-line no-console
    console.log(`[B3] gmail: ${hits.length} confusions, ${targets.size} distinct gated targets, ${refused} candidates refused\n${summarise(hits)}`);
    expect(hits.length).toBe(0);
    // Not vacuous: the enumeration still generates the attack candidates
    // (labels.delete → messages.delete, labels.patch → sendAs.patch, …).
    expect(refused).toBeGreaterThan(0);
  });

  it("FIXED (F-1): Xero: no plain-allow op reaches a gated op — every candidate path is refused", () => {
    const { hits, refused } = enumerate(xeroProvider.spec, xeroProvider.surfaceReview, xeroProvider.apiBaseUrl);
    const targets = new Set(hits.map((h) => h.targetOp));
    // eslint-disable-next-line no-console
    console.log(`[B3] xero: ${hits.length} confusions, ${targets.size} distinct gated targets, ${refused} candidates refused\n${summarise(hits)}`);
    expect(hits.length).toBe(0);
    expect(refused).toBeGreaterThan(0);
  });

  it("FIXED (F-1): Optical: enumerated for completeness — no confusions", () => {
    const { hits, refused } = enumerate(opticalProvider.spec, opticalProvider.surfaceReview, opticalProvider.apiBaseUrl);
    // eslint-disable-next-line no-console
    console.log(`[B3] optical: ${hits.length} confusions, ${refused} candidates refused\n${summarise(hits)}`);
    // Optical has very few gated ops (two denies, both POST with literal
    // tails), so the candidate count may itself be zero.
    expect(hits.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// End-to-end through the real request handler with the real Gmail surface
// review. Before the fix: no elicitation ran, no inspector ran, the audit line
// recorded the ALLOWED operationId, and the bytes on the wire hit the gated
// endpoint. Now: refused before any fetch, with a url_safety audit line.
// ---------------------------------------------------------------------------
function fakeBroker() {
  return { async getOrRefreshAccessToken() { return "AT-secret"; } };
}
function captureAudit() {
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  return () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
}

function expectRefused(fetchSpy: ReturnType<typeof vi.fn>, audit: () => Record<string, unknown>[]): void {
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(audit().at(-1)).toMatchObject({ decision: "deny", category: "url_safety", reason: "unsafe-path-segment" });
}

describe("B3 — end to end through handleUpstreamRequest (FIXED F-1)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  function argsFor(method: string, path: string, body?: unknown) {
    return {
      ctx: { method, path, ...(body !== undefined ? { body } : {}) },
      spec: gmailProvider.spec,
      surfaceReview: gmailProvider.surfaceReview,
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "poc",
      props: { userId: "u1", refreshToken: "RT" },
      // A server with NO elicitation capability: if elicit were reached the
      // handler would throw "requires user approval; outcome: unsupported".
      server: { server: { getClientCapabilities: () => ({}) } } as never,
      oauth: {
        refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
        userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
        broker: fakeBroker(),
      },
      audit: {},
      env: { OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com" },
    };
  }

  it("FIXED (F-1): labels.delete (allow) can no longer reach messages.delete (elicit)", async () => {
    const fetchSpy = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    await expect(
      handleUpstreamRequest(argsFor("DELETE", "/gmail/v1/users/me/labels/..\\messages\\18c0ffee") as never),
    ).rejects.toThrow(/disallowed segment/);
    expectRefused(fetchSpy, audit);
  });

  it("FIXED (F-1): labels.patch (allow) can no longer patch a calendar event past the attendee inspector", async () => {
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);
    const inspect = vi.spyOn(gmailProvider.surfaceReview["calendar.events.patch"]!, "inspect");
    const audit = captureAudit();
    const body = { attendees: [{ email: "attacker@evil.invalid" }] };
    await expect(
      handleUpstreamRequest(
        argsFor("PATCH", "/gmail/v1/users/me/labels/..\\..\\..\\..\\..\\calendar\\v3\\calendars\\primary\\events\\evt1", body) as never,
      ),
    ).rejects.toThrow(/disallowed segment/);
    expectRefused(fetchSpy, audit);
    expect(inspect).not.toHaveBeenCalled();
  });

  it("FIXED (F-1): labels.patch (allow) can no longer reach sendAs.patch (statically DENIED)", async () => {
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    await expect(
      handleUpstreamRequest(
        argsFor("PATCH", "/gmail/v1/users/me/labels/..\\settings\\sendAs\\victim@example.com", { displayName: "CEO", replyToAddress: "attacker@evil.invalid" }) as never,
      ),
    ).rejects.toThrow(/disallowed segment/);
    expectRefused(fetchSpy, audit);
  });

  it("origin invariance still holds (the guard is not the problem)", () => {
    for (const p of ["//evil.invalid/x", "/\\\\evil.invalid/x", "https://evil.invalid/x", "/\\/evil.invalid/x"]) {
      expect(() => buildUpstreamUrl("https://www.googleapis.com", p)).toThrow(/upstream-url-origin-mismatch/);
    }
  });
});
