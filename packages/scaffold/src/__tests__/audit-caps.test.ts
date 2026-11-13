import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUDIT_CATEGORY_MAX,
  AUDIT_METHOD_MAX,
  AUDIT_OPERATION_ID_MAX,
  AUDIT_PATH_MAX,
  AUDIT_REASON_MAX,
  auditLog,
  capAuditEntry,
  createAuditSink,
  redactAuditEntry,
  type AuditEntry,
  type AuditSink,
} from "../audit";

/**
 * B-2 (audit sink caps) and the wave-4 sink contract.
 *
 * Attacker: sandbox code calling `codemode.request` (it controls `method`
 * and `path`, and through them the audit line's size).
 * Precondition: any deployment; every refusal writes one `AUDIT` line.
 * Payload: `GET /AAAA…(300 000)` or `method: "M".repeat(200000)` with a
 * malformed `contentType: 42` — each denied, each echoed verbatim into its
 * audit line (> 200 KB per line), so a handful of calls exhausts the
 * platform's per-invocation log budget and pushes later lines out.
 * Control: the one sink (`auditLog`) caps `method` (32), `path` (1024, plus
 * `pathLength` with the true length), `reason` (128), `category` (64) and
 * `operationId` (256) code points; a cut value ends in `…`. Pre-fix,
 * `auditLog` was `console.log("AUDIT " + JSON.stringify(entry))` with no cap.
 *
 * Also pinned: `createAuditSink` fills `deployment`/`ts`, defaults
 * `principalId`/`context` (the entry's own values win) and writes through
 * `waitUntil` when given; and a typical wave-3 line serialises
 * byte-identically.
 */

function cp(s: string): number {
  return Array.from(s).length;
}

describe("audit sink caps (B-2)", () => {
  let lines: string[];
  beforeEach(() => {
    lines = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(String(args[0]));
    });
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function parsed(i = 0): AuditEntry {
    const l = lines[i]!;
    expect(l.startsWith("AUDIT ")).toBe(true);
    return JSON.parse(l.slice("AUDIT ".length)) as AuditEntry;
  }

  it("exports the §3.2 caps", () => {
    expect(AUDIT_METHOD_MAX).toBe(32);
    expect(AUDIT_PATH_MAX).toBe(1024);
    expect(AUDIT_REASON_MAX).toBe(128);
    expect(AUDIT_CATEGORY_MAX).toBe(64);
    expect(AUDIT_OPERATION_ID_MAX).toBe(256);
  });

  it("FIXED (B-2): a direct auditLog with a 300 KB path is capped by the sink", () => {
    const path = "/" + "A".repeat(300_000);
    auditLog({
      deployment: "gmail",
      method: "GET",
      path,
      decision: "deny",
      category: "malformed",
      reason: "no-op-match",
      ts: "2026-11-11T00:00:00.000Z",
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]!.length).toBeLessThan(2048);
    expect(lines[0]).not.toContain("A".repeat(1025));
    const e = parsed();
    expect(cp(e.path)).toBe(AUDIT_PATH_MAX);
    expect(e.path.endsWith("…")).toBe(true);
    expect(e.path.startsWith("/AAA")).toBe(true);
    expect(e.pathLength).toBe(300_001);
    expect(e.reason).toBe("no-op-match");
  });

  it("FIXED (B-2): a 200 000-char method is cut to 32 code points; the invalid-content-type reason survives", () => {
    auditLog({
      deployment: "gmail",
      method: "M".repeat(200_000),
      path: "/gmail/v1/users/me/messages",
      decision: "deny",
      category: "malformed",
      reason: "invalid-content-type",
      ts: "2026-11-11T00:00:00.000Z",
    });
    expect(lines[0]!.length).toBeLessThan(2048);
    const e = parsed();
    expect(cp(e.method)).toBe(AUDIT_METHOD_MAX);
    expect(e.method).toBe("M".repeat(AUDIT_METHOD_MAX - 1) + "…");
    expect(e.reason).toBe("invalid-content-type");
    expect(e.path).toBe("/gmail/v1/users/me/messages");
    expect(e.pathLength).toBeUndefined();
  });

  it("caps reason, category and operationId", () => {
    const e = capAuditEntry({
      deployment: "d",
      method: "GET",
      path: "/p",
      decision: "deny",
      reason: "r".repeat(500),
      category: "c".repeat(500),
      operationId: "o".repeat(5000),
      ts: "t",
    });
    expect(e.reason).toBe("r".repeat(AUDIT_REASON_MAX - 1) + "…");
    expect(e.category).toBe("c".repeat(AUDIT_CATEGORY_MAX - 1) + "…");
    expect(e.operationId).toBe("o".repeat(AUDIT_OPERATION_ID_MAX - 1) + "…");
    expect(e.pathLength).toBeUndefined();
  });

  it("counts code points, not UTF-16 units, and never splits a surrogate pair", () => {
    // 1024 astral chars = 2048 UTF-16 units: exactly at the cap, not cut.
    const atCap = "😀".repeat(AUDIT_PATH_MAX);
    const kept = capAuditEntry({ deployment: "d", method: "GET", path: atCap, decision: "deny", ts: "t" });
    expect(kept.path).toBe(atCap);
    expect(kept.pathLength).toBeUndefined();

    const over = "😀".repeat(AUDIT_PATH_MAX + 1);
    const cut = capAuditEntry({ deployment: "d", method: "GET", path: over, decision: "deny", ts: "t" });
    expect(cut.path).toBe("😀".repeat(AUDIT_PATH_MAX - 1) + "…");
    expect(cut.pathLength).toBe(AUDIT_PATH_MAX + 1);
    expect(cut.path).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
  });

  it("is pure: the input entry is not mutated and values at the cap pass through", () => {
    const input: AuditEntry = {
      deployment: "d",
      method: "X".repeat(AUDIT_METHOD_MAX),
      path: "/" + "p".repeat(AUDIT_PATH_MAX + 10),
      decision: "deny",
      ts: "t",
    };
    const snapshot = JSON.stringify(input);
    const out = capAuditEntry(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(out).not.toBe(input);
    expect(out.method).toBe(input.method);
  });

  it("FIXED (B-2): U+2028/U+2029 in a sandbox-controlled path are escaped, so no fake AUDIT continuation renders", () => {
    auditLog({
      deployment: "gmail",
      method: "GET",
      path: '/x\u2028AUDIT {"decision":"allow"}\u2029AUDIT {"decision":"allow"}',
      decision: "deny",
      category: "malformed",
      reason: "no-op-match",
      ts: "2026-11-11T00:00:00.000Z",
    });
    expect(lines).toHaveLength(1);
    const l = lines[0]!;
    expect(l).not.toMatch(/[\u2028\u2029]/);
    expect(l).toContain("\\u2028");
    expect(l).toContain("\\u2029");
    // Still valid JSON that round-trips to the original path.
    expect(parsed().path).toBe('/x\u2028AUDIT {"decision":"allow"}\u2029AUDIT {"decision":"allow"}');
  });

  it("REFUTED: a typical wave-3 line serialises byte-identically", () => {
    const entry = redactAuditEntry({
      deployment: "gmail",
      operationId: "gmail.users.messages.send",
      method: "POST",
      path: "/gmail/v1/users/me/messages/send",
      decision: "elicit",
      elicitationOutcome: "accepted",
      elicitFields: { to: "a@example.com", subject: "hi" },
      category: "external_data_flow",
      reason: "mass-send",
      queryKeys: ["alt", "fields"],
      queryKeyCount: 2,
      upstreamStatus: 200,
      principalId: "user-abc",
      context: { tenantId: "tenant-xyz" },
      ts: "2026-11-11T00:00:00.000Z",
    });
    auditLog(entry);
    // Literal of the pre-wave-4 serialisation (`"AUDIT " + JSON.stringify(entry)`).
    expect(lines[0]).toBe(
      'AUDIT {"deployment":"gmail","operationId":"gmail.users.messages.send","method":"POST",' +
        '"path":"/gmail/v1/users/me/messages/send","decision":"elicit","elicitationOutcome":"accepted",' +
        '"elicitFields":{"__redacted__":true,"keys":["to","subject"],"toLength":13,"subjectLength":2},' +
        '"category":"external_data_flow","reason":"mass-send","queryKeys":["alt","fields"],' +
        '"queryKeyCount":2,"upstreamStatus":200,"principalId":"user-abc",' +
        '"context":{"tenantId":"tenant-xyz"},"ts":"2026-11-11T00:00:00.000Z"}',
    );
    expect(lines[0]).toBe("AUDIT " + JSON.stringify(entry));
  });
});

describe("createAuditSink (sink defaults)", () => {
  let lines: string[];
  beforeEach(() => {
    lines = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(String(args[0]));
    });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const parse = (l: string) => JSON.parse(l.slice("AUDIT ".length)) as AuditEntry;

  it("fills deployment, ts, principalId and context", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-11T12:34:56.789Z"));
    const sink: AuditSink = createAuditSink({
      deployment: "gmail",
      principalId: "u1",
      context: { tenantId: "t1" },
    });
    sink({
      operationId: "staging.store",
      method: "HOST",
      path: "putFile",
      decision: "allow",
      staging: { event: "store", fileRef: "0123456789ab", byteLength: 5, status: 200 },
    });
    expect(lines).toHaveLength(1);
    const e = parse(lines[0]!);
    expect(e.deployment).toBe("gmail");
    expect(e.ts).toBe("2026-11-11T12:34:56.789Z");
    expect(e.principalId).toBe("u1");
    expect(e.context).toEqual({ tenantId: "t1" });
    expect(e.staging).toEqual({ event: "store", fileRef: "0123456789ab", byteLength: 5, status: 200 });
  });

  it("an entry's own principalId and context win over the defaults", () => {
    const sink = createAuditSink({ deployment: "d", principalId: "u1", context: { a: "1" } });
    sink({ method: "GET", path: "/x", decision: "deny", principalId: "u2", context: { b: "2" } });
    const e = parse(lines[0]!);
    expect(e.principalId).toBe("u2");
    expect(e.context).toEqual({ b: "2" });
  });

  it("omits principalId/context when neither the sink nor the entry has them", () => {
    const sink = createAuditSink({ deployment: "d" });
    sink({ method: "GET", path: "/x", decision: "deny" });
    const e = parse(lines[0]!);
    expect("principalId" in e).toBe(false);
    expect("context" in e).toBe(false);
  });

  it("writes through waitUntil when given, and the line is capped", async () => {
    const pending: Promise<unknown>[] = [];
    const waitUntil = vi.fn((p: Promise<unknown>) => {
      pending.push(p);
    });
    const sink = createAuditSink({ deployment: "d", waitUntil });
    sink({ method: "GET", path: "/" + "A".repeat(5000), decision: "deny", reason: "no-op-match" });
    expect(waitUntil).toHaveBeenCalledTimes(1);
    await Promise.all(pending);
    expect(lines).toHaveLength(1);
    const e = parse(lines[0]!);
    expect(cp(e.path)).toBe(AUDIT_PATH_MAX);
    expect(e.pathLength).toBe(5001);
  });

  it("writes synchronously without waitUntil", () => {
    const sink = createAuditSink({ deployment: "d" });
    sink({ method: "GET", path: "/x", decision: "allow", phase: "dispatch", stagedRefs: ["0123456789ab"] });
    expect(lines).toHaveLength(1);
    const e = parse(lines[0]!);
    expect(e.phase).toBe("dispatch");
    expect(e.stagedRefs).toEqual(["0123456789ab"]);
  });

  it("carries outcome: failed", () => {
    const sink = createAuditSink({ deployment: "d" });
    sink({ method: "POST", path: "/x", decision: "allow", outcome: "failed", reason: "upstream-request-failed" });
    expect(parse(lines[0]!).outcome).toBe("failed");
  });
});
