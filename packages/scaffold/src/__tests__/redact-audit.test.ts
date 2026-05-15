import { describe, it, expect } from "vitest";
import { redactAuditEntry, type AuditEntry } from "../audit";

/**
 * Coverage for the H1 redaction helper.
 *
 *   - Entries with no `elicitFields` are returned unchanged (no PII to drop).
 *   - String values become `<key>Length` integers preserving `.length`.
 *   - Array values become `<key>Count` integers preserving `.length`. (`FormFields`
 *     today is `Record<string, Primitive>` and doesn't admit arrays, but the
 *     helper is defensive against a future inspector emitting an array — we
 *     cast through `unknown` to exercise the branch without widening the
 *     public type.)
 *   - Number values collapse to `<key>Value: 0` — counts are themselves
 *     operational-pattern leakage.
 *   - Operational fields outside `elicitFields` survive untouched.
 */
describe("redactAuditEntry", () => {
  const base: AuditEntry = {
    deployment: "gmail",
    operationId: "gmail.users.messages.send",
    method: "POST",
    path: "/gmail/v1/users/me/messages/send",
    decision: "elicit",
    category: "external_data_flow",
    reason: "mass-send",
    principalId: "user-abc",
    context: { tenantId: "tenant-xyz" },
    ts: "2026-05-13T00:00:00.000Z",
  };

  it("returns the entry unchanged when elicitFields is absent", () => {
    const result = redactAuditEntry(base);
    expect(result).toEqual(base);
    // Either same ref or structurally equal — design only requires identity-shape.
    expect(result.elicitFields).toBeUndefined();
  });

  it("redacts string fields to <key>Length integers matching .length", () => {
    const entry: AuditEntry = {
      ...base,
      elicitFields: { subject: "hello world", recipients: "a@b.com,c@d.com" },
    };
    const result = redactAuditEntry(entry);
    expect(result.elicitFields).toMatchObject({
      __redacted__: true,
      keys: expect.arrayContaining(["subject", "recipients"]) as unknown,
      subjectLength: "hello world".length,
      recipientsLength: "a@b.com,c@d.com".length,
    });
    const rawValues = JSON.stringify(result.elicitFields);
    expect(rawValues).not.toContain("hello world");
    expect(rawValues).not.toContain("a@b.com");
  });

  it("redacts array fields to <key>Count integers matching .length", () => {
    // FormFields doesn't admit arrays today, but the helper handles arrays
    // for future-proofing. Cast through unknown to exercise the branch.
    const entry: AuditEntry = {
      ...base,
      elicitFields: {
        recipients: ["a@b.com", "c@d.com", "e@f.com"] as unknown as string,
      },
    };
    const result = redactAuditEntry(entry);
    expect(result.elicitFields).toMatchObject({
      __redacted__: true,
      keys: ["recipients"],
      recipientsCount: 3,
    });
  });

  it("redacts number fields to <key>Value: 0 (no count leakage)", () => {
    const entry: AuditEntry = {
      ...base,
      elicitFields: { count: 47 },
    };
    const result = redactAuditEntry(entry);
    expect(result.elicitFields).toMatchObject({
      __redacted__: true,
      keys: ["count"],
      countValue: 0,
    });
  });

  it("preserves all operational fields outside elicitFields", () => {
    const entry: AuditEntry = {
      ...base,
      elicitFields: { subject: "secret", count: 5 },
      elicitationOutcome: "accepted",
      upstreamStatus: 200,
    };
    const result = redactAuditEntry(entry);
    expect(result.deployment).toBe("gmail");
    expect(result.operationId).toBe("gmail.users.messages.send");
    expect(result.method).toBe("POST");
    expect(result.path).toBe("/gmail/v1/users/me/messages/send");
    expect(result.decision).toBe("elicit");
    expect(result.category).toBe("external_data_flow");
    expect(result.reason).toBe("mass-send");
    expect(result.principalId).toBe("user-abc");
    expect(result.context).toEqual({ tenantId: "tenant-xyz" });
    expect(result.ts).toBe("2026-05-13T00:00:00.000Z");
    expect(result.elicitationOutcome).toBe("accepted");
    expect(result.upstreamStatus).toBe(200);
  });

  it("handles mixed string + number elicitFields together", () => {
    const entry: AuditEntry = {
      ...base,
      elicitFields: { recipients: "a@b.com", subject: "hi", count: 5 },
    };
    const result = redactAuditEntry(entry);
    expect(result.elicitFields).toMatchObject({
      __redacted__: true,
      keys: expect.arrayContaining(["recipients", "subject", "count"]) as unknown,
      recipientsLength: "a@b.com".length,
      subjectLength: 2,
      countValue: 0,
    });
  });
});
