import { describe, it, expect } from "vitest";
import { validateAcceptedContent } from "../elicit";

const FIELDS = { name: "alpha", count: 7, active: true } as const;

describe("validateAcceptedContent", () => {
  it("accepts content with the same keys and matching types", () => {
    expect(validateAcceptedContent({ name: "alpha", count: 7, active: true }, FIELDS)).toBe(true);
  });

  it("accepts content with same keys but user-edited primitive values of correct type", () => {
    // (We do NOT enforce value equality — the form may be editable in some
    //  client implementations, even though we treat it as read-only-ish.)
    expect(validateAcceptedContent({ name: "beta", count: 9, active: false }, FIELDS)).toBe(true);
  });

  it("rejects missing keys", () => {
    expect(validateAcceptedContent({ name: "alpha", count: 7 }, FIELDS)).toBe(false);
  });

  it("rejects extra keys", () => {
    expect(validateAcceptedContent({ ...FIELDS, sneaky: "x" }, FIELDS)).toBe(false);
  });

  it("rejects wrong-type values", () => {
    expect(validateAcceptedContent({ name: 1, count: 7, active: true }, FIELDS)).toBe(false);
    expect(validateAcceptedContent({ name: "x", count: "7", active: true }, FIELDS)).toBe(false);
    expect(validateAcceptedContent({ name: "x", count: 7, active: 1 }, FIELDS)).toBe(false);
  });

  it("rejects null/undefined content", () => {
    expect(validateAcceptedContent(undefined, FIELDS)).toBe(false);
    expect(validateAcceptedContent(null, FIELDS)).toBe(false);
  });
});
