import { describe, it, expect } from "vitest";
import { validateAcceptedContent } from "../elicit";

// D-1: an accept counts as approval only when the user ticked confirm.
// `{confirm:false}` used to approve (key set and typeof were all that was
// checked); it must now read as a decline.
describe("validateAcceptedContent", () => {
  it("accepts exactly { confirm: true }", () => {
    expect(validateAcceptedContent({ confirm: true })).toBe(true);
  });

  it("FIXED (D-1): rejects { confirm: false }", () => {
    expect(validateAcceptedContent({ confirm: false })).toBe(false);
  });

  it("rejects truthy non-boolean confirm values", () => {
    for (const v of ["true", 1, "yes", {}, [true]]) {
      expect(validateAcceptedContent({ confirm: v })).toBe(false);
    }
  });

  it("rejects extra keys", () => {
    expect(validateAcceptedContent({ confirm: true, extra: 1 })).toBe(false);
    expect(validateAcceptedContent({ confirm: true, count: 30 })).toBe(false);
  });

  it("rejects a symbol-keyed extra and a missing confirm", () => {
    expect(validateAcceptedContent({ confirm: true, [Symbol("x")]: 1 })).toBe(false);
    expect(validateAcceptedContent({})).toBe(false);
    expect(validateAcceptedContent({ name: "alpha" })).toBe(false);
  });

  it("rejects an inherited confirm", () => {
    expect(validateAcceptedContent(Object.create({ confirm: true }))).toBe(false);
  });

  it("rejects arrays, primitives, null and undefined", () => {
    expect(validateAcceptedContent([true])).toBe(false);
    expect(validateAcceptedContent(true)).toBe(false);
    expect(validateAcceptedContent("confirm")).toBe(false);
    expect(validateAcceptedContent(null)).toBe(false);
    expect(validateAcceptedContent(undefined)).toBe(false);
  });
});
