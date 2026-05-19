import { describe, it, expect } from "vitest";
import { applyPatches } from "../patch";

describe("applyPatches", () => {
  it("applies a list of RFC-6902 patches in order", () => {
    const doc = { x: 1, list: [1, 2] };
    const out = applyPatches(doc, [
      [{ op: "replace" as const, path: "/x", value: 9 }],
      [{ op: "add" as const, path: "/list/-", value: 3 }],
    ]);
    expect(out).toEqual({ x: 9, list: [1, 2, 3] });
  });

  it("does not mutate the input", () => {
    const doc = { x: 1 };
    applyPatches(doc, [[{ op: "replace" as const, path: "/x", value: 2 }]]);
    expect(doc).toEqual({ x: 1 });
  });

  it("returns the input unchanged when no patches are provided", () => {
    const doc = { a: 1 };
    expect(applyPatches(doc, [])).toEqual(doc);
  });
});
