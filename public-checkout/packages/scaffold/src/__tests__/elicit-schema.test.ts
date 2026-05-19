import { describe, it, expect } from "vitest";
import { buildRequestedSchema } from "../elicit";

describe("buildRequestedSchema", () => {
  it("infers types from value types", () => {
    expect(buildRequestedSchema({ a: "x", b: 1, c: true })).toEqual({
      type: "object",
      properties: {
        a: { type: "string" },
        b: { type: "number" },
        c: { type: "boolean" },
      },
      required: ["a", "b", "c"],
      additionalProperties: false,
    });
  });

  it("returns a closed schema with all keys required", () => {
    const s = buildRequestedSchema({ confirm: true });
    expect(s.additionalProperties).toBe(false);
    expect(s.required).toEqual(["confirm"]);
  });

  it("preserves key order in required[]", () => {
    const s = buildRequestedSchema({ z: 1, a: 2, m: 3 });
    expect(s.required).toEqual(["z", "a", "m"]);
  });
});
