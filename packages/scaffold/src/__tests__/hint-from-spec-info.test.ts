import { describe, it, expect } from "vitest";
import { hintFromSpecInfo } from "../api-provider.js";

describe("hintFromSpecInfo", () => {
  it("returns the trimmed description when present", () => {
    expect(hintFromSpecInfo({ info: { description: "  flow guidance\n" } })).toBe(
      "flow guidance",
    );
  });

  it("returns undefined when description is whitespace-only", () => {
    expect(hintFromSpecInfo({ info: { description: "   \n\t  " } })).toBeUndefined();
  });

  it("returns undefined when description is absent", () => {
    expect(hintFromSpecInfo({ info: {} })).toBeUndefined();
    expect(hintFromSpecInfo({})).toBeUndefined();
  });
});
