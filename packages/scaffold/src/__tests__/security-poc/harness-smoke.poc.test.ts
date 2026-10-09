import { describe, it, expect } from "vitest";
import { resolveOperation } from "../../path-matcher";
describe("poc harness smoke", () => {
  it("loads scaffold modules under the poc config", () => {
    expect(resolveOperation({ paths: {} } as never, "GET", "/x")).toBeNull();
  });
});
