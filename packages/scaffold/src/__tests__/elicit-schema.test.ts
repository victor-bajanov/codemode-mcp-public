import { describe, it, expect } from "vitest";
import { CONFIRM_SCHEMA } from "../elicit";

// D-1: the approval dialog asks one question only. Facts are shown in the
// message, never requested as inputs (inputs were the bug: the user typed
// the "count"), so the schema is a constant confirm-only form.
describe("CONFIRM_SCHEMA", () => {
  it("is the confirm-only closed schema (same bytes as the single-confirm dialog)", () => {
    expect(JSON.stringify(CONFIRM_SCHEMA)).toBe(
      '{"type":"object","properties":{"confirm":{"type":"boolean"}},"required":["confirm"],"additionalProperties":false}',
    );
  });

  it("is frozen so no caller can widen it", () => {
    expect(Object.isFrozen(CONFIRM_SCHEMA)).toBe(true);
    expect(Object.isFrozen(CONFIRM_SCHEMA.properties)).toBe(true);
    expect(Object.isFrozen(CONFIRM_SCHEMA.properties.confirm)).toBe(true);
    expect(Object.isFrozen(CONFIRM_SCHEMA.required)).toBe(true);
  });
});
