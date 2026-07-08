import { describe, it, expect } from "vitest";
import { deepFreeze } from "../freeze";

describe("deepFreeze", () => {
  it("freezes the top-level object", () => {
    const o: { a: number } = deepFreeze({ a: 1 });
    expect(Object.isFrozen(o)).toBe(true);
  });

  it("freezes nested objects", () => {
    const o = deepFreeze({ a: { b: { c: 1 } } });
    expect(Object.isFrozen((o as { a: { b: object } }).a.b)).toBe(true);
  });

  it("freezes arrays", () => {
    const o = deepFreeze({ ids: [1, 2, 3] });
    expect(Object.isFrozen((o as { ids: number[] }).ids)).toBe(true);
  });

  it("returns the same reference (not a copy)", () => {
    const input = { a: 1 };
    const output = deepFreeze(input);
    expect(output).toBe(input);
  });

  it("tolerates primitives and null", () => {
    expect(deepFreeze(undefined)).toBe(undefined);
    expect(deepFreeze(null)).toBe(null);
    expect(deepFreeze("s")).toBe("s");
  });

  it("does not loop on circular references", () => {
    const a: Record<string, unknown> = { x: 1 };
    a.self = a;
    expect(() => deepFreeze(a)).not.toThrow();
    expect(Object.isFrozen(a)).toBe(true);
  });

  it("does not throw on non-empty typed-array values; still freezes the outer object", () => {
    const input = { a: new Uint8Array([1, 2, 3]) };
    let output: typeof input;
    expect(() => { output = deepFreeze(input); }).not.toThrow();
    expect(Object.isFrozen(output!)).toBe(true);
    // The typed array is left unfrozen (Object.freeze is impossible on it) but intact.
    expect(Object.isFrozen(output!.a)).toBe(false);
    expect(Array.from(output!.a)).toEqual([1, 2, 3]);
  });
});
