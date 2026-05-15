import { describe, it, expect } from "vitest";
import { truncateForReturn } from "../truncate";

describe("truncateForReturn", () => {
  it("returns small JSON unchanged", () => {
    const out = truncateForReturn({ a: 1 }, 1000);
    expect(out).toEqual({ a: 1 });
  });

  it("truncates very long strings inside objects", () => {
    const big = "x".repeat(100_000);
    const out = truncateForReturn({ field: big }, 64 * 1024) as { field: string };
    expect(out.field.length).toBeLessThan(70_000);
    expect(out.field).toContain("[TRUNCATED");
  });

  it("truncates raw strings", () => {
    const out = truncateForReturn("y".repeat(200_000), 1000) as string;
    expect(out.length).toBeLessThan(2000);
    expect(out).toContain("[TRUNCATED");
  });

  it("truncates large arrays by item count + appends marker", () => {
    const arr = Array.from({ length: 10_000 }, (_, i) => ({ id: i }));
    const out = truncateForReturn(arr, 1024) as Array<{ id: number } | string>;
    expect(out.length).toBeLessThan(10_000);
    expect(out[out.length - 1]).toMatch(/TRUNCATED/);
  });
});
