import { describe, it, expect, vi } from "vitest";
import { resolveRenderer } from "../elicit";
import type { ElicitRenderer, SurfaceReviewEntry } from "@local/shared";

const perOp: ElicitRenderer = vi.fn(() => ({ message: "per-op", fields: { x: 1 } }));
const perCat: ElicitRenderer = vi.fn(() => ({ message: "per-cat", fields: { x: 2 } }));

describe("resolveRenderer", () => {
  it("returns the per-op override when present", () => {
    const entry: SurfaceReviewEntry = { decision: "elicit", elicit: perOp };
    const r = resolveRenderer(entry, "external_data_flow", { external_data_flow: perCat });
    expect(r).toBe(perOp);
  });

  it("falls back to the per-category renderer when no per-op", () => {
    const entry: SurfaceReviewEntry = { decision: "elicit" };
    const r = resolveRenderer(entry, "external_data_flow", { external_data_flow: perCat });
    expect(r).toBe(perCat);
  });

  it("returns undefined when neither resolves (caller falls back to walker)", () => {
    const entry: SurfaceReviewEntry = { decision: "elicit" };
    const r = resolveRenderer(entry, "external_data_flow", {});
    expect(r).toBeUndefined();
  });

  it("returns undefined when category is undefined and no per-op", () => {
    const entry: SurfaceReviewEntry = { decision: "elicit" };
    const r = resolveRenderer(entry, undefined, { external_data_flow: perCat });
    expect(r).toBeUndefined();
  });

  it("returns undefined when renderers map is undefined", () => {
    const entry: SurfaceReviewEntry = { decision: "elicit" };
    expect(resolveRenderer(entry, "external_data_flow", undefined)).toBeUndefined();
  });
});
