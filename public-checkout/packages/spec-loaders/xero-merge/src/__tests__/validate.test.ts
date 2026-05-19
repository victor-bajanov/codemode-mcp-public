import { describe, it, expect } from "vitest";
import { validateMerged } from "../validate";

const VALID = {
  openapi: "3.0.0",
  info: { title: "X", version: "1" },
  servers: [{ url: "https://x" }],
  paths: {
    "/a": { get: { operationId: "getA", responses: { "200": { description: "OK" } } } },
    "/b": { get: { operationId: "getB", responses: { "200": { description: "OK" } } } },
  },
  components: { schemas: {} },
} as const;

describe("validateMerged", () => {
  it("returns the document unchanged when valid", () => {
    expect(validateMerged(VALID)).toEqual(VALID);
  });

  it("throws on duplicate operationIds", () => {
    const doc = {
      ...VALID,
      paths: {
        "/a": { get: { operationId: "dup", responses: { "200": { description: "OK" } } } },
        "/b": { get: { operationId: "dup", responses: { "200": { description: "OK" } } } },
      },
    };
    expect(() => validateMerged(doc)).toThrow(/duplicate operationId/i);
  });

  it("throws on missing operationId", () => {
    const doc = {
      ...VALID,
      paths: { "/a": { get: { responses: { "200": { description: "OK" } } } } },
    };
    expect(() => validateMerged(doc)).toThrow(/missing operationId/i);
  });
});
