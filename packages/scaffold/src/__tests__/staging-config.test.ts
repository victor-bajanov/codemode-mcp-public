import { describe, it, expect } from "vitest";
import { readStagingConfig } from "../config";

describe("readStagingConfig", () => {
  it("returns defaults when no vars are set", () => {
    expect(readStagingConfig({})).toEqual({
      uploadTtlSeconds: 300,
      fetchTtlSeconds: 3600,
      maxBytes: 50 * 1024 * 1024,
    });
  });

  it("parses overrides from vars", () => {
    expect(
      readStagingConfig({
        STAGING_UPLOAD_TTL_SECONDS: "60",
        STAGING_FETCH_TTL_SECONDS: "120",
        STAGING_MAX_BYTES: "1024",
      }),
    ).toEqual({ uploadTtlSeconds: 60, fetchTtlSeconds: 120, maxBytes: 1024 });
  });

  it("throws on non-numeric input", () => {
    expect(() => readStagingConfig({ STAGING_UPLOAD_TTL_SECONDS: "abc" })).toThrow();
  });

  it("throws on zero / negative", () => {
    expect(() => readStagingConfig({ STAGING_MAX_BYTES: "0" })).toThrow();
    expect(() => readStagingConfig({ STAGING_MAX_BYTES: "-1" })).toThrow();
  });
});
