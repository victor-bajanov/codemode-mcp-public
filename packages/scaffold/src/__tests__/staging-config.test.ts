import { describe, it, expect } from "vitest";
import { readStagingConfig, readStagingThrottleConfig } from "../config";

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

describe("readStagingThrottleConfig", () => {
  it("defaults to 30 failures per 300 s", () => {
    expect(readStagingThrottleConfig({})).toEqual({ limit: 30, windowSeconds: 300 });
  });

  it("parses overrides from vars", () => {
    expect(
      readStagingThrottleConfig({
        STAGING_FAILURE_RATE_LIMIT: "5",
        STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS: "60",
      }),
    ).toEqual({ limit: 5, windowSeconds: 60 });
  });

  it("treats an empty string as unset", () => {
    expect(readStagingThrottleConfig({ STAGING_FAILURE_RATE_LIMIT: "" })).toEqual({
      limit: 30,
      windowSeconds: 300,
    });
  });

  it("throws on non-numeric / zero / negative / fractional input", () => {
    expect(() => readStagingThrottleConfig({ STAGING_FAILURE_RATE_LIMIT: "abc" })).toThrow(
      /STAGING_FAILURE_RATE_LIMIT/,
    );
    expect(() => readStagingThrottleConfig({ STAGING_FAILURE_RATE_LIMIT: "0" })).toThrow();
    expect(() =>
      readStagingThrottleConfig({ STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS: "-5" }),
    ).toThrow(/STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS/);
    expect(() => readStagingThrottleConfig({ STAGING_FAILURE_RATE_LIMIT: "1.5" })).toThrow();
  });
});
