import { describe, it, expect } from "vitest";
import { readStagingConfig, readStagingThrottleConfig } from "../config";

describe("readStagingConfig", () => {
  it("returns defaults when no vars are set", () => {
    expect(readStagingConfig({})).toEqual({
      uploadTtlSeconds: 300,
      fetchTtlSeconds: 3600,
      maxBytes: 50 * 1024 * 1024,
      getFileMaxBytes: 8_388_608,
      composeMaxBytes: 75_497_472,
      maxConcurrentTransfers: 2,
      transferTimeoutMs: 60_000,
    });
  });

  it("parses overrides from vars", () => {
    expect(
      readStagingConfig({
        STAGING_UPLOAD_TTL_SECONDS: "60",
        STAGING_FETCH_TTL_SECONDS: "120",
        STAGING_MAX_BYTES: "1024",
      }),
    ).toMatchObject({ uploadTtlSeconds: 60, fetchTtlSeconds: 120, maxBytes: 1024 });
  });

  it("parses the staged-transfer v2 vars", () => {
    expect(
      readStagingConfig({
        STAGING_GETFILE_MAX_BYTES: "1000",
        STAGING_COMPOSE_MAX_BYTES: "2000",
        STAGING_MAX_CONCURRENT_TRANSFERS: "3",
        STAGING_TRANSFER_TIMEOUT_MS: "5000",
      }),
    ).toMatchObject({
      getFileMaxBytes: 1000,
      composeMaxBytes: 2000,
      maxConcurrentTransfers: 3,
      transferTimeoutMs: 5000,
    });
  });

  it("rejects invalid staged-transfer v2 vars", () => {
    for (const name of [
      "STAGING_GETFILE_MAX_BYTES",
      "STAGING_COMPOSE_MAX_BYTES",
      "STAGING_MAX_CONCURRENT_TRANSFERS",
      "STAGING_TRANSFER_TIMEOUT_MS",
    ]) {
      expect(() => readStagingConfig({ [name]: "0" })).toThrow(new RegExp(name));
      expect(() => readStagingConfig({ [name]: "1.5" })).toThrow(new RegExp(name));
    }
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
