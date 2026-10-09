// readExecutionLimits — the env contract for the host-side sandbox limits
// (F-12). Same positive-integer rules as config.ts's vars: unset or "" means
// the default, anything else must be a positive integer or boot fails loudly.
import { describe, it, expect } from "vitest";
import {
  DEFAULT_EXECUTE_HOST_TIMEOUT_MS,
  DEFAULT_EXECUTE_MAX_UPSTREAM_CALLS,
  readExecutionLimits,
} from "../execution-limits";

describe("readExecutionLimits", () => {
  it("defaults to 75 000 ms and 1 000 calls when unset", () => {
    expect(DEFAULT_EXECUTE_HOST_TIMEOUT_MS).toBe(75_000);
    expect(DEFAULT_EXECUTE_MAX_UPSTREAM_CALLS).toBe(1_000);
    expect(readExecutionLimits({})).toEqual({ hostTimeoutMs: 75_000, maxUpstreamCalls: 1_000 });
  });

  it("treats empty strings (and null) as unset", () => {
    expect(
      readExecutionLimits({ EXECUTE_HOST_TIMEOUT_MS: "", EXECUTE_MAX_UPSTREAM_CALLS: null }),
    ).toEqual({ hostTimeoutMs: 75_000, maxUpstreamCalls: 1_000 });
  });

  it("honours overrides, as strings (wrangler vars) or numbers", () => {
    expect(
      readExecutionLimits({ EXECUTE_HOST_TIMEOUT_MS: "30000", EXECUTE_MAX_UPSTREAM_CALLS: "50" }),
    ).toEqual({ hostTimeoutMs: 30_000, maxUpstreamCalls: 50 });
    expect(
      readExecutionLimits({ EXECUTE_HOST_TIMEOUT_MS: 1, EXECUTE_MAX_UPSTREAM_CALLS: 1 }),
    ).toEqual({ hostTimeoutMs: 1, maxUpstreamCalls: 1 });
  });

  it.each(["0", "-1", "1.5", "abc", " ", "Infinity", "NaN"])(
    "throws on EXECUTE_HOST_TIMEOUT_MS=%j",
    (raw) => {
      expect(() => readExecutionLimits({ EXECUTE_HOST_TIMEOUT_MS: raw })).toThrow(
        /EXECUTE_HOST_TIMEOUT_MS: must be a positive integer/,
      );
    },
  );

  it.each(["0", "-5", "2.5", "lots", " ", "Infinity"])(
    "throws on EXECUTE_MAX_UPSTREAM_CALLS=%j",
    (raw) => {
      expect(() => readExecutionLimits({ EXECUTE_MAX_UPSTREAM_CALLS: raw })).toThrow(
        /EXECUTE_MAX_UPSTREAM_CALLS: must be a positive integer/,
      );
    },
  );
});
