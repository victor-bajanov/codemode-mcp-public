import { describe, it, expect } from "vitest";
import { readOAuthClientTtlSeconds, readOAuthRateLimitConfig } from "../config";

describe("readOAuthRateLimitConfig", () => {
  it("returns per-endpoint defaults when no vars are set", () => {
    expect(readOAuthRateLimitConfig({})).toEqual({
      register: { limit: 1, windowSeconds: 300 },
      token: { limit: 20, windowSeconds: 60 },
    });
  });

  it("parses register overrides independently of token", () => {
    expect(
      readOAuthRateLimitConfig({
        OAUTH_REGISTER_RATE_LIMIT: "2",
        OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS: "600",
      }),
    ).toEqual({
      register: { limit: 2, windowSeconds: 600 },
      token: { limit: 20, windowSeconds: 60 },
    });
  });

  it("parses token overrides independently of register", () => {
    expect(
      readOAuthRateLimitConfig({
        OAUTH_TOKEN_RATE_LIMIT: "50",
        OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS: "30",
      }),
    ).toEqual({
      register: { limit: 1, windowSeconds: 300 },
      token: { limit: 50, windowSeconds: 30 },
    });
  });

  it("throws on non-numeric / zero / negative input", () => {
    expect(() => readOAuthRateLimitConfig({ OAUTH_REGISTER_RATE_LIMIT: "abc" })).toThrow();
    expect(() => readOAuthRateLimitConfig({ OAUTH_TOKEN_RATE_LIMIT: "0" })).toThrow();
    expect(() =>
      readOAuthRateLimitConfig({ OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS: "-5" }),
    ).toThrow();
  });
});

describe("readOAuthClientTtlSeconds", () => {
  it("defaults to 30 days when unset", () => {
    expect(readOAuthClientTtlSeconds({})).toBe(30 * 24 * 60 * 60);
  });

  it("parses an override", () => {
    expect(readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "604800" })).toBe(604800);
  });

  it("throws on invalid input", () => {
    expect(() => readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "nope" })).toThrow();
    expect(() => readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "0" })).toThrow();
  });
});
