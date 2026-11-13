import { describe, it, expect } from "vitest";
import {
  readOAuthClientTtlSeconds,
  readOAuthHardeningConfig,
  readOAuthRateLimitConfig,
} from "../config";
import { MCP_REFRESH_TOKEN_TTL_SECONDS } from "../oauth-provider-options";

const DEFAULT_AUTHORIZE = { limit: 30, windowSeconds: 300 };
const DEFAULT_CALLBACK = { limit: 10, windowSeconds: 300 };

describe("readOAuthRateLimitConfig", () => {
  it("returns per-endpoint defaults when no vars are set", () => {
    expect(readOAuthRateLimitConfig({})).toEqual({
      register: { limit: 1, windowSeconds: 300 },
      token: { limit: 20, windowSeconds: 60 },
      authorize: DEFAULT_AUTHORIZE,
      callback: DEFAULT_CALLBACK,
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
      authorize: DEFAULT_AUTHORIZE,
      callback: DEFAULT_CALLBACK,
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
      authorize: DEFAULT_AUTHORIZE,
      callback: DEFAULT_CALLBACK,
    });
  });

  it("FIXED (A-3): parses /authorize and /callback overrides independently", () => {
    expect(
      readOAuthRateLimitConfig({
        OAUTH_AUTHORIZE_RATE_LIMIT: "60",
        OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS: "600",
      }),
    ).toEqual({
      register: { limit: 1, windowSeconds: 300 },
      token: { limit: 20, windowSeconds: 60 },
      authorize: { limit: 60, windowSeconds: 600 },
      callback: DEFAULT_CALLBACK,
    });
    expect(
      readOAuthRateLimitConfig({
        OAUTH_CALLBACK_RATE_LIMIT: "5",
        OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS: "120",
      }),
    ).toEqual({
      register: { limit: 1, windowSeconds: 300 },
      token: { limit: 20, windowSeconds: 60 },
      authorize: DEFAULT_AUTHORIZE,
      callback: { limit: 5, windowSeconds: 120 },
    });
  });

  it("throws on non-numeric / zero / negative input", () => {
    expect(() => readOAuthRateLimitConfig({ OAUTH_REGISTER_RATE_LIMIT: "abc" })).toThrow();
    expect(() => readOAuthRateLimitConfig({ OAUTH_TOKEN_RATE_LIMIT: "0" })).toThrow();
    expect(() =>
      readOAuthRateLimitConfig({ OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS: "-5" }),
    ).toThrow();
    expect(() => readOAuthRateLimitConfig({ OAUTH_AUTHORIZE_RATE_LIMIT: "x" })).toThrow();
    expect(() => readOAuthRateLimitConfig({ OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS: "0" })).toThrow();
    expect(() => readOAuthRateLimitConfig({ OAUTH_CALLBACK_RATE_LIMIT: "-1" })).toThrow();
    expect(() => readOAuthRateLimitConfig({ OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS: "1.5" })).toThrow();
  });
});

describe("readOAuthClientTtlSeconds", () => {
  it("defaults to 30 days when unset", () => {
    expect(readOAuthClientTtlSeconds({})).toBe(30 * 24 * 60 * 60);
  });

  it("parses an override", () => {
    expect(readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "604800" })).toBe(604800);
  });

  it("clamps to KV's 60-second minimum expirationTtl (A-5 review)", () => {
    expect(readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "1" })).toBe(60);
    expect(readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "59" })).toBe(60);
    expect(readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "61" })).toBe(61);
    expect(readOAuthHardeningConfig({ OAUTH_CLIENT_TTL_SECONDS: "5" }).clientTtl).toEqual({
      registeredSeconds: 60,
      activeSeconds: MCP_REFRESH_TOKEN_TTL_SECONDS + 60,
    });
  });

  it("throws on invalid input", () => {
    expect(() => readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "nope" })).toThrow();
    expect(() => readOAuthClientTtlSeconds({ OAUTH_CLIENT_TTL_SECONDS: "0" })).toThrow();
  });
});

describe("readOAuthHardeningConfig (A-3, A-5)", () => {
  it("composes the four rate limits with the client TTLs: 30 days unused, grant life + 30 days after a token call", () => {
    expect(readOAuthHardeningConfig({})).toEqual({
      ...readOAuthRateLimitConfig({}),
      clientTtl: {
        registeredSeconds: 30 * 24 * 60 * 60,
        activeSeconds: MCP_REFRESH_TOKEN_TTL_SECONDS + 30 * 24 * 60 * 60,
      },
    });
    expect(readOAuthHardeningConfig({}).clientTtl.activeSeconds).toBe(120 * 24 * 60 * 60);
  });

  it("reuses OAUTH_CLIENT_TTL_SECONDS as both the unused lifetime and the grace after the grant", () => {
    const cfg = readOAuthHardeningConfig({
      OAUTH_CLIENT_TTL_SECONDS: "604800",
      OAUTH_CALLBACK_RATE_LIMIT: "3",
    });
    expect(cfg.clientTtl).toEqual({
      registeredSeconds: 604800,
      activeSeconds: MCP_REFRESH_TOKEN_TTL_SECONDS + 604800,
    });
    expect(cfg.callback).toEqual({ limit: 3, windowSeconds: 300 });
  });
});
