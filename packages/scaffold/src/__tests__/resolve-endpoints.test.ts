import { describe, it, expect } from "vitest";
import { resolveEndpoints } from "../config";

const provider = {
  apiBaseUrl: "https://api.prod.example",
  oauth: {
    authorizeUrl: "https://api.prod.example/oauth/authorize",
    tokenUrl: "https://api.prod.example/oauth/token",
    userInfoUrl: "https://api.prod.example/oauth/userinfo",
  },
};

describe("resolveEndpoints", () => {
  it("falls back to static provider values when no overrides are set", () => {
    expect(resolveEndpoints(provider, {})).toEqual({
      apiBaseUrl: "https://api.prod.example",
      authorizeUrl: "https://api.prod.example/oauth/authorize",
      tokenUrl: "https://api.prod.example/oauth/token",
      userInfoUrl: "https://api.prod.example/oauth/userinfo",
    });
  });

  it("applies each per-field override independently", () => {
    expect(
      resolveEndpoints(provider, {
        API_BASE_URL_OVERRIDE: "https://api.dev.example",
        OAUTH_AUTHORIZE_URL_OVERRIDE: "https://api.dev.example/oauth/authorize",
        OAUTH_TOKEN_URL_OVERRIDE: "https://api.dev.example/oauth/token",
        OAUTH_USERINFO_URL_OVERRIDE: "https://api.dev.example/oauth/userinfo",
      }),
    ).toEqual({
      apiBaseUrl: "https://api.dev.example",
      authorizeUrl: "https://api.dev.example/oauth/authorize",
      tokenUrl: "https://api.dev.example/oauth/token",
      userInfoUrl: "https://api.dev.example/oauth/userinfo",
    });
  });

  it("mixes overrides and fallbacks per field", () => {
    const r = resolveEndpoints(provider, {
      API_BASE_URL_OVERRIDE: "https://api.dev.example",
    });
    expect(r.apiBaseUrl).toBe("https://api.dev.example");
    // OAuth URLs untouched — still prod.
    expect(r.tokenUrl).toBe("https://api.prod.example/oauth/token");
  });

  it("ignores empty-string and non-string override vars", () => {
    expect(
      resolveEndpoints(provider, { API_BASE_URL_OVERRIDE: "", OAUTH_TOKEN_URL_OVERRIDE: 123 }),
    ).toEqual({
      apiBaseUrl: "https://api.prod.example",
      authorizeUrl: "https://api.prod.example/oauth/authorize",
      tokenUrl: "https://api.prod.example/oauth/token",
      userInfoUrl: "https://api.prod.example/oauth/userinfo",
    });
  });

  it("preserves undefined userInfoUrl when provider omits it and no override", () => {
    const noUserInfo = { apiBaseUrl: "https://a", oauth: { authorizeUrl: "https://a/au", tokenUrl: "https://a/t" } };
    expect(resolveEndpoints(noUserInfo, {}).userInfoUrl).toBeUndefined();
  });
});
