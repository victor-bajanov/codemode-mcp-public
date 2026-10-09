// F-22 / F-2 regression in the normal suite: the OAuthProvider options that
// carry the 90-day grant lifetime and the S256-only PKCE rule. The security
// POCs exercise these through the OAuth harness, but POCs are not part of
// `pnpm test`, so dropping either option would otherwise leave CI green.

import { describe, it, expect, vi } from "vitest";

const captured: Array<Record<string, unknown>> = [];
vi.mock("@cloudflare/workers-oauth-provider", () => ({
  OAuthProvider: class {
    constructor(options: Record<string, unknown>) {
      captured.push(options);
    }
    fetch(): Response {
      return new Response(null, { status: 404 });
    }
  },
}));

import { MCP_OAUTH_PROVIDER_OPTIONS, MCP_REFRESH_TOKEN_TTL_SECONDS } from "../oauth-provider-options";
import { setupProvider } from "../setup-provider";
import type { ApiProvider } from "../api-provider";

const MINIMAL_PROVIDER: ApiProvider = {
  name: "test",
  displayName: "Test Provider",
  oauth: {
    authorizeUrl: "https://login.example.com/authorize",
    tokenUrl: "https://login.example.com/token",
    scopes: ["openid"],
    clientIdSecretName: "TEST_CLIENT_ID",
    clientSecretSecretName: "TEST_CLIENT_SECRET",
  },
  spec: {} as never,
  surfaceReview: {},
  apiBaseUrl: "https://api.example.com",
};

describe("MCP_OAUTH_PROVIDER_OPTIONS (F-2, F-22)", () => {
  it("grants and refresh tokens live 90 days", () => {
    expect(MCP_REFRESH_TOKEN_TTL_SECONDS).toBe(7_776_000);
    expect(MCP_OAUTH_PROVIDER_OPTIONS.refreshTokenTTL).toBe(MCP_REFRESH_TOKEN_TTL_SECONDS);
  });

  it("refuses plain PKCE", () => {
    expect(MCP_OAUTH_PROVIDER_OPTIONS.allowPlainPKCE).toBe(false);
  });

  it("setupProvider constructs the OAuthProvider with these options", () => {
    captured.length = 0;
    setupProvider(MINIMAL_PROVIDER);
    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      refreshTokenTTL: MCP_REFRESH_TOKEN_TTL_SECONDS,
      allowPlainPKCE: false,
      authorizeEndpoint: "/authorize",
      tokenEndpoint: "/token",
      clientRegistrationEndpoint: "/register",
    });
  });
});
