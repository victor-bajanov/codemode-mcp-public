// packages/scaffold/src/__tests__/oauth-handler.test.ts
//
// Tests for the generic chained-OAuth Hono handler factory.
// Verifies:
//   - /authorize redirects to provider.oauth.authorizeUrl with the correct query params + persists state in KV.
//   - /callback exchanges code for tokens, fetches userInfo (if configured), runs completeAuthHook (if configured),
//     and calls OAuthProvider.completeAuthorization with the merged props.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createOAuthHandler } from "../oauth-handler";
import type { ApiProvider } from "../api-provider";

interface TestProps extends Record<string, unknown> {
  refreshToken: string;
  userId: string;
  email?: string;
  tenantId?: string;
}

const TEST_PROVIDER: ApiProvider<TestProps> = {
  name: "test",
  displayName: "Test Provider",
  oauth: {
    authorizeUrl: "https://login.example.com/authorize",
    tokenUrl: "https://login.example.com/token",
    scopes: ["openid", "offline_access", "test.read"],
    clientIdSecretName: "TEST_CLIENT_ID",
    clientSecretSecretName: "TEST_CLIENT_SECRET",
    userInfoUrl: "https://login.example.com/userinfo",
  },
  spec: {} as never,
  surfaceReview: {},
  apiBaseUrl: "https://api.example.com",
};

function makeKV() {
  const data = new Map<string, string>();
  return {
    data,
    async get(k: string): Promise<string | null> { return data.get(k) ?? null; },
    async put(k: string, v: string): Promise<void> { data.set(k, v); },
    async delete(k: string): Promise<void> { data.delete(k); },
  } as unknown as KVNamespace & { data: Map<string, string> };
}

function makeOAuthProvider() {
  const completeSpy = vi.fn(async (args: { request: unknown; userId: string; scope: string; metadata: unknown; props: unknown }) => ({
    redirectTo: `https://claude.ai/return?ok=1&user=${args.userId}`,
  }));
  return {
    completeSpy,
    parseAuthRequest: vi.fn(async () => ({ clientId: "claude-client", scope: "mcp" })),
    completeAuthorization: completeSpy,
  };
}

describe("createOAuthHandler", () => {
  beforeEach(() => vi.unstubAllGlobals());

  it("/authorize stores state in KV and redirects to provider.oauth.authorizeUrl with required params", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    const app = createOAuthHandler(TEST_PROVIDER);

    const res = await app.request("https://my-worker.dev/authorize?response_type=code", undefined, {
      OAUTH_PROVIDER: oauth as never,
      OAUTH_KV: KV,
      TEST_CLIENT_ID: "test-cid",
      TEST_CLIENT_SECRET: "test-csec",
    });

    expect(res.status).toBe(302);
    const loc = res.headers.get("location")!;
    expect(loc).toContain(TEST_PROVIDER.oauth.authorizeUrl);
    const url = new URL(loc);
    expect(url.searchParams.get("client_id")).toBe("test-cid");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid offline_access test.read");
    const state = url.searchParams.get("state")!;
    expect(state).toBeTruthy();
    expect(KV.data.has(`auth-state:${state}`)).toBe(true);
  });

  it("/callback exchanges code, calls userInfoUrl, runs completeAuthHook, and completes authorization", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();

    // Pre-seed KV state — pretending a prior /authorize stored it
    await KV.put(
      "auth-state:STATE-XYZ",
      JSON.stringify({ clientId: "claude-client", scope: "mcp" }),
    );

    const fetchSpy = vi.fn<typeof fetch>(async (input: RequestInfo | URL) => {
      const u = typeof input === "string" ? input : input.toString();
      if (u.startsWith(TEST_PROVIDER.oauth.tokenUrl)) {
        return new Response(JSON.stringify({
          access_token: "AT-fresh", refresh_token: "RT-fresh", expires_in: 1800,
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (u.startsWith(TEST_PROVIDER.oauth.userInfoUrl!)) {
        return new Response(JSON.stringify({
          sub: "subject-42", email: "u@example.com",
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch: ${u}`);
    });
    vi.stubGlobal("fetch", fetchSpy);

    const completeAuthHook = vi.fn(async () => ({ tenantId: "tenant-from-hook" }));

    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      completeAuthHook,
    };
    const app = createOAuthHandler(provider);

    const res = await app.request(
      "https://my-worker.dev/callback?code=CODE-A&state=STATE-XYZ",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never,
        OAUTH_KV: KV,
        TEST_CLIENT_ID: "test-cid",
        TEST_CLIENT_SECRET: "test-csec",
      },
    );

    expect(res.status).toBe(302);
    expect(completeAuthHook).toHaveBeenCalledTimes(1);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((completeAuthHook.mock.calls[0] as any)[0].tokens.access_token).toBe("AT-fresh");
    expect(oauth.completeSpy).toHaveBeenCalledTimes(1);
    const completeArgs = oauth.completeSpy.mock.calls[0]![0];
    expect((completeArgs.props as TestProps).refreshToken).toBe("RT-fresh");
    expect((completeArgs.props as TestProps).userId).toBe("subject-42");
    expect((completeArgs.props as TestProps).email).toBe("u@example.com");
    expect((completeArgs.props as TestProps).tenantId).toBe("tenant-from-hook");
  });

  it("/callback errors when token exchange fails (4xx)", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    await KV.put("auth-state:STATE", JSON.stringify({ clientId: "claude-client", scope: "mcp" }));

    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => new Response("bad", { status: 400 })));
    const app = createOAuthHandler(TEST_PROVIDER);

    const res = await app.request(
      "https://my-worker.dev/callback?code=BAD&state=STATE",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never,
        OAUTH_KV: KV,
        TEST_CLIENT_ID: "x", TEST_CLIENT_SECRET: "y",
      },
    );

    expect(res.status).toBe(502);
    expect(oauth.completeSpy).not.toHaveBeenCalled();
  });

  it("/callback propagates completeAuthHook errors as 502", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    await KV.put("auth-state:STATE", JSON.stringify({ clientId: "claude-client", scope: "mcp" }));

    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async (input: RequestInfo | URL) => {
      const u = typeof input === "string" ? input : input.toString();
      if (u.startsWith(TEST_PROVIDER.oauth.tokenUrl)) {
        return new Response(JSON.stringify({ access_token: "AT", refresh_token: "RT", expires_in: 60 }),
          { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ sub: "s" }), { status: 200, headers: { "content-type": "application/json" } });
    }));

    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      completeAuthHook: async () => { throw new Error("hook says no"); },
    };
    const app = createOAuthHandler(provider);

    const res = await app.request(
      "https://my-worker.dev/callback?code=C&state=STATE",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never, OAUTH_KV: KV,
        TEST_CLIENT_ID: "x", TEST_CLIENT_SECRET: "y",
      },
    );

    expect(res.status).toBe(502);
    expect(await res.text()).toContain("hook says no");
  });
});

describe("oauth-handler /authorize extraAuthorizeParams", () => {
  it("merges provider.oauth.extraAuthorizeParams into the redirect URL alongside base params", async () => {
    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      oauth: {
        ...TEST_PROVIDER.oauth,
        extraAuthorizeParams: {
          access_type: "offline",
          prompt: "consent",
          include_granted_scopes: "true",
        },
      },
    };
    const app = createOAuthHandler(provider);
    const env = {
      OAUTH_PROVIDER: {
        parseAuthRequest: vi.fn(async () => ({ clientId: "claude.ai", scope: ["test.read"] })),
        completeAuthorization: vi.fn(),
      },
      OAUTH_KV: makeKV(),
      TEST_CLIENT_ID: "cid",
      TEST_CLIENT_SECRET: "csec",
    };
    const res = await app.fetch(
      new Request("https://w.example.com/authorize?response_type=code"),
      env as never,
    );
    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("location")!);
    // Extras are merged in
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("include_granted_scopes")).toBe("true");
    // Base OAuth2 params still present alongside the extras
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid offline_access test.read");
    expect(url.searchParams.get("redirect_uri")).toBeTruthy();
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  it("default (no oauth.pkce field) adds code_challenge + code_challenge_method=S256 and stashes codeVerifier", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    const app = createOAuthHandler(TEST_PROVIDER);

    const res = await app.request("https://my-worker.dev/authorize?response_type=code", undefined, {
      OAUTH_PROVIDER: oauth as never,
      OAUTH_KV: KV,
      TEST_CLIENT_ID: "test-cid",
      TEST_CLIENT_SECRET: "test-csec",
    });

    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("location")!);
    const challenge = url.searchParams.get("code_challenge");
    expect(challenge).toBeTruthy();
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const state = url.searchParams.get("state")!;
    const stash = KV.data.get(`auth-state:${state}`)!;
    const parsed = JSON.parse(stash) as { oauthReqInfo: unknown; codeVerifier?: string };
    expect(parsed.oauthReqInfo).toBeTruthy();
    expect(typeof parsed.codeVerifier).toBe("string");
    expect(parsed.codeVerifier).toHaveLength(43);
  });

  it("oauth.pkce: \"none\" omits PKCE params and stashes codeVerifier=undefined", async () => {
    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      oauth: { ...TEST_PROVIDER.oauth, pkce: "none" },
    };
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    const app = createOAuthHandler(provider);

    const res = await app.request("https://my-worker.dev/authorize?response_type=code", undefined, {
      OAUTH_PROVIDER: oauth as never,
      OAUTH_KV: KV,
      TEST_CLIENT_ID: "test-cid",
      TEST_CLIENT_SECRET: "test-csec",
    });

    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("location")!);
    expect(url.searchParams.get("code_challenge")).toBeNull();
    expect(url.searchParams.get("code_challenge_method")).toBeNull();
    const state = url.searchParams.get("state")!;
    const stash = KV.data.get(`auth-state:${state}`)!;
    const parsed = JSON.parse(stash) as { oauthReqInfo: unknown; codeVerifier?: string };
    expect(parsed.oauthReqInfo).toBeTruthy();
    expect(parsed.codeVerifier).toBeUndefined();
  });

  it("/callback sends code_verifier in token POST body when stashed", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    const VERIFIER = "test-verifier-43-chars-base64url-no-padding";
    await KV.put(
      "auth-state:STATE-VFY",
      JSON.stringify({
        oauthReqInfo: { clientId: "claude-client", scope: "mcp" },
        codeVerifier: VERIFIER,
      }),
    );

    let capturedBody = "";
    const fetchSpy = vi.fn<typeof fetch>(async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof input === "string" ? input : input.toString();
      if (u.startsWith(TEST_PROVIDER.oauth.tokenUrl)) {
        capturedBody = typeof init?.body === "string" ? init.body : "";
        return new Response(JSON.stringify({
          access_token: "AT", refresh_token: "RT", expires_in: 60,
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (u.startsWith(TEST_PROVIDER.oauth.userInfoUrl!)) {
        return new Response(JSON.stringify({ sub: "s", email: "e@example.com" }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${u}`);
    });
    vi.stubGlobal("fetch", fetchSpy);

    const app = createOAuthHandler(TEST_PROVIDER);
    const res = await app.request(
      "https://my-worker.dev/callback?code=CODE-V&state=STATE-VFY",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never,
        OAUTH_KV: KV,
        TEST_CLIENT_ID: "cid", TEST_CLIENT_SECRET: "csec",
      },
    );

    expect(res.status).toBe(302);
    const sent = new URLSearchParams(capturedBody);
    expect(sent.get("code_verifier")).toBe(VERIFIER);
  });

  it("/callback emits actionable 502 + console.error when upstream rejects PKCE", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    await KV.put(
      "auth-state:STATE-PKCE-ERR",
      JSON.stringify({
        oauthReqInfo: { clientId: "claude-client", scope: "mcp" },
        codeVerifier: "some-verifier",
      }),
    );

    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        new Response("invalid_request: code_verifier required", { status: 400 }),
      ),
    );
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const app = createOAuthHandler(TEST_PROVIDER);
    const res = await app.request(
      "https://my-worker.dev/callback?code=C&state=STATE-PKCE-ERR",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never,
        OAUTH_KV: KV,
        TEST_CLIENT_ID: "cid", TEST_CLIENT_SECRET: "csec",
      },
    );

    expect(res.status).toBe(502);
    const body = await res.text();
    expect(body).toContain("upstream rejected PKCE");
    expect(body).toContain('oauth.pkce: "none"');
    expect(errSpy).toHaveBeenCalled();
    const msg = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(msg).toContain("rejected PKCE");
    expect(msg).toContain('oauth.pkce: "none"');
    errSpy.mockRestore();
  });

  it("/callback logs non-PKCE token-exchange failures with sliced body", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    await KV.put(
      "auth-state:STATE-GENERIC-ERR",
      JSON.stringify({
        oauthReqInfo: { clientId: "claude-client", scope: "mcp" },
        codeVerifier: "some-verifier",
      }),
    );

    const errBody = '{"error":"invalid_grant"}';
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => new Response(errBody, { status: 400 })),
    );
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const app = createOAuthHandler(TEST_PROVIDER);
    const res = await app.request(
      "https://my-worker.dev/callback?code=C&state=STATE-GENERIC-ERR",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never,
        OAUTH_KV: KV,
        TEST_CLIENT_ID: "cid", TEST_CLIENT_SECRET: "csec",
      },
    );

    expect(res.status).toBe(502);
    expect(await res.text()).toContain("token exchange failed");
    expect(errSpy).toHaveBeenCalled();
    const msg = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(msg).toContain("token exchange failed");
    expect(msg).toContain(errBody);
    errSpy.mockRestore();
  });

  it("/callback honours legacy KV state shape (bare oauthReqInfo, no envelope) and sends no code_verifier", async () => {
    const KV = makeKV();
    const oauth = makeOAuthProvider();
    // Legacy shape: JSON.stringify(oauthReqInfo) directly, with no
    // `oauthReqInfo` envelope key. The handler must still parse this and
    // simply omit `code_verifier` from the token POST.
    await KV.put(
      "auth-state:STATE-LEGACY",
      JSON.stringify({ clientId: "claude-client", scope: "mcp" }),
    );

    let capturedBody = "";
    const fetchSpy = vi.fn<typeof fetch>(async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof input === "string" ? input : input.toString();
      if (u.startsWith(TEST_PROVIDER.oauth.tokenUrl)) {
        capturedBody = typeof init?.body === "string" ? init.body : "";
        return new Response(JSON.stringify({
          access_token: "AT", refresh_token: "RT", expires_in: 60,
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (u.startsWith(TEST_PROVIDER.oauth.userInfoUrl!)) {
        return new Response(JSON.stringify({ sub: "s", email: "e@example.com" }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${u}`);
    });
    vi.stubGlobal("fetch", fetchSpy);

    const app = createOAuthHandler(TEST_PROVIDER);
    const res = await app.request(
      "https://my-worker.dev/callback?code=CODE-L&state=STATE-LEGACY",
      undefined,
      {
        OAUTH_PROVIDER: oauth as never,
        OAUTH_KV: KV,
        TEST_CLIENT_ID: "cid", TEST_CLIENT_SECRET: "csec",
      },
    );

    expect(res.status).toBe(302);
    const sent = new URLSearchParams(capturedBody);
    expect(sent.has("code_verifier")).toBe(false);
  });

  it("does not let extraAuthorizeParams clobber protected base OAuth2 params", async () => {
    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      oauth: {
        ...TEST_PROVIDER.oauth,
        extraAuthorizeParams: {
          // Collisions with base params should be skipped (silent no-op)
          state: "ATTACKER-CONTROLLED",
          client_id: "OTHER-CLIENT",
          scope: "evil",
          // Legitimate non-colliding extras still pass through
          access_type: "offline",
        },
      },
    };
    const app = createOAuthHandler(provider);
    const KV = makeKV();
    const env = {
      OAUTH_PROVIDER: {
        parseAuthRequest: vi.fn(async () => ({ clientId: "claude.ai", scope: ["test.read"] })),
        completeAuthorization: vi.fn(),
      },
      OAUTH_KV: KV,
      TEST_CLIENT_ID: "cid",
      TEST_CLIENT_SECRET: "csec",
    };
    const res = await app.fetch(
      new Request("https://w.example.com/authorize?response_type=code"),
      env as never,
    );
    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("location")!);
    // Base params keep their scaffold-set values
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("scope")).toBe("openid offline_access test.read");
    const state = url.searchParams.get("state");
    expect(state).not.toBe("ATTACKER-CONTROLLED");
    expect(state).toBeTruthy();
    // KV holds the real (scaffold-generated) state, not the attacker value
    expect(KV.data.has(`auth-state:${state}`)).toBe(true);
    expect(KV.data.has("auth-state:ATTACKER-CONTROLLED")).toBe(false);
    // Non-colliding extras still merged
    expect(url.searchParams.get("access_type")).toBe("offline");
  });
});
