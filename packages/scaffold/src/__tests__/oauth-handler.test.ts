// packages/scaffold/src/__tests__/oauth-handler.test.ts
//
// Tests for the generic chained-OAuth Hono handler factory.
// Verifies:
//   - GET /authorize requires MCP-client PKCE S256 and renders the consent
//     page (signed form token + __Host- SameSite=Strict cookie) without
//     writing KV or redirecting upstream (F-2).
//   - POST /authorize refuses a missing/wrong cookie, an expired or replayed
//     token; "deny" returns access_denied to the client; "approve" stashes the
//     state with a browser-binding hash, sets the binding cookie and 303s to
//     provider.oauth.authorizeUrl with the correct params (F-2, F-15, F-20).
//   - /callback refuses without the binding cookie (keeping the stash),
//     exchanges the code, fetches userInfo (if configured), runs
//     completeAuthHook (if configured) with upstream identity winning (F-23),
//     calls OAuthProvider.completeAuthorization and clears the cookie.
//   - Token-exchange failure logs carry status + error code; the body only
//     under ALLOW_PII_IN_LOGS (F-21).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createOAuthHandler } from "../oauth-handler";
import { sha256Base64Url } from "../pkce";
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

const CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const ORIGIN = "https://my-worker.dev";

interface KvEntry { value: string; opts?: unknown }

function makeKV() {
  const data = new Map<string, KvEntry>();
  const puts: string[] = [];
  return {
    data,
    puts,
    async get(k: string): Promise<string | null> { return data.get(k)?.value ?? null; },
    async put(k: string, v: string, opts?: unknown): Promise<void> {
      puts.push(k);
      data.set(k, { value: v, ...(opts ? { opts } : {}) });
    },
    async delete(k: string): Promise<void> { data.delete(k); },
  } as unknown as KVNamespace & { data: Map<string, KvEntry>; puts: string[] };
}

function authRequest(overrides: Record<string, unknown> = {}) {
  return {
    responseType: "code",
    clientId: "claude-client",
    redirectUri: CLIENT_REDIRECT,
    scope: ["mcp"],
    state: "client-state",
    codeChallenge: "mcp-client-challenge",
    codeChallengeMethod: "S256",
    ...overrides,
  };
}

function makeOAuthProvider(parsed: Record<string, unknown> | Error = authRequest()) {
  const completeSpy = vi.fn(async (args: { request: unknown; userId: string; scope: string[]; metadata: unknown; props: unknown }) => ({
    redirectTo: `https://claude.ai/return?ok=1&user=${args.userId}`,
  }));
  return {
    completeSpy,
    parseAuthRequest: vi.fn(async () => {
      if (parsed instanceof Error) throw parsed;
      return parsed;
    }),
    lookupClient: vi.fn(async (id: string) => ({ clientId: id, clientName: "Claude", redirectUris: [CLIENT_REDIRECT] })),
    completeAuthorization: completeSpy,
  };
}

function makeEnv(opts: { oauth?: ReturnType<typeof makeOAuthProvider>; extra?: Record<string, string> } = {}) {
  const KV = makeKV();
  const oauth = opts.oauth ?? makeOAuthProvider();
  const env = {
    OAUTH_PROVIDER: oauth as never,
    OAUTH_KV: KV,
    TEST_CLIENT_ID: "test-cid",
    TEST_CLIENT_SECRET: "test-csec",
    COOKIE_ENCRYPTION_KEY: "k".repeat(32),
    ...(opts.extra ?? {}),
  };
  return { KV, oauth, env };
}

type App = ReturnType<typeof createOAuthHandler<TestProps>>;
type Env = ReturnType<typeof makeEnv>["env"];

function setCookies(res: Response): string[] {
  return res.headers.getSetCookie();
}

/** GET /authorize → { res, token, cookieName, cookieValue }. */
async function getConsent(app: App, env: Env) {
  const res = await app.request(`${ORIGIN}/authorize?response_type=code`, undefined, env);
  const html = res.status === 200 ? await res.text() : "";
  const token = /name="consent_token" value="([^"]+)"/.exec(html)?.[1] ?? "";
  const m = /^(__Host-cm-consent-[0-9a-f]+)=([^;]+)/.exec(setCookies(res)[0] ?? "");
  return { res, html, token, cookieName: m?.[1] ?? "", cookieValue: m?.[2] ?? "" };
}

async function postConsent(
  app: App,
  env: Env,
  form: Record<string, string>,
  cookie?: string,
) {
  return app.request(
    `${ORIGIN}/authorize`,
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(cookie ? { cookie } : {}),
      },
      body: new URLSearchParams(form).toString(),
    },
    env,
  );
}

/** GET + approving POST → the upstream redirect, the state and its binding cookie. */
async function approveFlow(app: App, env: Env) {
  const consent = await getConsent(app, env);
  const res = await postConsent(
    app, env,
    { consent_token: consent.token, action: "approve" },
    `${consent.cookieName}=${consent.cookieValue}`,
  );
  const upstream = new URL(res.headers.get("location")!);
  const state = upstream.searchParams.get("state")!;
  const authCookie = setCookies(res).find((c) => c.startsWith(`__Host-cm-auth-${state}=`))!;
  const authCookiePair = authCookie.split(";")[0]!;
  return { consent, res, upstream, state, authCookie, authCookiePair };
}

function callback(app: App, env: Env, state: string, cookie?: string, code = "CODE-A") {
  return app.request(
    `${ORIGIN}/callback?code=${code}&state=${state}`,
    cookie ? { headers: { cookie } } : undefined,
    env,
  );
}

function stubUpstreamOk(opts: { userinfo?: unknown; onToken?: (body: string) => void } = {}) {
  const fetchSpy = vi.fn<typeof fetch>(async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof input === "string" ? input : input.toString();
    if (u.startsWith(TEST_PROVIDER.oauth.tokenUrl)) {
      opts.onToken?.(typeof init?.body === "string" ? init.body : "");
      return new Response(JSON.stringify({
        access_token: "AT-fresh", refresh_token: "RT-fresh", expires_in: 1800,
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u.startsWith(TEST_PROVIDER.oauth.userInfoUrl!)) {
      return new Response(JSON.stringify(opts.userinfo ?? { sub: "subject-42", email: "u@example.com" }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${u}`);
  });
  vi.stubGlobal("fetch", fetchSpy);
  return fetchSpy;
}

beforeEach(() => vi.unstubAllGlobals());
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("GET /authorize (consent interstitial, F-2)", () => {
  it("400 when the library rejects the request (e.g. plain PKCE), with no KV write", async () => {
    const { env, KV } = makeEnv({
      oauth: makeOAuthProvider(new Error("The plain PKCE method is not allowed. Use S256 instead.")),
    });
    const res = await createOAuthHandler(TEST_PROVIDER).request(`${ORIGIN}/authorize`, undefined, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe(
      "Invalid authorization request: The plain PKCE method is not allowed. Use S256 instead.",
    );
    expect(KV.puts).toEqual([]);
  });

  it("400 without code_challenge, or with a non-S256 method, and no KV write", async () => {
    for (const parsed of [
      authRequest({ codeChallenge: undefined }),
      authRequest({ codeChallengeMethod: "plain" }),
    ]) {
      const { env, KV } = makeEnv({ oauth: makeOAuthProvider(parsed) });
      const res = await createOAuthHandler(TEST_PROVIDER).request(`${ORIGIN}/authorize`, undefined, env);
      expect(res.status).toBe(400);
      expect(await res.text()).toBe("PKCE is required: send code_challenge with code_challenge_method=S256");
      expect(KV.puts).toEqual([]);
      expect(res.headers.get("set-cookie")).toBeNull();
    }
  });

  it("400 on a missing clientId, a non-code response_type or a missing redirect_uri", async () => {
    for (const [parsed, msg] of [
      [authRequest({ clientId: "" }), "missing clientId"],
      [authRequest({ responseType: "token" }), "response_type must be code"],
      [authRequest({ redirectUri: "" }), "missing redirect_uri"],
    ] as const) {
      const { env } = makeEnv({ oauth: makeOAuthProvider(parsed) });
      const res = await createOAuthHandler(TEST_PROVIDER).request(`${ORIGIN}/authorize`, undefined, env);
      expect(res.status).toBe(400);
      expect(await res.text()).toContain(msg);
    }
  });

  it("with S256 → 200 consent page + Strict consent cookie; no KV write, no upstream redirect", async () => {
    const { env, KV, oauth } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, env);
    expect(c.res.status).toBe(200);
    expect(c.res.headers.get("location")).toBeNull();
    expect(c.res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(c.res.headers.get("cache-control")).toBe("no-store");
    expect(c.res.headers.get("x-frame-options")).toBe("DENY");
    expect(c.res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(c.html).toContain("Test Provider");
    expect(c.html).toContain("Claude");
    expect(c.html).toContain("https://<strong>claude.ai</strong>/api/mcp/auth_callback");
    expect(c.html).toContain("test.read");
    expect(c.html).not.toContain("Warning:");
    expect(c.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(setCookies(c.res)[0]).toMatch(
      /^__Host-cm-consent-[0-9a-f]{32}=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=300$/,
    );
    expect(oauth.lookupClient).toHaveBeenCalledWith("claude-client");
    expect(KV.puts).toEqual([]);
  });

  it("warns when the redirect host is not a known MCP client", async () => {
    const { env } = makeEnv({
      oauth: makeOAuthProvider(authRequest({ redirectUri: "https://attacker.example/collect" })),
    });
    const c = await getConsent(createOAuthHandler(TEST_PROVIDER), env);
    expect(c.res.status).toBe(200);
    expect(c.html).toContain("Warning:");
    expect(c.html).toContain("<strong>attacker.example</strong>");
  });
});

describe("POST /authorize (consent submission, F-2 / F-15 / F-20)", () => {
  it("400 without the consent cookie (cross-site auto-submit), with a wrong cookie, or with no token", async () => {
    const { env, KV } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, env);
    const noCookie = await postConsent(app, env, { consent_token: c.token, action: "approve" });
    expect(noCookie.status).toBe(400);
    expect(await noCookie.text()).toBe(
      "Consent expired or invalid. Start the connection again from your MCP client.",
    );
    const wrong = await postConsent(app, env, { consent_token: c.token, action: "approve" }, `${c.cookieName}=not-the-nonce`);
    expect(wrong.status).toBe(400);
    const noToken = await postConsent(app, env, { action: "approve" }, `${c.cookieName}=${c.cookieValue}`);
    expect(noToken.status).toBe(400);
    const tampered = await postConsent(app, env, { consent_token: c.token + "x", action: "approve" }, `${c.cookieName}=${c.cookieValue}`);
    expect(tampered.status).toBe(400);
    expect(KV.puts).toEqual([]);
  });

  it("400 once the token has expired (300 s)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-08T00:00:00Z"));
    const { env } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, env);
    vi.setSystemTime(new Date("2026-10-08T00:05:00Z"));
    const res = await postConsent(app, env, { consent_token: c.token, action: "approve" }, `${c.cookieName}=${c.cookieValue}`);
    expect(res.status).toBe(400);
  });

  it("a token signed under a different COOKIE_ENCRYPTION_KEY is refused", async () => {
    const a = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, a.env);
    const b = makeEnv({ extra: { COOKIE_ENCRYPTION_KEY: "z".repeat(32) } });
    const res = await postConsent(app, b.env, { consent_token: c.token, action: "approve" }, `${c.cookieName}=${c.cookieValue}`);
    expect(res.status).toBe(400);
  });

  it("is single-use: a replayed token is refused and the marker carries a 600 s TTL", async () => {
    const { env, KV } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, env);
    const cookie = `${c.cookieName}=${c.cookieValue}`;
    const first = await postConsent(app, env, { consent_token: c.token, action: "approve" }, cookie);
    expect(first.status).toBe(303);
    const id = c.cookieName.slice("__Host-cm-consent-".length);
    expect(KV.data.get(`consent-used:${id}`)).toEqual({ value: "1", opts: { expirationTtl: 600 } });
    const replay = await postConsent(app, env, { consent_token: c.token, action: "approve" }, cookie);
    expect(replay.status).toBe(400);
    expect(setCookies(replay)).toContain(`${c.cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
    expect([...KV.data.keys()].filter((k) => k.startsWith("auth-state:"))).toHaveLength(1);
  });

  it("deny → 303 to the client redirect with error=access_denied and state; no state stashed", async () => {
    const { env, KV } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, env);
    const res = await postConsent(app, env, { consent_token: c.token, action: "deny" }, `${c.cookieName}=${c.cookieValue}`);
    expect(res.status).toBe(303);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe(CLIENT_REDIRECT);
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(loc.searchParams.get("state")).toBe("client-state");
    expect(setCookies(res)).toEqual([`${c.cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`]);
    expect([...KV.data.keys()].some((k) => k.startsWith("auth-state:"))).toBe(false);
  });

  it("an unknown action is refused without consuming the token", async () => {
    const { env } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const c = await getConsent(app, env);
    const cookie = `${c.cookieName}=${c.cookieValue}`;
    expect((await postConsent(app, env, { consent_token: c.token, action: "maybe" }, cookie)).status).toBe(400);
    expect((await postConsent(app, env, { consent_token: c.token, action: "approve" }, cookie)).status).toBe(303);
  });

  it("approve → 303 upstream with the required params, a Lax binding cookie and a stash holding bindingHash", async () => {
    const { env, KV } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const flow = await approveFlow(app, env);
    expect(flow.res.status).toBe(303);
    const url = flow.upstream;
    expect(url.origin + url.pathname).toBe(TEST_PROVIDER.oauth.authorizeUrl);
    expect(url.searchParams.get("client_id")).toBe("test-cid");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid offline_access test.read");
    expect(url.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/callback`);
    expect(flow.state).toMatch(/^[0-9a-f-]{36}$/);
    // Both the consent clear and the binding cookie are sent.
    const cookies = setCookies(flow.res);
    expect(cookies).toContain(`${flow.consent.cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
    expect(flow.authCookie).toMatch(
      new RegExp(`^__Host-cm-auth-${flow.state}=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$`),
    );
    const entry = KV.data.get(`auth-state:${flow.state}`)!;
    expect(entry.opts).toEqual({ expirationTtl: 600 });
    const stash = JSON.parse(entry.value) as { oauthReqInfo: Record<string, unknown>; bindingHash: string };
    expect(stash.oauthReqInfo).toEqual(authRequest());
    const nonce = flow.authCookiePair.split("=")[1]!;
    expect(stash.bindingHash).toBe(await sha256Base64Url(nonce));
    // The raw nonce itself is never stored.
    expect(entry.value).not.toContain(nonce);
  });

  it("default upstream PKCE (no oauth.pkce field) adds code_challenge S256 and stashes codeVerifier", async () => {
    const { env, KV } = makeEnv();
    const flow = await approveFlow(createOAuthHandler(TEST_PROVIDER), env);
    const challenge = flow.upstream.searchParams.get("code_challenge");
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(flow.upstream.searchParams.get("code_challenge_method")).toBe("S256");
    const parsed = JSON.parse(KV.data.get(`auth-state:${flow.state}`)!.value) as { codeVerifier?: string };
    expect(parsed.codeVerifier).toHaveLength(43);
    expect(await sha256Base64Url(parsed.codeVerifier!)).toBe(challenge);
  });

  it('oauth.pkce: "none" omits upstream PKCE params and stashes no codeVerifier', async () => {
    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      oauth: { ...TEST_PROVIDER.oauth, pkce: "none" },
    };
    const { env, KV } = makeEnv();
    const flow = await approveFlow(createOAuthHandler(provider), env);
    expect(flow.upstream.searchParams.get("code_challenge")).toBeNull();
    expect(flow.upstream.searchParams.get("code_challenge_method")).toBeNull();
    const parsed = JSON.parse(KV.data.get(`auth-state:${flow.state}`)!.value) as { codeVerifier?: string; bindingHash: string };
    expect(parsed.codeVerifier).toBeUndefined();
    expect(typeof parsed.bindingHash).toBe("string");
  });

  it("merges provider.oauth.extraAuthorizeParams into the upstream URL alongside base params", async () => {
    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      oauth: {
        ...TEST_PROVIDER.oauth,
        extraAuthorizeParams: { access_type: "offline", prompt: "consent", include_granted_scopes: "true" },
      },
    };
    const { env } = makeEnv();
    const { upstream } = await approveFlow(createOAuthHandler(provider), env);
    expect(upstream.searchParams.get("access_type")).toBe("offline");
    expect(upstream.searchParams.get("prompt")).toBe("consent");
    expect(upstream.searchParams.get("include_granted_scopes")).toBe("true");
    expect(upstream.searchParams.get("client_id")).toBe("test-cid");
    expect(upstream.searchParams.get("response_type")).toBe("code");
    expect(upstream.searchParams.get("scope")).toBe("openid offline_access test.read");
    expect(upstream.searchParams.get("redirect_uri")).toBeTruthy();
    expect(upstream.searchParams.get("state")).toBeTruthy();
  });

  it("does not let extraAuthorizeParams clobber protected base OAuth2 params", async () => {
    const provider: ApiProvider<TestProps> = {
      ...TEST_PROVIDER,
      oauth: {
        ...TEST_PROVIDER.oauth,
        extraAuthorizeParams: {
          state: "ATTACKER-CONTROLLED",
          client_id: "OTHER-CLIENT",
          scope: "evil",
          access_type: "offline",
        },
      },
    };
    const { env, KV } = makeEnv();
    const { upstream, state } = await approveFlow(createOAuthHandler(provider), env);
    expect(upstream.searchParams.get("client_id")).toBe("test-cid");
    expect(upstream.searchParams.get("scope")).toBe("openid offline_access test.read");
    expect(state).not.toBe("ATTACKER-CONTROLLED");
    expect(KV.data.has(`auth-state:${state}`)).toBe(true);
    expect(KV.data.has("auth-state:ATTACKER-CONTROLLED")).toBe(false);
    expect(upstream.searchParams.get("access_type")).toBe("offline");
  });
});

describe("/callback (browser binding F-15, props F-23, logging F-21)", () => {
  it("400 without the binding cookie or with a wrong one — and the stash is retained", async () => {
    const { env, KV, oauth } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    const fetchSpy = stubUpstreamOk();
    const { state, authCookiePair } = await approveFlow(app, env);
    const none = await callback(app, env, state);
    expect(none.status).toBe(400);
    expect(await none.text()).toBe("State expired or invalid");
    const wrong = await callback(app, env, state, `__Host-cm-auth-${state}=forged-value`);
    expect(wrong.status).toBe(400);
    const otherFlowCookie = await callback(app, env, state, `__Host-cm-auth-00000000-0000-0000-0000-000000000000=${authCookiePair.split("=")[1]}`);
    expect(otherFlowCookie.status).toBe(400);
    expect(KV.data.has(`auth-state:${state}`)).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(oauth.completeSpy).not.toHaveBeenCalled();
    // The legitimate browser still completes afterwards.
    expect((await callback(app, env, state, authCookiePair)).status).toBe(302);
  });

  it("400 for a state that is not UUID-shaped, without a KV read", async () => {
    const { env } = makeEnv();
    const get = vi.spyOn(env.OAUTH_KV, "get");
    const res = await callback(createOAuthHandler(TEST_PROVIDER), env, "STATE-XYZ", "__Host-cm-auth-STATE-XYZ=x");
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("State expired or invalid");
    expect(get).not.toHaveBeenCalled();
  });

  it("refuses legacy stash shapes (no envelope, or no bindingHash)", async () => {
    const { env, KV } = makeEnv();
    const app = createOAuthHandler(TEST_PROVIDER);
    stubUpstreamOk();
    const s1 = "11111111-1111-4111-8111-111111111111";
    const s2 = "22222222-2222-4222-8222-222222222222";
    await KV.put(`auth-state:${s1}`, JSON.stringify({ clientId: "claude-client", scope: ["mcp"] }));
    await KV.put(`auth-state:${s2}`, JSON.stringify({ oauthReqInfo: authRequest(), codeVerifier: "v" }));
    expect((await callback(app, env, s1, `__Host-cm-auth-${s1}=x`)).status).toBe(400);
    expect((await callback(app, env, s2, `__Host-cm-auth-${s2}=x`)).status).toBe(400);
  });

  it("with the cookie: exchanges code (with code_verifier), calls userinfo, runs the hook, completes, clears the cookie", async () => {
    const { env, KV, oauth } = makeEnv();
    let tokenBody = "";
    stubUpstreamOk({ onToken: (b) => { tokenBody = b; } });
    const completeAuthHook = vi.fn(async () => ({ tenantId: "tenant-from-hook" }));
    const app = createOAuthHandler({ ...TEST_PROVIDER, completeAuthHook });
    const { state, authCookiePair } = await approveFlow(app, env);
    const verifier = (JSON.parse(KV.data.get(`auth-state:${state}`)!.value) as { codeVerifier: string }).codeVerifier;

    const res = await callback(app, env, state, authCookiePair);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://claude.ai/return?ok=1&user=subject-42");
    expect(setCookies(res)).toEqual([`__Host-cm-auth-${state}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`]);
    expect(KV.data.has(`auth-state:${state}`)).toBe(false);

    const sent = new URLSearchParams(tokenBody);
    expect(sent.get("code")).toBe("CODE-A");
    expect(sent.get("code_verifier")).toBe(verifier);
    expect(sent.get("redirect_uri")).toBe(`${ORIGIN}/callback`);
    expect(completeAuthHook).toHaveBeenCalledTimes(1);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((completeAuthHook.mock.calls[0] as any)[0].tokens.access_token).toBe("AT-fresh");
    expect(oauth.completeSpy).toHaveBeenCalledTimes(1);
    const args = oauth.completeSpy.mock.calls[0]![0];
    expect(args.request).toEqual(authRequest());
    expect(args.userId).toBe("subject-42");
    expect(args.scope).toEqual(["mcp"]);
    const props = args.props as TestProps;
    expect(props).toEqual({
      refreshToken: "RT-fresh", userId: "subject-42", email: "u@example.com", tenantId: "tenant-from-hook",
    });
    // Replay after completion is refused.
    expect((await callback(app, env, state, authCookiePair)).status).toBe(400);
  });

  it('oauth.pkce: "none" sends no code_verifier', async () => {
    const { env } = makeEnv();
    let tokenBody = "";
    stubUpstreamOk({ onToken: (b) => { tokenBody = b; } });
    const app = createOAuthHandler({ ...TEST_PROVIDER, oauth: { ...TEST_PROVIDER.oauth, pkce: "none" } });
    const { state, authCookiePair } = await approveFlow(app, env);
    expect((await callback(app, env, state, authCookiePair)).status).toBe(302);
    expect(new URLSearchParams(tokenBody).has("code_verifier")).toBe(false);
  });

  it("F-23: a hook cannot override upstream userId/refreshToken/email, but can add fields", async () => {
    const { env, oauth } = makeEnv();
    stubUpstreamOk({ userinfo: { sub: "real-sub", email: "real@tenant", name: "Real Name" } });
    const app = createOAuthHandler({
      ...TEST_PROVIDER,
      completeAuthHook: async () => ({
        userId: "hook-sub", refreshToken: "RT-from-hook", email: "hook@tenant", tenantId: "t-1",
      }),
    });
    const { state, authCookiePair } = await approveFlow(app, env);
    expect((await callback(app, env, state, authCookiePair)).status).toBe(302);
    const args = oauth.completeSpy.mock.calls[0]![0];
    expect(args.userId).toBe("real-sub");
    expect(args.metadata).toEqual({ label: "real@tenant" });
    expect(args.props).toEqual({
      userId: "real-sub", refreshToken: "RT-fresh", email: "real@tenant", name: "Real Name", tenantId: "t-1",
    });
  });

  it("F-23: a hook may supply userId when userinfo has no string sub", async () => {
    const { env, oauth } = makeEnv();
    stubUpstreamOk({ userinfo: { email: "x@tenant" } });
    const app = createOAuthHandler({
      ...TEST_PROVIDER,
      completeAuthHook: async () => ({ userId: "hook-sub" }),
    });
    const { state, authCookiePair } = await approveFlow(app, env);
    expect((await callback(app, env, state, authCookiePair)).status).toBe(302);
    const args = oauth.completeSpy.mock.calls[0]![0];
    expect(args.userId).toBe("hook-sub");
    expect((args.props as TestProps).refreshToken).toBe("RT-fresh");
  });

  it("propagates completeAuthHook errors as 502", async () => {
    const { env } = makeEnv();
    stubUpstreamOk();
    const app = createOAuthHandler({
      ...TEST_PROVIDER,
      completeAuthHook: async () => { throw new Error("hook says no"); },
    });
    const { state, authCookiePair } = await approveFlow(app, env);
    const res = await callback(app, env, state, authCookiePair);
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("hook says no");
  });

  async function failingExchange(body: string, extra?: Record<string, string>) {
    const { env, oauth } = makeEnv(extra ? { extra } : {});
    const app = createOAuthHandler(TEST_PROVIDER);
    const { state, authCookiePair } = await approveFlow(app, env);
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(async () => new Response(body, { status: 400 })));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await callback(app, env, state, authCookiePair);
    const logged = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
    return { res, logged, oauth };
  }

  it("token-exchange failure → 502; the log carries status + error code, not the body (default)", async () => {
    const body = '{"error":"invalid_grant","error_description":"secret-ish upstream text"}';
    const { res, logged, oauth } = await failingExchange(body);
    expect(res.status).toBe(502);
    expect(await res.text()).toBe("Test Provider token exchange failed: 400");
    expect(logged).toBe("Test Provider token exchange failed: status=400 error=invalid_grant");
    expect(oauth.completeSpy).not.toHaveBeenCalled();
  });

  it("a non-JSON failure body logs error=unknown", async () => {
    const { logged } = await failingExchange("bad");
    expect(logged).toBe("Test Provider token exchange failed: status=400 error=unknown");
  });

  it("ALLOW_PII_IN_LOGS=true appends the body, sliced to 500 chars", async () => {
    const big = `{"error":"invalid_grant","pad":"${"E".repeat(2000)}"}`;
    const { logged } = await failingExchange(big, { ALLOW_PII_IN_LOGS: "true" });
    expect(logged).toBe(`Test Provider token exchange failed: status=400 error=invalid_grant body=${big.slice(0, 500)}`);
  });

  it("an upstream PKCE rejection → actionable 502; the log names the remedy, gated like the generic branch", async () => {
    const body = '{"error":"invalid_request","error_description":"code_verifier required"}';
    const { res, logged } = await failingExchange(body);
    expect(res.status).toBe(502);
    const text = await res.text();
    expect(text).toContain("upstream rejected PKCE");
    expect(text).toContain('oauth.pkce: "none"');
    expect(logged).toContain("rejected PKCE");
    expect(logged).toContain('oauth.pkce: "none"');
    expect(logged).toContain("status=400 error=invalid_request");
    expect(logged).not.toContain("code_verifier required");
    const pii = await failingExchange(body, { ALLOW_PII_IN_LOGS: "true" });
    expect(pii.logged).toContain(`body=${body}`);
  });
});
