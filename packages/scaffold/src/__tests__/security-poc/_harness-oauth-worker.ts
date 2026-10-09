// Shared harness for the A-series (token handling) security POCs.
//
// Builds the SAME worker composition that `setup-provider.ts` builds — the real
// `@cloudflare/workers-oauth-provider` OAuthProvider (configured with the real
// `MCP_OAUTH_PROVIDER_OPTIONS`: PKCE S256 only, 90-day refresh-token TTL)
// wrapping the real scaffold `createOAuthHandler` Hono app, with the real
// `enforceOAuthHardening` wrapper in front — but with:
//   - an in-memory KV namespace (so the tests can inspect what was stored),
//   - a stub `apiHandler` in place of `McpAgent.serve("/mcp")` that simply
//     echoes `ctx.props` (the decrypted grant props the library hands to the
//     MCP agent), so a test can prove what identity a bearer token resolves to,
//   - the upstream IdP (`/token`, `/userinfo`) stubbed via `vi.stubGlobal("fetch")`.
//
// Nothing here re-implements scaffold or library logic.

import { vi } from "vitest";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createOAuthHandler } from "../../oauth-handler";
import { enforceOAuthHardening, type HardeningConfig } from "../../oauth-hardening";
import { MCP_OAUTH_PROVIDER_OPTIONS } from "../../oauth-provider-options";
import { generateCodeVerifier, sha256Base64Url } from "../../pkce";
import type { ApiProvider } from "../../api-provider";

export interface PocProps extends Record<string, unknown> {
  refreshToken: string;
  userId: string;
  email?: string;
}

export const UPSTREAM_TOKEN_URL = "https://login.example.com/token";
export const UPSTREAM_USERINFO_URL = "https://login.example.com/userinfo";

export const POC_PROVIDER: ApiProvider<PocProps> = {
  name: "poc",
  displayName: "POC Provider",
  oauth: {
    authorizeUrl: "https://login.example.com/authorize",
    tokenUrl: UPSTREAM_TOKEN_URL,
    scopes: ["openid", "email", "offline_access"],
    clientIdSecretName: "TEST_CLIENT_ID",
    clientSecretSecretName: "TEST_CLIENT_SECRET",
    userInfoUrl: UPSTREAM_USERINFO_URL,
    extraAuthorizeParams: { access_type: "offline", prompt: "consent" },
  },
  spec: {} as never,
  surfaceReview: {},
  apiBaseUrl: "https://api.example.com",
  audit: { principalIdAccessor: (p) => p.userId },
};

export interface StoredKv {
  value: string;
  opts?: { expirationTtl?: number; expiration?: number };
}

/** In-memory KVNamespace covering every call the library + scaffold make. */
export function makeKV() {
  const data = new Map<string, StoredKv>();
  const kv = {
    data,
    async get(key: string, opts?: { type?: "json" | "text" } | "json" | "text") {
      const entry = data.get(key);
      if (!entry) return null;
      const type = typeof opts === "string" ? opts : opts?.type;
      return type === "json" ? JSON.parse(entry.value) : entry.value;
    },
    async put(key: string, value: string, opts?: StoredKv["opts"]) {
      data.set(key, { value, ...(opts ? { opts } : {}) });
    },
    async delete(key: string) {
      data.delete(key);
    },
    async list(opts: { prefix?: string; limit?: number; cursor?: string }) {
      const prefix = opts.prefix ?? "";
      const keys = [...data.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys, list_complete: true, cursor: undefined };
    },
  };
  return kv as unknown as KVNamespace & { data: Map<string, StoredKv> };
}

export const LOOSE_LIMITS: HardeningConfig = {
  register: { limit: 1000, windowSeconds: 300 },
  token: { limit: 1000, windowSeconds: 60 },
};

export function makeWorker(opts?: { limits?: HardeningConfig }) {
  const kv = makeKV();
  const authHandler = createOAuthHandler(POC_PROVIDER);
  // Stand-in for McpAgent.serve("/mcp"): echo the props the library decrypted
  // from the bearer token. This is exactly what the real McpAgent receives as
  // `this.props` (and what mcp-agent-factory uses to address the TokenBroker).
  const apiHandler = {
    async fetch(_req: Request, _env: unknown, ctx: { props?: unknown }) {
      return new Response(JSON.stringify({ props: ctx.props ?? null }), {
        headers: { "content-type": "application/json" },
      });
    },
  };
  const oauth = new OAuthProvider({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    apiHandler: apiHandler as any,
    ...MCP_OAUTH_PROVIDER_OPTIONS,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    defaultHandler: authHandler as any,
  });
  const env: Record<string, unknown> = {
    OAUTH_KV: kv,
    TEST_CLIENT_ID: "upstream-app-client-id",
    TEST_CLIENT_SECRET: "upstream-app-client-secret",
    COOKIE_ENCRYPTION_KEY: "x".repeat(32),
  };
  const ctx = { waitUntil() {}, passThroughOnException() {} };
  const limits = opts?.limits ?? LOOSE_LIMITS;

  async function fetchWorker(
    input: string | Request,
    init?: RequestInit,
    ip = "203.0.113.10",
    extraHeaders: Record<string, string> = {},
  ) {
    const req = new Request(input, init);
    req.headers.set("CF-Connecting-IP", ip);
    for (const [k, v] of Object.entries(extraHeaders)) req.headers.set(k, v);
    return enforceOAuthHardening(req, kv, limits, Date.now(), (r) =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (oauth as any).fetch(r, env, ctx),
    );
  }

  return { kv, env, oauth, fetchWorker };
}

export interface UpstreamUser {
  sub: string;
  email: string;
  refresh_token: string;
  access_token?: string;
}

/** Stub the upstream IdP. Records every call so tests can assert on them. */
export function stubUpstream(user: UpstreamUser) {
  const calls: Array<{ url: string; body: string | null }> = [];
  const spy = vi.fn<typeof fetch>(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, body: init?.body ? String(init.body) : null });
    if (url.startsWith(UPSTREAM_TOKEN_URL)) {
      return new Response(
        JSON.stringify({
          access_token: user.access_token ?? "UPSTREAM-AT",
          refresh_token: user.refresh_token,
          expires_in: 3600,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.startsWith(UPSTREAM_USERINFO_URL)) {
      return new Response(JSON.stringify({ sub: user.sub, email: user.email }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected upstream fetch: ${url}`);
  });
  vi.stubGlobal("fetch", spy);
  return { spy, calls };
}

export const WORKER_ORIGIN = "https://mcp.example.test";

/** Register a dynamic client the way an MCP client (or an attacker) would. */
export async function registerClient(
  w: ReturnType<typeof makeWorker>,
  metadata: Record<string, unknown>,
  ip?: string,
) {
  const res = await w.fetchWorker(
    `${WORKER_ORIGIN}/register`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(metadata),
    },
    ip,
  );
  const json = (await res.json()) as Record<string, unknown>;
  return { res, json };
}

export interface BrowserLegOpts {
  /** Send no code_challenge at all (the library then assumes `plain`). */
  omitPkce?: boolean;
  /** Override the `Cookie` header on the approving POST (default: the consent cookie). */
  approveCookie?: string | null;
  /** Override the `Cookie` header on /callback (default: the binding cookie). */
  callbackCookie?: string | null;
}

/** Pull the `name=value` pair of the first `Set-Cookie` whose name starts with `prefix`. */
export function cookiePair(res: Response, prefix: string): string | null {
  const c = res.headers.getSetCookie().find((v) => v.startsWith(prefix));
  return c ? c.split(";")[0]! : null;
}

/**
 * Drive the browser leg of the flow (as if Cloudflare Access had already
 * admitted the browser):
 *   1. GET /authorize with a fresh PKCE S256 pair (unless the caller supplied
 *      `code_challenge` or `opts.omitPkce`) → expect the 200 consent page;
 *   2. POST /authorize with the page's `consent_token`, `action=approve` and
 *      the consent cookie → expect a 303 to the upstream IdP;
 *   3. GET /callback with a fake upstream `code` and the
 *      `__Host-cm-auth-<state>` binding cookie.
 * Returns early (later fields null) when a step does not produce the expected
 * status. `codeVerifier` is what the MCP client must send to /token.
 */
export async function runBrowserLeg(
  w: ReturnType<typeof makeWorker>,
  authorizeQuery: Record<string, string>,
  upstreamCode = "UPSTREAM-CODE-1",
  opts: BrowserLegOpts = {},
) {
  const q = new URLSearchParams(authorizeQuery);
  let codeVerifier: string | null = null;
  if (!q.has("code_challenge") && !opts.omitPkce) {
    codeVerifier = generateCodeVerifier();
    q.set("code_challenge", await sha256Base64Url(codeVerifier));
    q.set("code_challenge_method", "S256");
  }
  const base = {
    consentHtml: null as string | null,
    consentToken: null as string | null,
    consentCookie: null as string | null,
    approveRes: null as Response | null,
    upstreamLocation: null as URL | null,
    authCookie: null as string | null,
    callbackRes: null as Response | null,
    finalLocation: null as URL | null,
    codeVerifier,
  };

  const consentRes = await w.fetchWorker(`${WORKER_ORIGIN}/authorize?${q.toString()}`);
  if (consentRes.status !== 200) return { ...base, consentRes };
  const consentHtml = await consentRes.text();
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(consentHtml)?.[1] ?? "";
  const consentCookie = cookiePair(consentRes, "__Host-cm-consent-");

  const approveCookie = opts.approveCookie === undefined ? consentCookie : opts.approveCookie;
  const approveRes = await w.fetchWorker(
    `${WORKER_ORIGIN}/authorize`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ consent_token: consentToken, action: "approve" }).toString(),
    },
    undefined,
    approveCookie ? { Cookie: approveCookie } : {},
  );
  const afterConsent = { ...base, consentRes, consentHtml, consentToken, consentCookie, approveRes };
  if (approveRes.status !== 303) return afterConsent;

  const upstreamLocation = new URL(approveRes.headers.get("location")!);
  const state = upstreamLocation.searchParams.get("state")!;
  const authCookie = cookiePair(approveRes, `__Host-cm-auth-${state}=`);
  const callbackCookie = opts.callbackCookie === undefined ? authCookie : opts.callbackCookie;
  const callbackRes = await w.fetchWorker(
    `${WORKER_ORIGIN}/callback?code=${encodeURIComponent(upstreamCode)}&state=${encodeURIComponent(state)}`,
    undefined,
    undefined,
    callbackCookie ? { Cookie: callbackCookie } : {},
  );
  const finalLocation =
    callbackRes.status === 302 ? new URL(callbackRes.headers.get("location")!) : null;
  return { ...afterConsent, upstreamLocation, authCookie, callbackRes, finalLocation };
}

export async function exchangeCode(
  w: ReturnType<typeof makeWorker>,
  form: Record<string, string>,
  ip?: string,
) {
  const res = await w.fetchWorker(
    `${WORKER_ORIGIN}/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form).toString(),
    },
    ip,
  );
  const json = (await res.json()) as Record<string, unknown>;
  return { res, json };
}

export async function callMcp(w: ReturnType<typeof makeWorker>, bearer: string) {
  const res = await w.fetchWorker(`${WORKER_ORIGIN}/mcp`, {
    method: "POST",
    headers: { Authorization: `Bearer ${bearer}`, "content-type": "application/json" },
    body: "{}",
  });
  const json = (await res.json()) as { props?: PocProps | null; error?: string };
  return { res, json };
}
