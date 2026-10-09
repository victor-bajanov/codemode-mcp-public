// A2 — /callback state token: replay, TTL, race, and browser binding.
//
// Status: FIXED (F-15) — the approving POST /authorize binds the flow to the
// browser with a `__Host-cm-auth-<state>` cookie whose SHA-256 is stashed with
// the state; /callback refuses (without consuming the stash) unless it matches.
//
// Against the real `createOAuthHandler` with a fake KV, exactly like
// oauth-handler.test.ts does; the flow is driven through the consent page
// (GET /authorize → POST /authorize approve) before /callback.
//
// Findings:
//   - REFUTED: a consumed state cannot be replayed (KV entry deleted).
//   - FIXED (F-15, was CONFIRMED Low): get-then-delete on the `auth-state:`
//     key is still not atomic, but a /callback without the binding cookie no
//     longer reaches it: two concurrent requests carrying the state but not
//     the cookie are both refused before the upstream token endpoint is
//     called. Accepted residual: the SAME browser double-submitting /callback
//     within KV propagation can still pass twice; the upstream's single-use
//     code makes the second exchange fail.
//   - FIXED (F-15, was STATIC): the state is no longer the only binding — a
//     different browser holding the state string cannot complete the flow.
//   - REFUTED: state entries are written with the documented 600 s TTL.

import { describe, it, expect, afterEach, vi } from "vitest";
import { createOAuthHandler } from "../../oauth-handler";
import { POC_PROVIDER, UPSTREAM_TOKEN_URL, UPSTREAM_USERINFO_URL } from "./_harness-oauth-worker";

function makeKV() {
  const data = new Map<string, string>();
  return {
    data,
    async get(k: string) { return data.get(k) ?? null; },
    async put(k: string, v: string) { data.set(k, v); },
    async delete(k: string) { data.delete(k); },
  } as unknown as KVNamespace & { data: Map<string, string> };
}

function makeEnv(kv: KVNamespace, completeSpy: ReturnType<typeof vi.fn>) {
  return {
    OAUTH_PROVIDER: {
      parseAuthRequest: vi.fn(async () => ({
        clientId: "c", redirectUri: "https://claude.ai/cb", scope: ["mcp"], state: "s",
        responseType: "code", codeChallenge: "mcp-client-challenge", codeChallengeMethod: "S256",
      })),
      lookupClient: vi.fn(async () => ({ clientId: "c", clientName: "Claude", redirectUris: ["https://claude.ai/cb"] })),
      completeAuthorization: completeSpy,
    } as never,
    OAUTH_KV: kv,
    TEST_CLIENT_ID: "cid",
    TEST_CLIENT_SECRET: "csec",
    COOKIE_ENCRYPTION_KEY: "x".repeat(32),
  };
}

type App = ReturnType<typeof createOAuthHandler>;

/** GET /authorize → POST approve; returns the state and its binding cookie pair. */
async function approve(app: App, env: ReturnType<typeof makeEnv>) {
  const consent = await app.request("https://w.test/authorize?client_id=c", undefined, env);
  const html = await consent.text();
  const token = /name="consent_token" value="([^"]+)"/.exec(html)![1]!;
  const consentCookie = consent.headers.getSetCookie()[0]!.split(";")[0]!;
  const res = await app.request(
    "https://w.test/authorize",
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie: consentCookie },
      body: new URLSearchParams({ consent_token: token, action: "approve" }).toString(),
    },
    env,
  );
  const state = new URL(res.headers.get("location")!).searchParams.get("state")!;
  const authCookie = res.headers.getSetCookie().find((c) => c.startsWith(`__Host-cm-auth-${state}=`)) ?? null;
  return { consent, res, state, authCookie, authCookiePair: authCookie?.split(";")[0] ?? "" };
}

function stubUpstream() {
  const tokenCalls: string[] = [];
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async (input: RequestInfo | URL, init?: RequestInit) => {
    const u = typeof input === "string" ? input : input.toString();
    if (u.startsWith(UPSTREAM_TOKEN_URL)) {
      tokenCalls.push(String(init?.body));
      return new Response(JSON.stringify({ access_token: "AT", refresh_token: "RT", expires_in: 3600 }), { status: 200 });
    }
    if (u.startsWith(UPSTREAM_USERINFO_URL)) {
      return new Response(JSON.stringify({ sub: "sub-1", email: "a@b" }), { status: 200 });
    }
    throw new Error("unexpected " + u);
  }));
  return tokenCalls;
}

describe("A2 /callback state handling", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("REFUTED: a state token is single-use — replay after completion is rejected", async () => {
    const kv = makeKV();
    const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb?code=x" }));
    const env = makeEnv(kv, completeSpy);
    const app = createOAuthHandler(POC_PROVIDER);
    stubUpstream();

    const { state, authCookiePair } = await approve(app, env);
    const headers = { headers: { cookie: authCookiePair } };

    const first = await app.request(`https://w.test/callback?code=UPC&state=${state}`, headers, env);
    expect(first.status).toBe(302);
    const replay = await app.request(`https://w.test/callback?code=UPC&state=${state}`, headers, env);
    expect(replay.status).toBe(400);
    expect(await replay.text()).toBe("State expired or invalid");
    expect(completeSpy).toHaveBeenCalledTimes(1);
  });

  it("FIXED (F-15): two concurrent /callback requests without the binding cookie are both refused before any upstream call", async () => {
    const kv = makeKV();
    const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb?code=x" }));
    const env = makeEnv(kv, completeSpy);
    const app = createOAuthHandler(POC_PROVIDER);
    const tokenCalls = stubUpstream();

    const { state, authCookiePair } = await approve(app, env);

    const [r1, r2] = await Promise.all([
      app.request(`https://w.test/callback?code=UPC&state=${state}`, undefined, env),
      app.request(`https://w.test/callback?code=UPC&state=${state}`, undefined, env),
    ]);
    expect(r1.status).toBe(400);
    expect(r2.status).toBe(400);
    expect(tokenCalls).toHaveLength(0);
    expect(completeSpy).not.toHaveBeenCalled();
    // The stash was not consumed, so the legitimate browser still completes.
    expect(kv.data.has(`auth-state:${state}`)).toBe(true);
    const legit = await app.request(`https://w.test/callback?code=UPC&state=${state}`, { headers: { cookie: authCookiePair } }, env);
    expect(legit.status).toBe(302);
    expect(tokenCalls).toHaveLength(1);
    expect(completeSpy).toHaveBeenCalledTimes(1);
    // Accepted residual (not exercised): the same browser double-submitting
    // within KV propagation can still race; the upstream's single-use code
    // makes the second exchange fail.
  });

  it("FIXED (F-15): the approving POST binds the state to the browser — a different browser cannot complete the flow", async () => {
    const kv = makeKV();
    const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb?code=x" }));
    const env = makeEnv(kv, completeSpy);
    const app = createOAuthHandler(POC_PROVIDER);
    stubUpstream();

    const { state, authCookie, authCookiePair } = await approve(app, env);
    expect(authCookie).toMatch(new RegExp(`^__Host-cm-auth-${state}=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$`));
    // A different "browser" (no cookie, or its own cookie value) holding the state.
    for (const cookie of [undefined, `__Host-cm-auth-${state}=someone-elses-value`]) {
      const other = await app.request(
        `https://w.test/callback?code=UPC&state=${state}`,
        { headers: { "user-agent": "someone-else", ...(cookie ? { cookie } : {}) } },
        env,
      );
      expect(other.status).toBe(400);
    }
    expect(completeSpy).not.toHaveBeenCalled();
    const mine = await app.request(`https://w.test/callback?code=UPC&state=${state}`, { headers: { cookie: authCookiePair } }, env);
    expect(mine.status).toBe(302);
  });

  it("REFUTED: state entries are written with the documented 600 s TTL", async () => {
    const puts: Array<{ k: string; opts: unknown }> = [];
    const kv = {
      async get() { return null; },
      async put(k: string, _v: string, opts: unknown) { puts.push({ k, opts }); },
      async delete() {},
    } as unknown as KVNamespace;
    const env = makeEnv(kv, vi.fn());
    const app = createOAuthHandler(POC_PROVIDER);
    await approve(app, env);
    // GET /authorize writes nothing; the approving POST writes the single-use
    // consent marker and the state stash, both with a 600 s TTL.
    expect(puts).toHaveLength(2);
    expect(puts[0]!.k.startsWith("consent-used:")).toBe(true);
    expect(puts[0]!.opts).toEqual({ expirationTtl: 600 });
    expect(puts[1]!.k.startsWith("auth-state:")).toBe(true);
    expect(puts[1]!.opts).toEqual({ expirationTtl: 600 });
  });
});
