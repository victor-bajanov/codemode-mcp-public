// A1 — Attacker-registered client + consent-less /authorize = grant theft.
//
// Status: FIXED (F-2) — /authorize now requires PKCE S256 and shows a signed,
// cookie-bound, single-use consent page; /register refuses non-loopback http://.
//
// Originally CONFIRMED. Static-only component: the Cloudflare Access gate on
// /authorize (which covers both GET and the consent POST) is not reproducible
// here; the POC starts from the point where the operator's browser (already
// admitted by Access) follows a link.
//
// The original chain, all against the REAL library + REAL scaffold handler:
//   1. Unauthenticated POST /register with an attacker redirect_uri and
//      token_endpoint_auth_method "none" (public client, no secret) → 201.
//   2. Operator (Access-authenticated) is lured to
//        /authorize?client_id=<attacker>&redirect_uri=<attacker>&response_type=code
//      The scaffold validated redirect_uri ONLY against the attacker's own
//      registration, showed NO consent/approval page, and redirected straight
//      to the upstream IdP.
//   3. Upstream returned to /callback; the scaffold minted the grant and 302'd
//      the MCP auth code to the ATTACKER's redirect_uri.
//   4. Attacker POSTed /token (no client secret, no PKCE needed) → MCP tokens.
//   5. Attacker's bearer on /mcp resolved to the OPERATOR's props.
//
// What now holds (same attack payloads):
//   - Without PKCE, step 2 is refused with 400 (allowPlainPKCE: false plus the
//     scaffold's own code_challenge requirement).
//   - With PKCE, step 2's first response is a 200 consent page naming the
//     attacker host with a warning; no state is minted and nothing goes
//     upstream until the operator explicitly approves.
//   - A cross-site auto-submitted approval carries no SameSite=Strict consent
//     cookie and is refused.
//   - A grant the operator does approve expires 90 days after authorisation
//     (refreshTokenTTL) instead of never.
//   - http:// redirect URIs on non-loopback hosts are refused at /register.

import { describe, it, expect, afterEach } from "vitest";
import { vi } from "vitest";
import {
  makeWorker,
  stubUpstream,
  registerClient,
  runBrowserLeg,
  exchangeCode,
  callMcp,
  WORKER_ORIGIN,
} from "./_harness-oauth-worker";
import { MCP_REFRESH_TOKEN_TTL_SECONDS } from "../../oauth-provider-options";

const ATTACKER_REDIRECT = "https://attacker.example/collect";

describe("A1 attacker-registered client obtains the operator's grant", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("FIXED (F-2): register → lure to /authorize now meets PKCE, a consent page and a cookie-bound approval", async () => {
    const w = makeWorker();
    const upstream = stubUpstream({ sub: "operator-sub-123", email: "operator@tenant.example", refresh_token: "OPERATOR-UPSTREAM-RT" });

    // 1. Attacker registers a public client (https, so the redirect rule allows it).
    const reg = await registerClient(w, {
      client_name: "Claude",
      redirect_uris: [ATTACKER_REDIRECT],
      token_endpoint_auth_method: "none",
    }, "198.51.100.7");
    expect(reg.res.status).toBe(201);
    const attackerClientId = reg.json.client_id as string;
    expect(reg.json.client_secret).toBeUndefined();

    const lure = {
      client_id: attackerClientId,
      redirect_uri: ATTACKER_REDIRECT,
      response_type: "code",
      state: "attacker-state",
    };

    // 2a. The original crafted link (no code_challenge) is refused outright.
    const noPkce = await runBrowserLeg(w, lure, undefined, { omitPkce: true });
    expect(noPkce.consentRes.status).toBe(400);
    expect(await noPkce.consentRes.text()).toMatch(/Invalid authorization request: .*S256/);

    // 2b. With PKCE the first response is the consent page, not an upstream redirect.
    //     Simulate a cross-site auto-submit: the approval carries no consent cookie.
    const autoSubmit = await runBrowserLeg(w, lure, undefined, { approveCookie: null });
    expect(autoSubmit.consentRes.status).toBe(200);
    expect(autoSubmit.consentRes.headers.get("location")).toBeNull();
    expect(autoSubmit.consentRes.headers.get("x-frame-options")).toBe("DENY");
    expect(autoSubmit.consentHtml).toContain("<strong>attacker.example</strong>");
    expect(autoSubmit.consentHtml).toContain("Warning:");
    expect(autoSubmit.approveRes!.status).toBe(400);
    expect([...w.kv.data.keys()].some((k) => k.startsWith("auth-state:"))).toBe(false);
    expect(upstream.calls).toHaveLength(0);

    // The token cannot be posted from another browser either: replaying it with
    // a cookie value of the attacker's choosing fails the nonce check.
    const forged = await w.fetchWorker(
      `${WORKER_ORIGIN}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ consent_token: autoSubmit.consentToken!, action: "approve" }).toString(),
      },
      undefined,
      { Cookie: `${autoSubmit.consentCookie!.split("=")[0]}=attacker-chosen` },
    );
    expect(forged.status).toBe(400);

    // 3. Only an explicit operator approval (despite the warning) proceeds, and
    //    the resulting grant is no longer permanent.
    const approved = await runBrowserLeg(w, lure);
    expect(approved.approveRes!.status).toBe(303);
    expect(approved.callbackRes!.status).toBe(302);
    expect(approved.finalLocation!.origin).toBe("https://attacker.example");
    const mcpCode = approved.finalLocation!.searchParams.get("code")!;

    // 4. The code is bound to the PKCE challenge: without the verifier it is useless.
    const noVerifier = await exchangeCode(w, {
      grant_type: "authorization_code",
      code: mcpCode,
      client_id: attackerClientId,
      redirect_uri: ATTACKER_REDIRECT,
    }, "198.51.100.7");
    expect(noVerifier.res.status).toBe(400);
    expect(noVerifier.json.error_description).toBe("code_verifier is required for PKCE");

    const before = Math.floor(Date.now() / 1000);
    const tok = await exchangeCode(w, {
      grant_type: "authorization_code",
      code: (await runBrowserLeg(w, lure)).finalLocation!.searchParams.get("code")!,
      client_id: attackerClientId,
      redirect_uri: ATTACKER_REDIRECT,
      code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier",
    }, "198.51.100.7");
    expect(tok.res.status).toBe(400);
    expect(tok.json.error_description).toBe("Invalid PKCE code_verifier");

    const legit = await runBrowserLeg(w, lure);
    const ok = await exchangeCode(w, {
      grant_type: "authorization_code",
      code: legit.finalLocation!.searchParams.get("code")!,
      client_id: attackerClientId,
      redirect_uri: ATTACKER_REDIRECT,
      code_verifier: legit.codeVerifier!,
    }, "198.51.100.7");
    expect(ok.res.status).toBe(200);
    const grantKey = [...w.kv.data.keys()].find((k) => k.startsWith("grant:"))!;
    const expiresAt = JSON.parse(w.kv.data.get(grantKey)!.value).expiresAt as number;
    expect(expiresAt - before).toBeGreaterThanOrEqual(MCP_REFRESH_TOKEN_TTL_SECONDS);
    expect(expiresAt - before).toBeLessThanOrEqual(MCP_REFRESH_TOKEN_TTL_SECONDS + 5);
    expect(MCP_REFRESH_TOKEN_TTL_SECONDS).toBe(90 * 24 * 60 * 60);
    expect((await callMcp(w, ok.json.access_token as string)).res.status).toBe(200);
  });

  it("FIXED (F-2): registration refuses plaintext http:// redirect targets on non-loopback hosts", async () => {
    const w = makeWorker();
    const reg = await registerClient(w, {
      redirect_uris: ["http://attacker.example/collect"],
      token_endpoint_auth_method: "none",
    });
    expect(reg.res.status).toBe(400);
    expect(reg.json.error).toBe("invalid_redirect_uri");
    expect(reg.res.headers.get("cache-control")).toBe("no-store");
    expect([...w.kv.data.keys()].some((k) => k.startsWith("client:"))).toBe(false);
    // Loopback http:// (Claude Code, MCP Inspector) is still accepted.
    for (const uri of ["http://localhost:6274/oauth/callback", "http://127.0.0.1:33418/cb"]) {
      const ok = await registerClient(w, { redirect_uris: [uri], token_endpoint_auth_method: "none" });
      expect(ok.res.status).toBe(201);
    }
  });

  it("REFUTED (control holds): /authorize rejects a redirect_uri not registered for the client", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "s", email: "e", refresh_token: "r" });
    const reg = await registerClient(w, {
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      token_endpoint_auth_method: "none",
    });
    const leg = await runBrowserLeg(w, {
      client_id: reg.json.client_id as string,
      redirect_uri: ATTACKER_REDIRECT,
      response_type: "code",
    });
    // parseAuthRequest throws → 400 before any consent page; no state is
    // minted, no upstream redirect.
    expect(leg.consentRes.status).toBe(400);
    expect(leg.approveRes).toBeNull();
    expect([...w.kv.data.keys()].some((k) => k.startsWith("auth-state:"))).toBe(false);
  });

  it("REFUTED (control holds): the auth code cannot be exchanged by a different client", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "s", email: "e", refresh_token: "r" });
    const legit = await registerClient(w, {
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      token_endpoint_auth_method: "none",
    });
    const other = await registerClient(w, {
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      token_endpoint_auth_method: "none",
    });
    const leg = await runBrowserLeg(w, {
      client_id: legit.json.client_id as string,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      response_type: "code",
    });
    const code = leg.finalLocation!.searchParams.get("code")!;
    const tok = await exchangeCode(w, {
      grant_type: "authorization_code",
      code,
      client_id: other.json.client_id as string,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      code_verifier: leg.codeVerifier!,
    });
    expect(tok.res.status).toBe(400);
    expect(tok.json.error).toBe("invalid_grant");
  });
});
