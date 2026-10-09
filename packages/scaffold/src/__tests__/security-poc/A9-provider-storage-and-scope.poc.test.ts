// A9 — What workers-oauth-provider actually stores, for how long, and what
// the MCP-side `scope` means in this design.
//
// Status: FIXED (F-22) — MCP grants and refresh tokens now expire 90 days
// after authorisation (refreshTokenTTL); MCP scope stays unenforced by design.
//
// Driven through the real library + real scaffold handler (harness), which now
// runs the consent page and MCP-client PKCE S256 on every flow.
//
//   REFUTED: no MCP access token, MCP refresh token, auth code, client secret
//            or upstream refresh token appears in plaintext anywhere in KV
//            (tokens are stored as SHA-256 ids; props are AES-GCM under a
//            per-grant key that is only ever wrapped under the token strings).
//   FIXED (F-22, was CONFIRMED Informational): the grant (and therefore the
//            MCP refresh token) had NO expiry. `refreshTokenTTL` is now set
//            (MCP_REFRESH_TOKEN_TTL_SECONDS, 90 days): the grant carries
//            `expiresAt` and its KV entry an `expiration`. The library fixes
//            this at authorisation time; refreshes do not extend it. Grants
//            minted before the change keep no expiry until re-authorised.
//            Access tokens: 3600 s, unchanged.
//   DESIGN (F-22, Informational, not a defect): `scope` on /authorize is
//            echoed into the grant verbatim and never consulted by the
//            scaffold — an MCP client can request "admin anything" and gets it
//            in the token response, but it changes nothing: authority comes
//            from the surface review, not the MCP scope (documented in
//            SECURITY.md).
//   REFUTED: re-authorising with the same client revokes the previous grant
//            and its access tokens; an auth code replay revokes the grant.

import { describe, it, expect, afterEach, vi } from "vitest";
import {
  makeWorker, stubUpstream, registerClient, runBrowserLeg, exchangeCode, callMcp,
} from "./_harness-oauth-worker";
import { MCP_REFRESH_TOKEN_TTL_SECONDS } from "../../oauth-provider-options";

const CB = "https://claude.ai/api/mcp/auth_callback";

async function fullFlow(w: ReturnType<typeof makeWorker>, clientId: string, extra: Record<string, string> = {}) {
  const leg = await runBrowserLeg(w, { client_id: clientId, redirect_uri: CB, response_type: "code", ...extra });
  const code = leg.finalLocation!.searchParams.get("code")!;
  const tok = await exchangeCode(w, {
    grant_type: "authorization_code", code, client_id: clientId, redirect_uri: CB, code_verifier: leg.codeVerifier!,
  });
  return { leg, code, tok };
}

describe("A9 provider storage, TTLs and scope", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("REFUTED: KV never holds a plaintext token, code, client secret or upstream refresh token", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "sub-1", email: "a@b", refresh_token: "UPSTREAM-RT-SECRET" });
    const reg = await registerClient(w, { redirect_uris: [CB] }); // confidential client → secret issued
    const secret = reg.json.client_secret as string;
    const clientId = reg.json.client_id as string;
    const leg = await runBrowserLeg(w, { client_id: clientId, redirect_uri: CB, response_type: "code" });
    const code = leg.finalLocation!.searchParams.get("code")!;
    const tok = await exchangeCode(w, {
      grant_type: "authorization_code", code, client_id: clientId, client_secret: secret, redirect_uri: CB, code_verifier: leg.codeVerifier!,
    });
    expect(tok.res.status).toBe(200);

    const everything = [...w.kv.data.values()].map((e) => e.value).join("\n");
    for (const s of [secret, code, tok.json.access_token as string, tok.json.refresh_token as string, "UPSTREAM-RT-SECRET", "upstream-app-client-secret"]) {
      expect(everything).not.toContain(s);
    }
    // ...but the bearer still resolves to the props (so the props are recoverable only WITH the token).
    const mcp = await callMcp(w, tok.json.access_token as string);
    expect(mcp.json.props?.refreshToken).toBe("UPSTREAM-RT-SECRET");
  });

  it("FIXED (F-22): the grant/refresh token expires 90 days after authorisation; access token TTL is 3600 s", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "sub-1", email: "a@b", refresh_token: "r" });
    const reg = await registerClient(w, { redirect_uris: [CB], token_endpoint_auth_method: "none" });
    const before = Math.floor(Date.now() / 1000);
    const { tok } = await fullFlow(w, reg.json.client_id as string);
    const after = Math.floor(Date.now() / 1000);
    expect(tok.res.status).toBe(200);
    expect(typeof tok.json.refresh_token).toBe("string");
    const grantKey = [...w.kv.data.keys()].find((k) => k.startsWith("grant:"))!;
    const tokenKey = [...w.kv.data.keys()].find((k) => k.startsWith("token:"))!;
    const expiresAt = JSON.parse(w.kv.data.get(grantKey)!.value).expiresAt as number;
    expect(MCP_REFRESH_TOKEN_TTL_SECONDS).toBe(7_776_000);
    expect(expiresAt).toBeGreaterThanOrEqual(before + MCP_REFRESH_TOKEN_TTL_SECONDS);
    expect(expiresAt).toBeLessThanOrEqual(after + MCP_REFRESH_TOKEN_TTL_SECONDS);
    // The library now stores the grant with an absolute KV expiration.
    expect(w.kv.data.get(grantKey)!.opts?.expiration).toBe(expiresAt);
    expect(w.kv.data.get(tokenKey)!.opts).toEqual({ expirationTtl: 3600 });
  });

  it("DESIGN (F-22): MCP-side scope is echoed verbatim and unenforced — authority is the surface review", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "sub-1", email: "a@b", refresh_token: "r" });
    const reg = await registerClient(w, { redirect_uris: [CB], token_endpoint_auth_method: "none" });
    const { tok } = await fullFlow(w, reg.json.client_id as string, { scope: "admin delete-everything" });
    expect(tok.json.scope).toBe("admin delete-everything");
    const grantKey = [...w.kv.data.keys()].find((k) => k.startsWith("grant:"))!;
    expect(JSON.parse(w.kv.data.get(grantKey)!.value).scope).toEqual(["admin", "delete-everything"]);
  });

  it("REFUTED: re-auth with the same client revokes the older grant and its tokens", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "sub-1", email: "a@b", refresh_token: "r" });
    const reg = await registerClient(w, { redirect_uris: [CB], token_endpoint_auth_method: "none" });
    const first = await fullFlow(w, reg.json.client_id as string);
    expect((await callMcp(w, first.tok.json.access_token as string)).res.status).toBe(200);
    const second = await fullFlow(w, reg.json.client_id as string);
    expect((await callMcp(w, second.tok.json.access_token as string)).res.status).toBe(200);
    expect((await callMcp(w, first.tok.json.access_token as string)).res.status).toBe(401);
    expect([...w.kv.data.keys()].filter((k) => k.startsWith("grant:"))).toHaveLength(1);
  });

  it("REFUTED: replaying an authorization code revokes the grant it minted", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "sub-1", email: "a@b", refresh_token: "r" });
    const reg = await registerClient(w, { redirect_uris: [CB], token_endpoint_auth_method: "none" });
    const { leg, code, tok } = await fullFlow(w, reg.json.client_id as string);
    const replay = await exchangeCode(w, {
      grant_type: "authorization_code", code, client_id: reg.json.client_id as string, redirect_uri: CB, code_verifier: leg.codeVerifier!,
    });
    expect(replay.res.status).toBe(400);
    expect(replay.json.error_description).toBe("Authorization code already used");
    expect((await callMcp(w, tok.json.access_token as string)).res.status).toBe(401);
  });

  it("REFUTED: /mcp rejects a forged bearer in the internal `user:grant:secret` shape", async () => {
    const w = makeWorker();
    const forged = await callMcp(w, "sub-1:AAAAAAAAAAAAAAAA:" + "B".repeat(32));
    expect(forged.res.status).toBe(401);
  });
});
