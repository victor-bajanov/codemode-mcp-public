import { Hono } from "hono";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { ApiProvider, UpstreamTokenResponse } from "./api-provider";
import { resolveEndpoints } from "./config";
import { generateCodeVerifier, sha256Base64Url } from "./pkce";

const STATE_KV_PREFIX = "auth-state:";
const STATE_TTL_SEC = 600;

type BaseEnv = {
  OAUTH_PROVIDER: OAuthHelpers;
  OAUTH_KV: KVNamespace;
} & Record<string, string | KVNamespace | OAuthHelpers>;

export function createOAuthHandler<
  P extends Record<string, unknown>,
  Env extends BaseEnv = BaseEnv,
>(provider: ApiProvider<P, Env>) {
  const app = new Hono<{ Bindings: Env }>();

  app.get("/authorize", async (c) => {
    const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    if (!oauthReqInfo.clientId) {
      return c.text("Invalid authorization request: missing clientId", 400);
    }

    const pkceMode = provider.oauth.pkce ?? "s256";
    let codeVerifier: string | undefined;
    let codeChallenge: string | undefined;
    if (pkceMode === "s256") {
      codeVerifier = generateCodeVerifier();
      codeChallenge = await sha256Base64Url(codeVerifier);
    }

    const stateToken = crypto.randomUUID();
    await c.env.OAUTH_KV.put(
      STATE_KV_PREFIX + stateToken,
      JSON.stringify({ oauthReqInfo, codeVerifier }),
      { expirationTtl: STATE_TTL_SEC },
    );

    const redirectUri = new URL("/callback", c.req.url).toString();
    const clientId = c.env[provider.oauth.clientIdSecretName] as string;

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: provider.oauth.scopes.join(" "),
      state: stateToken,
    });
    if (codeChallenge) {
      params.set("code_challenge", codeChallenge);
      params.set("code_challenge_method", "S256");
    }
    if (provider.oauth.extraAuthorizeParams) {
      for (const [k, v] of Object.entries(provider.oauth.extraAuthorizeParams)) {
        // Base OAuth2 params (set above) win — see ApiProvider.oauth.extraAuthorizeParams JSDoc.
        if (!params.has(k)) params.set(k, v);
      }
    }

    const { authorizeUrl } = resolveEndpoints(provider, c.env as Record<string, unknown>);
    return Response.redirect(`${authorizeUrl}?${params.toString()}`);
  });

  app.get("/callback", async (c) => {
    const code = c.req.query("code");
    const stateToken = c.req.query("state");
    if (!code || !stateToken) return c.text("Missing code or state", 400);

    const stashed = await c.env.OAUTH_KV.get(STATE_KV_PREFIX + stateToken);
    if (!stashed) return c.text("State expired or invalid", 400);
    const parsedStash: unknown = JSON.parse(stashed);
    // Backward compat: legacy stash was `JSON.stringify(oauthReqInfo)` directly
    // (no envelope). Detect by absence of an `oauthReqInfo` property on the
    // parsed object. Legacy entries TTL out within STATE_TTL_SEC seconds.
    const isEnvelope =
      typeof parsedStash === "object" &&
      parsedStash !== null &&
      "oauthReqInfo" in (parsedStash as Record<string, unknown>);
    const oauthReqInfo: AuthRequest = (isEnvelope
      ? (parsedStash as { oauthReqInfo: unknown }).oauthReqInfo
      : parsedStash) as AuthRequest;
    const codeVerifier: string | undefined = isEnvelope
      ? (parsedStash as { codeVerifier?: string }).codeVerifier
      : undefined;
    await c.env.OAUTH_KV.delete(STATE_KV_PREFIX + stateToken);

    const pkceMode = provider.oauth.pkce ?? "s256";

    const redirectUri = new URL("/callback", c.req.url).toString();
    const clientId = c.env[provider.oauth.clientIdSecretName] as string;
    const clientSecret = c.env[provider.oauth.clientSecretSecretName] as string;

    const tokenBody = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    });
    if (codeVerifier) tokenBody.set("code_verifier", codeVerifier);

    const { tokenUrl, userInfoUrl } = resolveEndpoints(provider, c.env as Record<string, unknown>);
    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: tokenBody.toString(),
    });
    if (!tokenRes.ok) {
      const errText = await tokenRes.text();
      const isPkceError =
        pkceMode === "s256" && /code_verifier|code_challenge|pkce/i.test(errText);
      if (isPkceError) {
        console.error(
          `${provider.displayName} rejected PKCE on token exchange. To disable, ` +
          `set oauth.pkce: "none" on the provider config and redeploy. ` +
          `Upstream status=${tokenRes.status} body=${errText.slice(0, 500)}`,
        );
        return c.text(
          `${provider.displayName} OAuth failed: upstream rejected PKCE. ` +
          `Operator: set oauth.pkce: "none" on the provider to disable.`,
          502,
        );
      }
      console.error(
        `${provider.displayName} token exchange failed: status=${tokenRes.status} ` +
        `body=${errText.slice(0, 500)}`,
      );
      return c.text(`${provider.displayName} token exchange failed: ${tokenRes.status}`, 502);
    }
    const tokens = (await tokenRes.json()) as UpstreamTokenResponse;
    if (!tokens.refresh_token) {
      return c.text(
        `${provider.displayName} did not return a refresh_token. Confirm offline_access (or equivalent) scope.`,
        502,
      );
    }

    let userInfo: unknown = null;
    if (userInfoUrl) {
      const userRes = await fetch(userInfoUrl, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      if (!userRes.ok) {
        return c.text(`${provider.displayName} userinfo fetch failed: ${userRes.status}`, 502);
      }
      userInfo = await userRes.json();
    }

    let hookProps: Partial<P> = {};
    if (provider.completeAuthHook) {
      try {
        hookProps = await provider.completeAuthHook({
          tokens,
          userInfo,
          env: c.env as unknown as Env,
        });
      } catch (err) {
        return c.text((err instanceof Error ? err.message : String(err)), 502);
      }
    }

    const ui = (userInfo ?? {}) as Record<string, unknown>;
    const props = {
      refreshToken: tokens.refresh_token,
      ...(typeof ui.sub === "string" ? { userId: ui.sub } : {}),
      ...(typeof ui.email === "string" ? { email: ui.email } : {}),
      ...(typeof ui.name === "string" ? { name: ui.name } : {}),
      ...hookProps,
    } as unknown as P;

    const subject = (props.userId as string | undefined)
      ?? (typeof ui.sub === "string" ? ui.sub : "")
      ?? "";
    if (!subject) {
      return c.text(`${provider.displayName} OAuth produced no subject identifier`, 502);
    }

    const label = (props.email as string | undefined)
      ?? (typeof ui.email === "string" ? ui.email : provider.displayName);

    const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReqInfo,
      userId: subject,
      scope: oauthReqInfo.scope,
      metadata: { label },
      props,
    });

    return Response.redirect(redirectTo);
  });

  return app;
}
