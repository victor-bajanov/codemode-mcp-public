import { Hono } from "hono";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { ApiProvider, UpstreamTokenResponse } from "./api-provider";
import { allowPiiInLogs, resolveEndpoints } from "./config";
import {
  AUTH_COOKIE_PREFIX,
  CONSENT_COOKIE_PREFIX,
  CONSENT_TTL_SEC,
  CONSENT_USED_KV_PREFIX,
  clearCookie,
  consentKey,
  consentPageHeaders,
  isKnownRedirectHost,
  randomId,
  randomNonce,
  readCookie,
  renderConsentPage,
  setCookie,
  signConsentToken,
  verifyConsentToken,
} from "./oauth-consent";
import { generateCodeVerifier, sha256Base64Url } from "./pkce";
import { oauthErrorCode } from "./refresh";

const STATE_KV_PREFIX = "auth-state:";
const STATE_TTL_SEC = 600;
/** TTL of the single-use `consent-used:` marker; outlives the 300 s token. */
const CONSENT_USED_TTL_SEC = 600;
/** `crypto.randomUUID()` shape; anything else cannot name a stash. */
const STATE_TOKEN_RE = /^[0-9a-f-]{36}$/i;

const CONSENT_INVALID =
  "Consent expired or invalid. Start the connection again from your MCP client.";
const STATE_INVALID = "State expired or invalid";

type BaseEnv = {
  OAUTH_PROVIDER: OAuthHelpers;
  OAUTH_KV: KVNamespace;
} & Record<string, string | KVNamespace | OAuthHelpers>;

/** The `auth-state:` stash written by the approving `POST /authorize`. */
interface AuthStateStash {
  oauthReqInfo: AuthRequest;
  codeVerifier?: string;
  /** SHA-256 (base64url) of the browser-binding cookie's value (F-15). */
  bindingHash: string;
}

function parseStash(raw: string): AuthStateStash | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const p = parsed as Record<string, unknown>;
  if (typeof p.oauthReqInfo !== "object" || p.oauthReqInfo === null) return null;
  if (typeof p.bindingHash !== "string" || p.bindingHash.length === 0) return null;
  if (p.codeVerifier !== undefined && typeof p.codeVerifier !== "string") return null;
  return parsed as AuthStateStash;
}

function textResponse(body: string, status: number, cookies: string[] = []): Response {
  const headers = new Headers({
    "content-type": "text/plain; charset=UTF-8",
    "cache-control": "no-store",
  });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(body, { status, headers });
}

function redirectResponse(location: string, status: number, cookies: string[]): Response {
  // Built by hand: `Response.redirect` headers are immutable in Workers, and
  // `Headers.append` is needed to send more than one cookie.
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status, headers });
}

/**
 * Upstream token-exchange failure detail for `console.error`: status and the
 * OAuth `error` code always; up to 500 chars of the body only when
 * `ALLOW_PII_IN_LOGS === "true"` (F-21). IdP error bodies are upstream text
 * and can echo request details.
 */
function exchangeFailureDetail(status: number, errText: string, env: unknown): string {
  const detail = `status=${status} error=${oauthErrorCode(errText) ?? "unknown"}`;
  return allowPiiInLogs(env as { ALLOW_PII_IN_LOGS?: string })
    ? `${detail} body=${errText.slice(0, 500)}`
    : detail;
}

export function createOAuthHandler<
  P extends Record<string, unknown>,
  Env extends BaseEnv = BaseEnv,
>(provider: ApiProvider<P, Env>) {
  const app = new Hono<{ Bindings: Env }>();

  // GET /authorize renders the consent interstitial (F-2). Nothing is written
  // to KV and nothing goes upstream until the operator approves it.
  app.get("/authorize", async (c) => {
    let oauthReqInfo: AuthRequest;
    try {
      // With allowPlainPKCE: false the library throws for a missing or
      // `plain` code_challenge_method, an unknown client, or a redirect_uri
      // not registered for the client.
      oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    } catch (err) {
      return c.text(
        `Invalid authorization request: ${err instanceof Error ? err.message : String(err)}`,
        400,
      );
    }
    if (!oauthReqInfo.clientId) {
      return c.text("Invalid authorization request: missing clientId", 400);
    }
    if (oauthReqInfo.responseType !== "code") {
      return c.text("Invalid authorization request: response_type must be code", 400);
    }
    if (!oauthReqInfo.redirectUri) {
      return c.text("Invalid authorization request: missing redirect_uri", 400);
    }
    // MCP-client PKCE (F-2). `provider.oauth.pkce` separately governs the
    // scaffold → upstream IdP leg.
    if (!oauthReqInfo.codeChallenge || oauthReqInfo.codeChallengeMethod !== "S256") {
      return c.text(
        "PKCE is required: send code_challenge with code_challenge_method=S256",
        400,
      );
    }

    const client = await c.env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);
    if (!client) {
      return c.text("Invalid authorization request: unknown client", 400);
    }

    const key = await consentKey(c.env as Record<string, unknown>);
    const id = randomId();
    const nonce = randomNonce();
    const token = await signConsentToken(key, {
      v: 1,
      id,
      nonce,
      exp: Math.floor(Date.now() / 1000) + CONSENT_TTL_SEC,
      req: oauthReqInfo,
    });

    const html = renderConsentPage({
      providerName: provider.displayName,
      clientName: client.clientName,
      redirectUri: oauthReqInfo.redirectUri,
      upstreamScopes: provider.oauth.scopes,
      token,
      knownRedirectHost: isKnownRedirectHost(oauthReqInfo.redirectUri),
    });
    const cookie = setCookie(CONSENT_COOKIE_PREFIX + id, nonce, {
      maxAge: CONSENT_TTL_SEC,
      sameSite: "Strict",
    });
    return new Response(html, { status: 200, headers: consentPageHeaders(cookie) });
  });

  // POST /authorize is the consent form submission (F-2, F-15, F-20). The
  // signed token proves the page came from this worker within 300 s; the
  // SameSite=Strict cookie proves the submission came from the browser that
  // was shown the page (a cross-site auto-submit carries no Strict cookie);
  // the KV marker makes the token single-use.
  app.post("/authorize", async (c) => {
    const form = await c.req.parseBody();
    const token = form["consent_token"];
    const action = form["action"];
    if (typeof token !== "string" || typeof action !== "string") {
      return textResponse(CONSENT_INVALID, 400);
    }

    const key = await consentKey(c.env as Record<string, unknown>);
    const payload = await verifyConsentToken(key, token, Math.floor(Date.now() / 1000));
    if (!payload) return textResponse(CONSENT_INVALID, 400);

    // Every response from here clears this flow's consent cookie.
    const consentCookie = CONSENT_COOKIE_PREFIX + payload.id;
    const clearConsent = clearCookie(consentCookie);
    if (readCookie(c.req.raw, consentCookie) !== payload.nonce) {
      return textResponse(CONSENT_INVALID, 400, [clearConsent]);
    }
    if (action !== "approve" && action !== "deny") {
      return textResponse(CONSENT_INVALID, 400, [clearConsent]);
    }
    const usedKey = CONSENT_USED_KV_PREFIX + payload.id;
    if (await c.env.OAUTH_KV.get(usedKey)) {
      return textResponse(CONSENT_INVALID, 400, [clearConsent]);
    }
    await c.env.OAUTH_KV.put(usedKey, "1", { expirationTtl: CONSENT_USED_TTL_SEC });

    const oauthReqInfo = payload.req;
    if (action === "deny") {
      const denied = new URL(oauthReqInfo.redirectUri);
      denied.searchParams.set("error", "access_denied");
      if (oauthReqInfo.state) denied.searchParams.set("state", oauthReqInfo.state);
      return redirectResponse(denied.toString(), 303, [clearConsent]);
    }

    const pkceMode = provider.oauth.pkce ?? "s256";
    let codeVerifier: string | undefined;
    let codeChallenge: string | undefined;
    if (pkceMode === "s256") {
      codeVerifier = generateCodeVerifier();
      codeChallenge = await sha256Base64Url(codeVerifier);
    }

    // Browser binding (F-15): only the browser holding this cookie can
    // complete /callback for this state.
    const stateToken = crypto.randomUUID();
    const browserNonce = randomNonce();
    const stash: AuthStateStash = {
      oauthReqInfo,
      ...(codeVerifier !== undefined ? { codeVerifier } : {}),
      bindingHash: await sha256Base64Url(browserNonce),
    };
    await c.env.OAUTH_KV.put(STATE_KV_PREFIX + stateToken, JSON.stringify(stash), {
      expirationTtl: STATE_TTL_SEC,
    });

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
    // SameSite=Lax so the cookie survives the top-level redirect back from the IdP.
    const authCookie = setCookie(AUTH_COOKIE_PREFIX + stateToken, browserNonce, {
      maxAge: STATE_TTL_SEC,
      sameSite: "Lax",
    });
    return redirectResponse(`${authorizeUrl}?${params.toString()}`, 303, [
      clearConsent,
      authCookie,
    ]);
  });

  app.get("/callback", async (c) => {
    const code = c.req.query("code");
    const stateToken = c.req.query("state");
    if (!code || !stateToken) return c.text("Missing code or state", 400);
    if (!STATE_TOKEN_RE.test(stateToken)) return c.text(STATE_INVALID, 400);

    const stashed = await c.env.OAUTH_KV.get(STATE_KV_PREFIX + stateToken);
    if (!stashed) return c.text(STATE_INVALID, 400);
    // Only the enveloped shape with a browser binding is accepted; stashes
    // written before the consent page existed TTL out within STATE_TTL_SEC
    // (sign-ins in flight at deploy time must restart).
    const stash = parseStash(stashed);
    if (!stash) return c.text(STATE_INVALID, 400);
    const authCookie = AUTH_COOKIE_PREFIX + stateToken;
    const binding = readCookie(c.req.raw, authCookie);
    if (!binding || (await sha256Base64Url(binding)) !== stash.bindingHash) {
      // Refuse WITHOUT consuming the stash, so a request from another browser
      // cannot burn the legitimate user's sign-in.
      return c.text(STATE_INVALID, 400);
    }
    // Residual (accepted): the same browser double-submitting /callback within
    // KV propagation can still pass twice; the upstream's single-use code
    // makes the second exchange fail.
    await c.env.OAUTH_KV.delete(STATE_KV_PREFIX + stateToken);
    const { oauthReqInfo, codeVerifier } = stash;

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
          `Upstream ${exchangeFailureDetail(tokenRes.status, errText, c.env)}`,
        );
        return c.text(
          `${provider.displayName} OAuth failed: upstream rejected PKCE. ` +
          `Operator: set oauth.pkce: "none" on the provider to disable.`,
          502,
        );
      }
      console.error(
        `${provider.displayName} token exchange failed: ` +
        exchangeFailureDetail(tokenRes.status, errText, c.env),
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
    // Trust assumption (F-23): hooks are first-party, but identity from the
    // upstream always wins. `hookProps` is spread FIRST so the token response's
    // refresh token and userinfo's sub/email/name override anything a hook
    // returns; a hook can still add fields (e.g. Xero's tenantId) and may
    // supply userId only when the upstream returned no string `sub`.
    const props = {
      ...hookProps,
      refreshToken: tokens.refresh_token,
      ...(typeof ui.sub === "string" ? { userId: ui.sub } : {}),
      ...(typeof ui.email === "string" ? { email: ui.email } : {}),
      ...(typeof ui.name === "string" ? { name: ui.name } : {}),
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

    return redirectResponse(redirectTo, 302, [clearCookie(authCookie)]);
  });

  return app;
}
