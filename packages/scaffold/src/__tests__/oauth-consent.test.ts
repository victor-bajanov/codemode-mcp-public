// packages/scaffold/src/__tests__/oauth-consent.test.ts
//
// Unit tests for the /authorize consent interstitial helpers (F-2, F-20):
// HMAC-signed form tokens under COOKIE_ENCRYPTION_KEY, cookie helpers, the
// HTML-escaped consent page and its anti-framing headers.

import { describe, it, expect } from "vitest";
import type { AuthRequest } from "@cloudflare/workers-oauth-provider";
import {
  AUTH_COOKIE_PREFIX,
  CONSENT_COOKIE_PREFIX,
  CONSENT_TTL_SEC,
  CONSENT_USED_KV_PREFIX,
  clearCookie,
  consentKey,
  consentPageHeaders,
  displayClientName,
  escapeHtml,
  KNOWN_REDIRECT_URIS,
  isKnownRedirectUri,
  randomId,
  randomNonce,
  readCookie,
  renderConsentPage,
  setCookie,
  signConsentToken,
  verifyConsentToken,
  type ConsentTokenPayload,
} from "../oauth-consent";

const KEY_A = "a".repeat(32);
const KEY_B = "b".repeat(32);

const REQ: AuthRequest = {
  responseType: "code",
  clientId: "client-1",
  redirectUri: "https://claude.ai/api/mcp/auth_callback",
  scope: ["mcp"],
  state: "st",
  codeChallenge: "chal",
  codeChallengeMethod: "S256",
};

function payload(overrides: Partial<ConsentTokenPayload> = {}): ConsentTokenPayload {
  return { v: 1, id: "id-1", nonce: "nonce-1", exp: 2_000, req: REQ, ...overrides };
}

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("consentKey", () => {
  it("throws when COOKIE_ENCRYPTION_KEY is missing, not a string or under 32 chars", async () => {
    await expect(consentKey({})).rejects.toThrow(/COOKIE_ENCRYPTION_KEY/);
    await expect(consentKey({ COOKIE_ENCRYPTION_KEY: 42 })).rejects.toThrow();
    await expect(consentKey({ COOKIE_ENCRYPTION_KEY: "x".repeat(31) })).rejects.toThrow();
  });

  it("imports a non-extractable HMAC-SHA256 key", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    expect(key.type).toBe("secret");
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "HMAC", hash: { name: "SHA-256" } });
    expect([...key.usages].sort()).toEqual(["sign", "verify"]);
  });
});

describe("signConsentToken / verifyConsentToken", () => {
  it("round-trips a payload before expiry", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const token = await signConsentToken(key, payload());
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(await verifyConsentToken(key, token, 1_999)).toEqual(payload());
  });

  it("rejects an expired token (exp is exclusive)", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const token = await signConsentToken(key, payload({ exp: 2_000 }));
    expect(await verifyConsentToken(key, token, 2_000)).toBeNull();
    expect(await verifyConsentToken(key, token, 9_999)).toBeNull();
  });

  it("rejects a tampered payload", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const token = await signConsentToken(key, payload());
    const [, sig] = token.split(".");
    const forged = b64url(JSON.stringify(payload({ req: { ...REQ, redirectUri: "https://attacker.example/cb" } })));
    expect(await verifyConsentToken(key, `${forged}.${sig}`, 1_000)).toBeNull();
  });

  it("rejects a tampered signature", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const token = await signConsentToken(key, payload());
    const [body, sig] = token.split(".") as [string, string];
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    expect(await verifyConsentToken(key, `${body}.${flipped}`, 1_000)).toBeNull();
  });

  it("rejects a token signed with a different key", async () => {
    const a = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const b = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_B });
    const token = await signConsentToken(a, payload());
    expect(await verifyConsentToken(b, token, 1_000)).toBeNull();
  });

  it("rejects a correctly signed payload with the wrong version or a bad shape", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const sign = (p: unknown) => signConsentToken(key, p as ConsentTokenPayload);
    expect(await verifyConsentToken(key, await sign({ ...payload(), v: 2 }), 1_000)).toBeNull();
    expect(await verifyConsentToken(key, await sign({ ...payload(), id: 7 }), 1_000)).toBeNull();
    expect(await verifyConsentToken(key, await sign({ ...payload(), exp: "later" }), 1_000)).toBeNull();
    expect(await verifyConsentToken(key, await sign({ ...payload(), req: { clientId: "c" } }), 1_000)).toBeNull();
  });

  it("returns null (never throws) for garbage", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    for (const g of ["", ".", "abc", "a.b.c", "!!!.???", "e30.", ".e30", "e30.AAAA", "%%%%.%%%%", "\u0000.\u0000"]) {
      expect(await verifyConsentToken(key, g, 1_000)).toBeNull();
    }
  });

  it("binds the MAC to the codemode-consent-v1 context (a bare HMAC of the body does not verify)", async () => {
    const key = await consentKey({ COOKIE_ENCRYPTION_KEY: KEY_A });
    const body = b64url(JSON.stringify(payload()));
    const raw = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
    const sig = b64url(String.fromCharCode(...new Uint8Array(raw)));
    expect(await verifyConsentToken(key, `${body}.${sig}`, 1_000)).toBeNull();
  });
});

describe("cookies", () => {
  it("setCookie always emits Path=/; Secure; HttpOnly with SameSite and Max-Age", () => {
    expect(setCookie(`${CONSENT_COOKIE_PREFIX}abc`, "n1", { maxAge: CONSENT_TTL_SEC, sameSite: "Strict" })).toBe(
      "__Host-cm-consent-abc=n1; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300",
    );
    expect(setCookie(`${AUTH_COOKIE_PREFIX}st`, "n2", { maxAge: 600, sameSite: "Lax" })).toBe(
      "__Host-cm-auth-st=n2; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
    );
  });

  it("clearCookie expires the cookie with the same __Host- attributes", () => {
    expect(clearCookie("__Host-cm-auth-st")).toBe(
      "__Host-cm-auth-st=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
    );
  });

  it("readCookie finds the named cookie among others and returns null when absent", () => {
    const req = new Request("https://w.test/", {
      headers: { Cookie: "a=1; __Host-cm-consent-x=nonce=with=equals ;b=2" },
    });
    expect(readCookie(req, "__Host-cm-consent-x")).toBe("nonce=with=equals");
    expect(readCookie(req, "b")).toBe("2");
    expect(readCookie(req, "__Host-cm-consent-y")).toBeNull();
    expect(readCookie(new Request("https://w.test/"), "a")).toBeNull();
  });

  it("exports the documented constants", () => {
    expect(CONSENT_TTL_SEC).toBe(300);
    expect(CONSENT_USED_KV_PREFIX).toBe("consent-used:");
  });
});

describe("random helpers", () => {
  it("randomId is 16 bytes of hex and randomNonce 32 bytes of base64url", () => {
    expect(randomId()).toMatch(/^[0-9a-f]{32}$/);
    expect(randomNonce()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomId()).not.toBe(randomId());
    expect(randomNonce()).not.toBe(randomNonce());
  });
});

// A-6(2-3). Attacker: registers a client whose redirect_uri sits on a Claude
// host or a loopback port but is not a Claude/Claude Code/MCP Inspector
// callback (an artifact page, another port, a different loopback path).
// Pre-fix, the check was hostname-only, so every such URI counted as "known"
// and the consent page showed no warning. Control: Claude's callback URIs are
// pinned exactly; loopback is pinned by path with the port free (RFC 8252
// §7.3); everything else is unknown (warned, never refused).
describe("isKnownRedirectUri", () => {
  it("pins Claude's callback URIs exactly", () => {
    expect([...KNOWN_REDIRECT_URIS].sort()).toEqual([
      "https://claude.ai/api/mcp/auth_callback",
      "https://claude.com/api/mcp/auth_callback",
    ]);
    for (const u of KNOWN_REDIRECT_URIS) expect(isKnownRedirectUri(u), u).toBe(true);
  });

  it("pins loopback by path (/callback, /oauth/callback), any port", () => {
    for (const u of [
      "http://localhost:31337/callback",
      "http://localhost:6274/oauth/callback",
      "http://127.0.0.1:6274/oauth/callback",
      "http://127.0.0.1:33418/callback",
      "http://[::1]:8080/callback",
      "https://localhost/callback",
      "http://localhost/oauth/callback",
    ]) expect(isKnownRedirectUri(u), u).toBe(true);
  });

  it("FIXED (A-6): other paths, ports or queries on a Claude host are unknown", () => {
    for (const u of [
      "https://claude.ai/anything/else?next=https://attacker.example/",
      "https://claude.ai:8443/cb",
      "https://claude.com/redirect",
      "https://claude.ai/public/artifacts/0000",
      "https://claude.com/cb",
      "https://claude.ai:8443/api/mcp/auth_callback",
      "https://claude.ai/api/mcp/auth_callback?next=x",
      "https://claude.ai/api/mcp/auth_callback?",
      "https://claude.ai/api/mcp/auth_callback#frag",
      "https://claude.ai/api/mcp/auth_callback/",
      "https://user@claude.ai/api/mcp/auth_callback",
      "http://claude.ai/api/mcp/auth_callback",
    ]) expect(isKnownRedirectUri(u), u).toBe(false);
  });

  it("FIXED (A-6): other loopback paths, queries or fragments are unknown", () => {
    for (const u of [
      "http://localhost:31337/collect",
      "http://127.0.0.1:33418/cb",
      "http://[::1]:8080/cb",
      "http://localhost:31337/callback/",
      "http://localhost:31337/callback?x=1",
      "http://localhost:31337/callback#x",
      "http://localhost:31337/Callback",
      "http://user@localhost:31337/callback",
      "ftp://localhost/callback",
    ]) expect(isKnownRedirectUri(u), u).toBe(false);
  });

  it("REFUTED: look-alike hosts, userinfo tricks and foreign schemes stay unknown", () => {
    for (const u of [
      "https://attacker.example/collect",
      "https://claude.ai.attacker.example/api/mcp/auth_callback",
      "https://evil.claude.ai.example/api/mcp/auth_callback",
      "https://claude.ai@attacker.example/api/mcp/auth_callback",
      "not a url",
      // Known hostname, unknown scheme: delivered to whatever app claims it.
      "evil://claude.ai/api/mcp/auth_callback",
      "x-evil://claude.com/api/mcp/auth_callback",
      "evil://localhost/callback",
    ]) expect(isKnownRedirectUri(u), u).toBe(false);
  });
});

describe("displayClientName", () => {
  it("names a nameless client the old way", () => {
    for (const n of [undefined, "", "   ", "\u0000\u202e\u200b"]) {
      expect(displayClientName(n), JSON.stringify(n)).toBe("an application that did not give a name");
    }
  });

  it("strips control, zero-width and bidi characters", () => {
    expect(displayClientName("Cla\u0000ude\u0007")).toBe("Claude");
    expect(displayClientName("\u202eedualC\u202c")).toBe("edualC");
    expect(displayClientName("Cl\u200bau\u200fde\u2066\u2069")).toBe("Claude");
    expect(displayClientName("A\u0085B\u009fC\u007f")).toBe("ABC");
    expect(displayClientName("A\u2028B\u2029C\u202aD")).toBe("ABCD");
  });

  it("strips other invisible format characters and the tag block", () => {
    expect(
      displayClientName("A\u00adB\u061cC\u180eD\u2060E\u2064F\u3164G\u{e0001}H\u{e0041}\u{e007f}I"),
    ).toBe("ABCDEFGHI");
  });

  it("maps quote characters to ' so a name cannot close the quoted claim", () => {
    expect(displayClientName("Claude\u201d (verified). Approve is safe. \u201cx")).toBe(
      "Claude' (verified). Approve is safe. 'x",
    );
    expect(displayClientName('a"b\u201ec\u201fd')).toBe("a'b'c'd");
  });

  it("collapses whitespace and trims", () => {
    expect(displayClientName("  MCP \u00a0  Inspector  ")).toBe("MCP Inspector");
  });

  it("keeps short names and caps long ones at 64 code points with an ellipsis", () => {
    expect(displayClientName("Claude Code")).toBe("Claude Code");
    const exact = "x".repeat(64);
    expect(displayClientName(exact)).toBe(exact);
    const long = displayClientName("y".repeat(65));
    expect(long).toBe("y".repeat(64) + "\u2026");
    // Counted in code points, so an astral character is not split.
    const astral = displayClientName("\u{1F600}".repeat(100));
    expect([...astral]).toHaveLength(65);
    expect(astral.endsWith("\u{1F600}\u2026")).toBe(true);
  });
});

describe("renderConsentPage", () => {
  const base = {
    providerName: "Gmail",
    clientName: "Claude",
    redirectUri: "https://claude.ai/api/mcp/auth_callback",
    upstreamScopes: ["openid", "https://www.googleapis.com/auth/gmail.modify"],
    token: "tok.sig",
    knownRedirect: true,
  };

  it("HTML-escapes the client name, redirect URI, scopes and token", () => {
    const html = renderConsentPage({
      ...base,
      clientName: `<script>alert("x")</script>`,
      redirectUri: `https://attacker.example/cb?a="><img src=x onerror=alert(1)>`,
      upstreamScopes: [`"'&`, `<b>admin</b>`],
      token: `"><script>`,
      knownRedirect: false,
    });
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>admin</b>");
    expect(html).toContain("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;");
    expect(html).toContain("&lt;b&gt;admin&lt;/b&gt;");
    expect(html).toContain("&quot;&#39;&amp;");
    expect(html).toContain('value="&quot;&gt;&lt;script&gt;"');
  });

  it("shows the redirect URI with its host in bold, skipping userinfo", () => {
    expect(renderConsentPage(base)).toContain(
      "https://<strong>claude.ai</strong>/api/mcp/auth_callback",
    );
    const tricky = renderConsentPage({
      ...base,
      redirectUri: "https://claude.ai@attacker.example/cb",
      knownRedirect: false,
    });
    expect(tricky).toContain("https://claude.ai@<strong>attacker.example</strong>/cb");
  });

  // A-6(1). Attacker: starts a flow through a real, known client (Claude's own
  // callback) and sends the victim the consent link. Pre-fix, a known redirect
  // rendered no warning at all, so nothing told the victim to deny a flow they
  // did not start. Control: the "started this connection yourself" box is on
  // every page, before the client line.
  it("FIXED (A-6): a known redirect still shows the always-on 'started this connection yourself' box, before the client line", () => {
    const html = renderConsentPage(base);
    expect(html).toContain('<p class="warn" role="alert">');
    expect(html).toContain("only approve if you started this connection yourself");
    expect(html).toMatch(/<p class="warn" role="alert">[^]*<strong>Deny<\/strong>[^]*<\/p>/);
    expect(html).not.toContain("not a known MCP client");
    expect(html).not.toContain("Warning:");
    expect(html.indexOf('class="warn"')).toBeLessThan(html.indexOf("calling itself"));
  });

  it("warns about an unknown redirect: the always-on sentence first, then the not-a-known-client warning", () => {
    const unknown = renderConsentPage({
      ...base,
      redirectUri: "https://attacker.example/collect",
      knownRedirect: false,
    });
    expect(unknown).toContain("Warning:");
    expect(unknown).toContain("through <strong>attacker.example</strong>");
    expect(unknown).toContain("not a known MCP client");
    const always = unknown.indexOf("only approve if you started this connection yourself");
    expect(always).toBeGreaterThan(unknown.indexOf('class="warn"'));
    expect(always).toBeLessThan(unknown.indexOf("not a known MCP client"));
    expect(unknown.match(/class="warn"/g)).toHaveLength(1);
  });

  it("names the whole URI, not a host, for a non-http(s) or host-less unknown redirect", () => {
    const evil = renderConsentPage({ ...base, redirectUri: "evil://claude.ai/cb", knownRedirect: false });
    expect(evil).toContain("through <strong>evil://claude.ai/cb</strong>, which is not a known MCP client");
    expect(evil).not.toContain("through <strong>claude.ai</strong>");
    const app = renderConsentPage({ ...base, redirectUri: "com.example.app:/cb", knownRedirect: false });
    expect(app).toContain("through <strong>com.example.app:/cb</strong>, which is not a known MCP client");
    expect(app).not.toContain("<strong></strong>");
    const odd = renderConsentPage({ ...base, redirectUri: `x-app:/"<b>`, knownRedirect: false });
    expect(odd).not.toContain("<b>");
  });

  it("orders the page: heading, warning box, client line, redirect, scopes, form", () => {
    const html = renderConsentPage({ ...base, knownRedirect: false, redirectUri: "https://attacker.example/cb" });
    const order = [
      "<h1>",
      'class="warn"',
      "An application calling itself",
      "access will be sent to",
      'class="uri"',
      'class="scopes"',
      "<form",
    ].map((m) => html.indexOf(m));
    for (const i of order) expect(i).toBeGreaterThan(-1);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });

  it("shows the client name as a quoted claim", () => {
    expect(renderConsentPage(base)).toContain(
      "An application calling itself \u201cClaude\u201d is asking to use this Gmail connector on your behalf.",
    );
    expect(renderConsentPage({ ...base, clientName: undefined })).toContain(
      "<em>an application that did not give a name</em> is asking to use this Gmail connector",
    );
  });

  // A-6 (client_name). Attacker: registers a client whose name is ~4 KB of
  // reassurance text ("the warning below ... can be ignored"). Pre-fix the
  // name was unbounded and rendered ABOVE the warning. Control: the name is
  // capped at 64 code points and rendered after the box.
  it("FIXED (A-6): a 4 KB reassurance client_name is cut to 64 characters and rendered after the warning", () => {
    const reassurance =
      "Claude (verified by Anthropic). Security notice: Claude is migrating its sign-in callback to a new domain this week, " +
      "so the warning below is expected and can be ignored. Claude";
    const html = renderConsentPage({
      ...base,
      clientName: reassurance + " ".repeat(4000),
      redirectUri: "https://attacker.example/cb",
      knownRedirect: false,
    });
    expect(html.indexOf("can be ignored")).toBe(-1);
    expect(html).toContain(`\u201c${escapeHtml(displayClientName(reassurance))}\u201d`);
    expect(html.indexOf('class="warn"')).toBeLessThan(html.indexOf("Claude (verified"));
  });

  it("escapes a sanitised client name", () => {
    const html = renderConsentPage({ ...base, clientName: `<b>"x"</b>` });
    expect(html).toContain("\u201c&lt;b&gt;&#39;x&#39;&lt;/b&gt;\u201d");
  });

  it("posts back to /authorize with the token and approve/deny buttons", () => {
    const html = renderConsentPage(base);
    expect(html).toContain('<form method="post" action="/authorize">');
    expect(html).toContain('<input type="hidden" name="consent_token" value="tok.sig">');
    expect(html).toContain('name="action" value="approve"');
    expect(html).toContain('name="action" value="deny"');
    expect(html).toContain("gmail.modify");
  });

  it("lists each upstream scope as its own item", () => {
    const html = renderConsentPage(base);
    expect(html).toContain(
      '<ul class="scopes"><li><code>openid</code></li>' +
        "<li><code>https://www.googleapis.com/auth/gmail.modify</code></li></ul>",
    );
  });

  it("says when the provider requests no scopes", () => {
    expect(renderConsentPage({ ...base, upstreamScopes: [] })).toContain("<em>none</em>");
  });

  it("shows the codemode Gate mark in Optical blue above the heading", () => {
    const html = renderConsentPage(base);
    const svg = html.indexOf('<svg class="logo"');
    expect(svg).toBeGreaterThan(-1);
    expect(svg).toBeLessThan(html.indexOf("<h1>"));
    expect(html).toContain('aria-label="codemode"');
    expect(html).toContain('stroke="#0A66FF"');
    // Inline SVG only: the page CSP is default-src 'none', so no external image.
    expect(html).not.toMatch(/<img|href="http/);
  });

  it("does not show MCP scopes, which nothing enforces", () => {
    expect(renderConsentPage(base)).not.toContain("MCP scopes");
  });

  it("names an unnamed client as such", () => {
    const html = renderConsentPage({ ...base, clientName: undefined });
    expect(html).toContain("did not give a name");
  });

  it("escapeHtml covers the five significant characters", () => {
    expect(escapeHtml(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#39;");
  });
});

describe("consentPageHeaders", () => {
  it("sets no-store, anti-framing CSP without form-action, DENY, no-referrer and the cookie", () => {
    const h = consentPageHeaders("__Host-cm-consent-x=n; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300");
    expect(h.get("content-type")).toBe("text/html; charset=utf-8");
    expect(h.get("cache-control")).toBe("no-store");
    const csp = h.get("content-security-policy")!;
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    // form-action would also govern the post-submit 303 to the upstream IdP in Chrome.
    expect(csp).not.toContain("form-action");
    expect(h.get("x-frame-options")).toBe("DENY");
    expect(h.get("referrer-policy")).toBe("no-referrer");
    expect(h.get("set-cookie")).toContain("__Host-cm-consent-x=n");
  });
});
