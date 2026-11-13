// Wave 5 (2026-11 review) — end-to-end regressions for the OAuth public legs,
// driven through the real worker composition (`oauth-worker-harness.ts`: the
// library's OAuthProvider, the scaffold's OAuth handler, `enforceOAuthHardening`,
// an in-memory KV that honours TTLs and records put options, a stubbed IdP).
// Ports the review's private PoC A-6 and demo 07 as regression inputs; the
// unit-level regressions live in oauth-handler.test.ts, oauth-consent.test.ts,
// oauth-hardening.test.ts and oauth-public-legs.test.ts.
//
// A-6(4) split flow. Attacker: anyone who can send the victim one link, with
//   their own dynamically registered client. Precondition: the victim signs
//   in at the upstream IdP and then shares the address of the error page they
//   land on ("it just shows an error, send me the link"). Payload: the
//   attacker approves the consent page in their own browser and forwards the
//   resulting IdP sign-in link; the IdP sends the victim's browser to
//   `/callback?code=<victim's code>&state=<attacker's state>`, which carries
//   no binding cookie; the attacker then replays that address with their own
//   cookie. Control: a `/callback` whose binding cookie is missing or wrong
//   deletes the `auth-state:` stash before answering 400 with the do-not-share
//   text, and never spends the upstream code. Pre-fix: the refusal kept the
//   stash, so the replay was 302, the attacker's client exchanged the victim's
//   code and its bearer resolved to `victim-sub`; the probe fails at
//   `kv.data.has("auth-state:<state>") === false`.
//
// A-6(1-3) consent page. Attacker: a malicious MCP client, or a phishing link
//   to the real worker. Payloads: (1) a flow the attacker started in their own
//   account of the hosted client, redirect `https://claude.ai/api/mcp/auth_callback`;
//   (2) the PoC's four other claude.ai / claude.com URIs; (3) a loopback client
//   registered on one port and authorising on another; and a 4 KB `client_name`
//   of reassurance text. Control: the warning box ("started this connection
//   yourself", "Deny") is on every page and precedes the client line; only the
//   two pinned Claude URIs and loopback `/callback` / `/oauth/callback` (any
//   port) are known; the name is capped at 64 code points and shown as a quoted
//   claim after the box. Pre-fix: no `class="warn"` on a known host, so (1)
//   rendered nothing that told the victim they had not started the flow; any
//   claude.ai path, port or query and any loopback path were quiet; the whole
//   4 KB name rendered above the warning.
//
// A-3 throttling and body caps. Attacker: one anonymous IP. Payloads: the
//   PoC's 500 × (GET + POST `/authorize`); approvals each followed by
//   `/callback`; 24 MiB chunked bodies to `POST /authorize` and
//   `POST /register`; the percent-encoded aliases `/%61uthorize` and
//   `/%63allback` and a malformed escape. Control: per-IP fixed-window limits
//   (`/authorize` 30 per 300 s, `/callback` 10 per 300 s) answered 429 before
//   the handler, the path compared after percent-decoding, and streaming caps
//   (16 KiB forms, 1 MiB registration) answered 413 before the library.
//   Pre-fix: only `POST /register` and `POST /token` were hardened — no 429 on
//   the browser legs, every `/callback` cost an upstream token request carrying
//   the client secret, and the bodies were read to the end.
//
// A-5 client lifetime. Attacker: junk registrations, or anyone who knows a
//   public client_id. Control: `client:<id>` carries a 30-day KV TTL from
//   `/register` and 120 days from each code exchange or refresh; a revocation
//   200 (`token=`, no `grant_type`) does not renew it. Pre-fix: the record had
//   no TTL (the harness KV stores no `opts`), a `clientreg:` stamp was written
//   and a five-minute sweep reaped clients once their grant lapsed; with the
//   first fix alone, any 200 from `/token` renewed the record, so a junk
//   revocation kept any public client alive for ever.
//
// No real hostnames, account ids or operator identities: the harness uses
// `mcp.example.test`, `login.example.com` and `attacker.example`.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  callMcp,
  CHUNK,
  cookiePair,
  exchangeCode,
  keysWith,
  makeWorker,
  meteredBody,
  registerClient,
  stubUpstream,
  UPSTREAM_TOKEN_URL,
  WORKER_ORIGIN,
} from "./oauth-worker-harness";
import { readOAuthHardeningConfig } from "../config";
import { MAX_FORM_BODY_BYTES, MAX_REGISTRATION_BODY_BYTES } from "../oauth-hardening";
import { generateCodeVerifier, sha256Base64Url } from "../pkce";

const CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const ATTACKER_REDIRECT = "https://attacker.example/cb";
const ATTACKER_IP = "198.51.100.77";
const VICTIM_IP = "203.0.113.42";
const OTHER_IP = "198.51.100.78";
const DO_NOT_SHARE =
  "This sign-in could not be completed in this browser and has been cancelled. " +
  "Do not share this page's address with anyone. Start the connection again from your MCP client.";
const STATE_INVALID = "State expired or invalid";
const WARN_BOX = '<p class="warn" role="alert">';
const UNKNOWN_CLIENT = "not a known MCP client";
const DAY_S = 86_400;
const DAY_MS = DAY_S * 1000;
/** Middle of a 300 s window, so a limiter probe never straddles a boundary. */
const T0 = Date.UTC(2026, 10, 11, 0, 2, 30);

type Worker = ReturnType<typeof makeWorker>;

/** The limits and TTLs the apps ship with (no vars set). */
const SHIPPED = () => readOAuthHardeningConfig({});

/** `GET /authorize` with a fresh PKCE S256 pair; returns the page and the verifier. */
async function consentPage(w: Worker, params: Record<string, string>, ip?: string) {
  const verifier = generateCodeVerifier();
  const q = new URLSearchParams({
    response_type: "code",
    code_challenge: await sha256Base64Url(verifier),
    code_challenge_method: "S256",
    ...params,
  });
  const res = await w.fetchWorker(`${WORKER_ORIGIN}/authorize?${q.toString()}`, undefined, ip);
  return { res, html: await res.text(), verifier };
}

/** `POST /authorize` approve with the page's token and consent cookie; returns the state and binding cookie. */
async function approve(w: Worker, page: { res: Response; html: string }, ip?: string) {
  const consentToken = /name="consent_token" value="([^"]+)"/.exec(page.html)![1]!;
  const res = await w.fetchWorker(
    `${WORKER_ORIGIN}/authorize`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ consent_token: consentToken, action: "approve" }).toString(),
    },
    ip,
    { Cookie: cookiePair(page.res, "__Host-cm-consent-")! },
  );
  if (res.status !== 303) return { res, state: null, authCookie: null };
  const state = new URL(res.headers.get("location")!).searchParams.get("state")!;
  return { res, state, authCookie: cookiePair(res, `__Host-cm-auth-${state}=`)! };
}

async function registerAttackerClient(w: Worker, extra: Record<string, unknown> = {}, ip = ATTACKER_IP) {
  const reg = await registerClient(
    w,
    { client_name: "x", redirect_uris: [ATTACKER_REDIRECT], token_endpoint_auth_method: "none", ...extra },
    ip,
  );
  expect(reg.res.status).toBe(201);
  return { reg, clientId: reg.json.client_id as string };
}


describe("A-6(4) split flow: a refused /callback is cancelled, not kept for the attacker", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("FIXED (A-6(4)): the victim's cookie-less /callback deletes the stash and spends nothing; the attacker's replay is dead and no bearer resolves to the victim", async () => {
    const w = makeWorker();
    const upstream = stubUpstream({ sub: "victim-sub", email: "victim@tenant.example", refresh_token: "VICTIM-RT" });

    // 1. Attacker's browser: own client, consent approved by the attacker.
    const { clientId } = await registerAttackerClient(w);
    const page = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "a" }, ATTACKER_IP);
    expect(page.res.status).toBe(200);
    const approved = await approve(w, page, ATTACKER_IP);
    expect(approved.res.status).toBe(303);
    const state = approved.state!;
    expect(w.kv.data.has(`auth-state:${state}`)).toBe(true);

    // 2-3. The victim follows the forwarded IdP link, signs in, and the IdP
    // sends the victim's browser (no binding cookie) to /callback with the
    // victim's code.
    const victimLanding = `${WORKER_ORIGIN}/callback?code=VICTIM-UPSTREAM-CODE&state=${state}`;
    const refused = await w.fetchWorker(victimLanding, undefined, VICTIM_IP);
    expect(refused.status).toBe(400);
    // The exact text pins which check refused: the browser binding, not the
    // limiter (429), PKCE or a missing stash (STATE_INVALID).
    expect(await refused.text()).toBe(DO_NOT_SHARE);
    expect(w.kv.data.has(`auth-state:${state}`)).toBe(false);
    expect(upstream.calls).toHaveLength(0);

    // 4. "Send me the address so I can fix it": the attacker replays it with
    // the matching cookie.
    const replay = await w.fetchWorker(victimLanding, undefined, ATTACKER_IP, { Cookie: approved.authCookie! });
    expect(replay.status).toBe(400);
    expect(await replay.text()).toBe(STATE_INVALID);
    expect(upstream.calls).toHaveLength(0);

    // Nothing the attacker holds redeems: no grant or token exists at all,
    // a code forged in the library's `<userId>:<grantId>:<secret>` shape is
    // refused, and no string from the exchange resolves to the victim.
    expect(keysWith(w, "grant:")).toEqual([]);
    expect(keysWith(w, "token:")).toEqual([]);
    const forged = await exchangeCode(
      w,
      {
        grant_type: "authorization_code",
        code: "victim-sub:forged-grant:x",
        client_id: clientId,
        redirect_uri: ATTACKER_REDIRECT,
        code_verifier: page.verifier,
      },
      ATTACKER_IP,
    );
    expect(forged.res.status).toBe(400);
    for (const bearer of ["VICTIM-UPSTREAM-CODE", "victim-sub:forged-grant:x", state, approved.authCookie!]) {
      const who = await callMcp(w, bearer);
      expect(who.res.status).toBe(401);
      expect(who.json.props?.userId).toBeUndefined();
    }

    // Control: the attacker's own browser, on an untouched flow, still signs
    // in as the attacker. The fix cancels shared flows, not legitimate ones.
    vi.unstubAllGlobals();
    const own = stubUpstream({ sub: "attacker-sub", email: "attacker@attacker.example", refresh_token: "ATTACKER-RT" });
    const page2 = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "b" }, ATTACKER_IP);
    const approved2 = await approve(w, page2, ATTACKER_IP);
    const done = await w.fetchWorker(
      `${WORKER_ORIGIN}/callback?code=ATTACKER-UPSTREAM-CODE&state=${approved2.state}`,
      undefined,
      ATTACKER_IP,
      { Cookie: approved2.authCookie! },
    );
    expect(done.status).toBe(302);
    expect(own.calls.some((c) => c.url === UPSTREAM_TOKEN_URL)).toBe(true);
    const tokens = await exchangeCode(
      w,
      {
        grant_type: "authorization_code",
        code: new URL(done.headers.get("location")!).searchParams.get("code")!,
        client_id: clientId,
        redirect_uri: ATTACKER_REDIRECT,
        code_verifier: page2.verifier,
      },
      ATTACKER_IP,
    );
    expect(tokens.res.status).toBe(200);
    const me = await callMcp(w, tokens.json.access_token as string);
    expect(me.json.props?.userId).toBe("attacker-sub");
    expect(keysWith(w, "grant:victim-sub:")).toEqual([]);
  });
});

describe("A-6(1-3) consent page through the real composition", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("FIXED (A-6(1)): an attacker-started flow through the pinned Claude redirect shows the always-on warning before the client line", async () => {
    const w = makeWorker();
    // The hosted client's own registration (made when the ATTACKER added the connector).
    const reg = await registerClient(w, {
      client_name: "Claude",
      redirect_uris: [CLAUDE_CALLBACK],
      token_endpoint_auth_method: "none",
    });
    const page = await consentPage(w, {
      client_id: reg.json.client_id as string,
      redirect_uri: CLAUDE_CALLBACK,
      state: "STATE-BOUND-TO-THE-ATTACKERS-CLIENT-SESSION",
    });
    expect(page.res.status).toBe(200);
    const { html } = page;
    const box = html.indexOf(WARN_BOX);
    expect(box).toBeGreaterThan(html.indexOf("<h1>"));
    const boxEnd = html.indexOf("</p>", box);
    const boxText = html.slice(box, boxEnd);
    expect(boxText).toContain("only approve if you started this connection yourself");
    expect(boxText).toContain("choose <strong>Deny</strong>");
    // The pinned URI is known: no "unknown client" sentence anywhere.
    expect(html).not.toContain(UNKNOWN_CLIENT);
    expect(html).not.toContain("Warning:");
    // Page order: box, then the client's name as a quoted claim, then the form.
    const claim = html.indexOf("An application calling itself “Claude” is asking to use this POC Provider connector");
    expect(claim).toBeGreaterThan(boxEnd);
    expect(html.indexOf("<form")).toBeGreaterThan(claim);
    // The PoC's pre-fix line (the bare name as the subject) is gone.
    expect(html).not.toContain("Claude is asking to use this POC Provider connector");
  });

  it("FIXED (A-6(2)): the PoC's other claude.ai / claude.com redirects are unknown and warn, with the always-on box first", async () => {
    const w = makeWorker();
    for (const uri of [
      "https://claude.ai/anything/else?next=https://attacker.example",
      "https://claude.ai:8443/cb",
      "https://claude.com/redirect",
      "https://claude.ai/public/artifacts/0000",
    ]) {
      // The library registers and accepts any https URI; only the page's rule changed.
      const reg = await registerClient(w, { client_name: "Claude", redirect_uris: [uri], token_endpoint_auth_method: "none" });
      expect(reg.res.status).toBe(201);
      const page = await consentPage(w, { client_id: reg.json.client_id as string, redirect_uri: uri, state: "s" });
      expect(page.res.status, uri).toBe(200);
      expect(page.html, uri).toContain(UNKNOWN_CLIENT);
      expect(page.html, uri).toContain(`through <strong>${new URL(uri).host}</strong>`);
      expect(page.html.indexOf("started this connection yourself"), uri).toBeLessThan(page.html.indexOf("Warning:"));
    }
  });

  it("FIXED (A-6(3)): a loopback /callback on another port stays quiet; a loopback path that is not /callback or /oauth/callback warns", async () => {
    const w = makeWorker();
    const code = await registerClient(w, {
      client_name: "Claude Code",
      redirect_uris: ["http://localhost:6274/callback"],
      token_endpoint_auth_method: "none",
    });
    // RFC 8252 §7.3: the library accepts any loopback port, so the page cannot pin it.
    const quiet = await consentPage(w, {
      client_id: code.json.client_id as string,
      redirect_uri: "http://localhost:31337/callback",
      state: "s",
    });
    expect(quiet.res.status).toBe(200);
    expect(quiet.html).toContain("localhost:31337");
    expect(quiet.html).toContain(WARN_BOX);
    expect(quiet.html).toContain("started this connection yourself");
    expect(quiet.html).not.toContain(UNKNOWN_CLIENT);

    const collector = await registerClient(w, {
      client_name: "Claude Code",
      redirect_uris: ["http://localhost:6274/collect"],
      token_endpoint_auth_method: "none",
    });
    const warned = await consentPage(w, {
      client_id: collector.json.client_id as string,
      redirect_uri: "http://localhost:31337/collect",
      state: "s",
    });
    expect(warned.res.status).toBe(200);
    expect(warned.html).toContain(UNKNOWN_CLIENT);
    expect(warned.html).toContain("through <strong>localhost:31337</strong>");
  });

  it("FIXED (A-6): a 4 KB reassurance client_name registered through /register is cut to 64 characters and shown as a quoted claim after the warning", async () => {
    const w = makeWorker();
    const reassurance =
      "Claude (verified by Anthropic). Security notice: Claude is migrating its sign-in callback to a new domain this week, " +
      "so the warning below is expected and can be ignored. Claude";
    const { reg, clientId } = await registerAttackerClient(w, { client_name: reassurance + " ".repeat(4000) });
    // The library stores the name whole; the renderer is the only cap.
    expect((reg.json.client_name as string).length).toBeGreaterThan(4000);
    const page = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "s" });
    expect(page.res.status).toBe(200);
    expect(page.html.indexOf("can be ignored")).toBe(-1);
    const shown = /calling itself “([^”]*)”/.exec(page.html)![1]!;
    // 64 code points plus the ellipsis.
    expect(Array.from(shown)).toHaveLength(65);
    expect(shown.endsWith("…")).toBe(true);
    expect(shown.startsWith("Claude (verified by Anthropic). Security notice:")).toBe(true);
    expect(page.html.indexOf(WARN_BOX)).toBeLessThan(page.html.indexOf("calling itself"));
    // And the attacker's redirect is unknown, so the box also names it.
    expect(page.html).toContain("through <strong>attacker.example</strong>");
  });
});

describe("A-3 public legs through the real composition: throttled per IP, bodies capped", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(T0);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("FIXED (A-3): the 31st /authorize request from one IP (and its %61uthorize alias) is 429; a malformed escape is 400; another IP proceeds", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const { clientId } = await registerAttackerClient(w);

    // The PoC's 500 anonymous approvals (GET + POST each), until the limiter bites.
    const statuses: number[] = [];
    for (let i = 0; i < 500 && !statuses.includes(429); i++) {
      const page = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: `s${i}` }, ATTACKER_IP);
      statuses.push(page.res.status);
      if (page.res.status !== 200) break;
      statuses.push((await approve(w, page, ATTACKER_IP)).res.status);
    }
    expect(statuses.slice(0, 30)).toEqual(new Array(15).fill([200, 303]).flat());
    expect(statuses[30]).toBe(429);
    expect(statuses).toHaveLength(31);
    // Abuse that writes KV is bounded by the limit: 15 approvals, two keys each.
    expect(keysWith(w, "consent-used:").length + keysWith(w, "auth-state:").length).toBe(30);

    // Hono routes `/%61uthorize` to the consent handler; it shares the bucket.
    const alias = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "alias" }, ATTACKER_IP);
    expect(alias.res.status).toBe(429);
    const encoded = await w.fetchWorker(`${WORKER_ORIGIN}/%61uthorize?client_id=${clientId}`, undefined, ATTACKER_IP);
    expect(encoded.status).toBe(429);
    expect(encoded.headers.get("retry-after")).toMatch(/^\d+$/);
    // A path that does not percent-decode is refused outright, from any IP.
    const malformed = await w.fetchWorker(`${WORKER_ORIGIN}/authoriz%ZZ?client_id=${clientId}`, undefined, OTHER_IP);
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ error: "invalid_request", error_description: "Malformed request path" });

    // A different address has its own budget.
    const other = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "o" }, OTHER_IP);
    expect(other.res.status).toBe(200);
    expect((await approve(w, other, OTHER_IP)).res.status).toBe(303);
  });

  it("FIXED (A-3): the 11th /callback from one IP is 429 before the stash is read (the stash survives); another IP completes it; upstream calls stay within the limit", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const { clientId } = await registerAttackerClient(w);
    const upstreamBodies: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input.toString();
        if (!url.startsWith(UPSTREAM_TOKEN_URL)) throw new Error(`unexpected fetch ${url}`);
        upstreamBodies.push(String(init?.body));
        return new Response('{"error":"invalid_grant"}', { status: 400 });
      }),
    );

    // Ten genuine callbacks (right cookie each time) reach the handler, which
    // spends an upstream token request on every one.
    const flows: Array<{ state: string; authCookie: string }> = [];
    for (let i = 0; i < 11; i++) {
      const page = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: `s${i}` }, ATTACKER_IP);
      const approved = await approve(w, page, ATTACKER_IP);
      expect(approved.res.status).toBe(303);
      flows.push({ state: approved.state!, authCookie: approved.authCookie! });
    }
    const callback = (i: number, ip: string, path = "/callback") =>
      w.fetchWorker(
        `${WORKER_ORIGIN}${path}?code=attacker-chosen-${i}&state=${flows[i]!.state}`,
        undefined,
        ip,
        { Cookie: flows[i]!.authCookie },
      );
    for (let i = 0; i < 10; i++) expect((await callback(i, ATTACKER_IP)).status).toBe(502);
    expect(upstreamBodies).toHaveLength(10);
    expect(upstreamBodies.every((b) => b.includes("client_secret=upstream-app-client-secret"))).toBe(true);

    // The 11th is refused by the limiter, not by the handler: its stash is
    // untouched and no upstream call was made.
    const eleventh = await callback(10, ATTACKER_IP);
    expect(eleventh.status).toBe(429);
    expect(w.kv.data.has(`auth-state:${flows[10]!.state}`)).toBe(true);
    expect((await callback(10, ATTACKER_IP, "/%63allback")).status).toBe(429);
    expect(upstreamBodies).toHaveLength(10);

    // Another IP (its own bucket) completes that same flow: the handler runs,
    // consumes the stash and spends the upstream call.
    const elsewhere = await callback(10, OTHER_IP);
    expect(elsewhere.status).toBe(502);
    expect(w.kv.data.has(`auth-state:${flows[10]!.state}`)).toBe(false);
    expect(upstreamBodies).toHaveLength(11);
  });

  it("FIXED (A-3): 24 MiB chunked bodies to POST /register and POST /authorize are 413 after at most the cap plus one chunk, with no KV write and the library untouched", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const libSpy = vi.spyOn(w.oauth as unknown as { fetch: (...a: unknown[]) => unknown }, "fetch");
    const total = 24 * 1024 * 1024;

    const reg = meteredBody(total);
    const regRes = await w.fetchWorker(
      `${WORKER_ORIGIN}/register`,
      { method: "POST", headers: { "content-type": "application/json" }, body: reg.stream, duplex: "half" } as RequestInit,
      ATTACKER_IP,
    );
    expect(regRes.status).toBe(413);
    // The status alone is not the control: the library answers its own 413
    // after buffering the whole body. The bound on bytes pulled, and the
    // wrapper's own error text (the library's says "payload"), are.
    expect(reg.consumed()).toBeLessThanOrEqual(MAX_REGISTRATION_BODY_BYTES + CHUNK);
    expect(await regRes.json()).toEqual({ error: "invalid_request", error_description: "Request body too large" });
    expect(keysWith(w, "client:")).toEqual([]);

    const form = meteredBody(total);
    const formRes = await w.fetchWorker(
      `${WORKER_ORIGIN}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.stream,
        duplex: "half",
      } as RequestInit,
      ATTACKER_IP,
    );
    expect(formRes.status).toBe(413);
    expect(form.consumed()).toBeLessThanOrEqual(MAX_FORM_BODY_BYTES + CHUNK);
    expect(keysWith(w, "consent-used:")).toEqual([]);

    // A declared oversize length is refused before a byte is read.
    const declared = meteredBody(total);
    const declaredRes = await w.fetchWorker(
      `${WORKER_ORIGIN}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(total) },
        body: declared.stream,
        duplex: "half",
      } as RequestInit,
      ATTACKER_IP,
    );
    expect(declaredRes.status).toBe(413);
    expect(declared.consumed()).toBe(0);

    expect(libSpy).not.toHaveBeenCalled();
    // The limiter counted each attempt; nothing else was written.
    expect([...w.kv.data.keys()].every((k) => k.startsWith("ratelimit:"))).toBe(true);
  });
});

describe("A-5 client records through the real composition: 30 days unused, 120 days after a token call, no renewal on revocation", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(T0);
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("FIXED (A-5): /register gives the client a 30-day TTL; a code exchange and a refresh each renew it to 120 days; no clientreg: stamp", async () => {
    const w = makeWorker();
    stubUpstream({ sub: "victim-sub", email: "victim@tenant.example", refresh_token: "VICTIM-RT" });
    const reg = await registerClient(w, {
      client_name: "Claude",
      redirect_uris: [CLAUDE_CALLBACK],
      token_endpoint_auth_method: "none",
    });
    const clientId = reg.json.client_id as string;
    const record = () => w.kv.data.get(`client:${clientId}`);
    expect(record()!.opts).toEqual({ expirationTtl: 30 * DAY_S });

    const page = await consentPage(w, { client_id: clientId, redirect_uri: CLAUDE_CALLBACK, state: "s" });
    const approved = await approve(w, page);
    const done = await w.fetchWorker(
      `${WORKER_ORIGIN}/callback?code=UPSTREAM-CODE&state=${approved.state}`,
      undefined,
      undefined,
      { Cookie: approved.authCookie! },
    );
    expect(done.status).toBe(302);
    // `/callback` is not a refresh point: still the registration TTL.
    expect(record()!.opts).toEqual({ expirationTtl: 30 * DAY_S });
    const tokens = await exchangeCode(w, {
      grant_type: "authorization_code",
      code: new URL(done.headers.get("location")!).searchParams.get("code")!,
      client_id: clientId,
      redirect_uri: CLAUDE_CALLBACK,
      code_verifier: page.verifier,
    });
    expect(tokens.res.status).toBe(200);
    expect(record()!.opts).toEqual({ expirationTtl: 120 * DAY_S });

    // A refresh 10 days later renews again, so the record now outlives the
    // original 120 days by those 10.
    vi.setSystemTime(T0 + 10 * DAY_MS);
    const refreshed = await exchangeCode(w, {
      grant_type: "refresh_token",
      refresh_token: tokens.json.refresh_token as string,
      client_id: clientId,
    });
    expect(refreshed.res.status).toBe(200);
    expect(record()!.opts).toEqual({ expirationTtl: 120 * DAY_S });
    vi.setSystemTime(T0 + 125 * DAY_MS);
    expect(await w.kv.get(`client:${clientId}`)).not.toBeNull();
    vi.setSystemTime(T0 + 131 * DAY_MS);
    expect(await w.kv.get(`client:${clientId}`)).toBeNull();
    expect(keysWith(w, "clientreg:")).toEqual([]);
  });

  it("FIXED (A-5 review): a revocation 200 from /token (token=, no grant_type) leaves a public client at its 30-day TTL", async () => {
    const w = makeWorker();
    const { clientId } = await registerAttackerClient(w);
    const record = () => w.kv.data.get(`client:${clientId}`);
    expect(record()!.opts).toEqual({ expirationTtl: 30 * DAY_S });

    // Anyone who knows the public client_id can send this; the library
    // answers an empty 200 for a junk token.
    const revoke = await w.fetchWorker(
      `${WORKER_ORIGIN}/token`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: clientId, token: "junk" }).toString(),
      },
      OTHER_IP,
    );
    expect(revoke.status).toBe(200);
    expect(record()!.opts).toEqual({ expirationTtl: 30 * DAY_S });
    expect(record()!.opts?.expirationTtl).not.toBe(120 * DAY_S);

    // Nor does a failed code exchange renew it.
    const bad = await exchangeCode(w, {
      grant_type: "authorization_code",
      code: "nope",
      client_id: clientId,
      redirect_uri: ATTACKER_REDIRECT,
      code_verifier: generateCodeVerifier(),
    });
    expect(bad.res.status).toBe(400);
    expect(record()!.opts).toEqual({ expirationTtl: 30 * DAY_S });

    // Polling /authorize does not keep it alive either: at +31 d it is gone.
    vi.setSystemTime(T0 + 20 * DAY_MS);
    const poll = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "p" });
    expect(poll.res.status).toBe(200);
    expect(record()!.opts).toEqual({ expirationTtl: 30 * DAY_S });
    vi.setSystemTime(T0 + 31 * DAY_MS);
    const gone = await consentPage(w, { client_id: clientId, redirect_uri: ATTACKER_REDIRECT, state: "g" });
    expect(gone.res.status).toBe(400);
    expect(gone.html).toContain("Invalid client");
  });
});
