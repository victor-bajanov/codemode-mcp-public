// A-3 and A-5 (2026-11 review) — regressions for the public OAuth legs and
// the client-record lifetime, driven through the real worker composition
// (`oauth-worker-harness.ts`: the library's OAuthProvider, the scaffold's
// OAuth handler and `enforceOAuthHardening`, an in-memory KV that honours
// TTLs, a stubbed IdP).
//
// A-3. Attacker: any anonymous internet client, one IP address. Precondition:
//   none (one `/register`, or any existing client_id, supplies the client).
//   Payloads: 500 × (GET + POST /authorize); 100 approvals each followed by
//   `/callback` with an attacker-chosen `code`; 24 MiB request bodies
//   streamed to `POST /authorize` and `POST /register`.
//   Control: per-IP fixed-window limits on `/authorize` (30 per 300 s) and
//   `/callback` (10 per 300 s), and a streaming body cap (16 KiB for the
//   forms, 1 MiB for registration) answered 413 before the library runs.
//   Pre-fix: `enforceOAuthHardening` covered `POST /register` and
//   `POST /token` only, so every anonymous approval wrote two KV keys and every
//   `/callback` spent an upstream token request with the deployment's client
//   secret, with no 429 anywhere; `POST /authorize` read any body to the end
//   and `POST /register` without Content-Length read the whole body (tee'd)
//   before looking at its length.
//
// A-5. Attacker: any anonymous internet client (junk registrations); the
//   victim is a legitimate client whose grant expired or was revoked.
//   Payloads: the junk registrations, and the grant-removal step kept as the
//   regression input. Control: the library's `client:<id>` record carries a
//   KV TTL (30 days from registration, 120 days from each successful
//   `/token`); there is no scheduled sweep and no `clientreg:` stamp.
//   Pre-fix: a five-minute sweep read KV once per grant and once per
//   ungranted client on every run (junk turned into a recurring read bill and
//   outgrew one invocation's operation budget), and reaped a legitimate
//   client five minutes after its grant went away, so the user's
//   re-authorisation failed with "Invalid client".

import { existsSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CHUNK,
  cookiePair,
  exchangeCode,
  keysWith,
  makeWorker,
  meteredBody,
  registerClient,
  runBrowserLeg,
  stubUpstream,
  UPSTREAM_TOKEN_URL,
  WORKER_ORIGIN,
} from "./oauth-worker-harness";
import { readOAuthHardeningConfig } from "../config";
import { MAX_FORM_BODY_BYTES, MAX_REGISTRATION_BODY_BYTES } from "../oauth-hardening";
import { generateCodeVerifier, sha256Base64Url } from "../pkce";

const ATTACKER_IP = "198.51.100.99";
const OTHER_IP = "198.51.100.100";
const DAY_MS = 24 * 60 * 60 * 1000;
/** Middle of a 300 s window, so a test never straddles a window boundary. */
const T0 = Date.UTC(2026, 10, 9, 0, 2, 30);

/** The limits and TTLs the apps ship with (no vars set). */
const SHIPPED = () => readOAuthHardeningConfig({});

async function attackerClient(w: ReturnType<typeof makeWorker>) {
  const reg = await registerClient(w, {
    redirect_uris: ["https://attacker.example/cb"],
    token_endpoint_auth_method: "none",
  });
  return reg.json.client_id as string;
}

async function authorizeQuery(clientId: string) {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: "https://attacker.example/cb",
    state: "x",
    code_challenge: await sha256Base64Url(generateCodeVerifier()),
    code_challenge_method: "S256",
  });
}

/** GET /authorize then POST approve, exactly as an anonymous script would. */
async function consentAndApprove(w: ReturnType<typeof makeWorker>, clientId: string, ip = ATTACKER_IP) {
  const page = await w.fetchWorker(`${WORKER_ORIGIN}/authorize?${await authorizeQuery(clientId)}`, undefined, ip);
  if (page.status !== 200) return { page, approve: null };
  const token = /name="consent_token" value="([^"]+)"/.exec(await page.text())![1]!;
  const cookie = cookiePair(page, "__Host-cm-consent-")!;
  const approve = await w.fetchWorker(
    `${WORKER_ORIGIN}/authorize`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ consent_token: token, action: "approve" }).toString(),
    },
    ip,
    { Cookie: cookie },
  );
  return { page, approve };
}


describe("A-3 public OAuth legs: throttled, bodies capped", () => {
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

  it("FIXED (A-3): from one IP the 31st /authorize request in a window is 429; KV writes stay bounded; another IP is unaffected", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const clientId = await attackerClient(w);

    // The PoC's 500 anonymous approvals, request by request.
    const statuses: number[] = [];
    let retryAfter: string | null = null;
    for (let i = 0; i < 500 && statuses.length < 1000; i++) {
      const { page, approve } = await consentAndApprove(w, clientId);
      statuses.push(page.status);
      if (page.status === 429) retryAfter ??= page.headers.get("retry-after");
      if (approve) statuses.push(approve.status);
    }
    const first429 = statuses.indexOf(429) + 1;
    expect(first429).toBe(31);
    expect(statuses.slice(0, 30).every((s) => s === 200 || s === 303)).toBe(true);
    expect(statuses.slice(30).every((s) => s === 429)).toBe(true);
    expect(Number(retryAfter)).toBeGreaterThan(0);
    const writes = keysWith(w, "consent-used:").length + keysWith(w, "auth-state:").length;
    expect(writes).toBeLessThanOrEqual(2 * 30);
    // Hono decodes %xx before routing; the encoded path shares the bucket.
    const encoded = await w.fetchWorker(
      `${WORKER_ORIGIN}/%61uthorize?${await authorizeQuery(clientId)}`, undefined, ATTACKER_IP,
    );
    expect(encoded.status).toBe(429);

    // A different address has its own budget.
    const other = await consentAndApprove(w, clientId, OTHER_IP);
    expect(other.page.status).toBe(200);
    expect(other.approve!.status).toBe(303);
  });

  it("FIXED (A-3): the 11th /callback from one IP is 429 before the stash is read; upstream token requests stay within the limit", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const clientId = await attackerClient(w);
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
    const getSpy = vi.spyOn(w.kv, "get");

    const callbackStatuses: number[] = [];
    for (let i = 0; i < 11; i++) {
      const { approve } = await consentAndApprove(w, clientId);
      expect(approve!.status).toBe(303);
      const state = new URL(approve!.headers.get("location")!).searchParams.get("state")!;
      const authCookie = cookiePair(approve!, `__Host-cm-auth-${state}=`)!;
      getSpy.mockClear();
      const cb = await w.fetchWorker(
        `${WORKER_ORIGIN}/callback?code=attacker-chosen-${i}&state=${state}`,
        undefined,
        ATTACKER_IP,
        { Cookie: authCookie },
      );
      callbackStatuses.push(cb.status);
    }
    expect(callbackStatuses.slice(0, 10)).toEqual(new Array(10).fill(502));
    expect(callbackStatuses[10]).toBe(429);
    // The refused request read only the limiter's counter, never the stash.
    const readKeys = getSpy.mock.calls.map((c) => String(c[0]));
    expect(readKeys.every((k) => k.startsWith("ratelimit:callback:"))).toBe(true);
    expect(readKeys.some((k) => k.startsWith("auth-state:"))).toBe(false);
    expect(upstreamBodies.length).toBeLessThanOrEqual(10);
  });

  it("FIXED (A-3): POST /authorize with a 24 MiB body is 413 after at most 16 KiB + one chunk; no consent-used write", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const total = 24 * 1024 * 1024;
    const body = meteredBody(total);
    const res = await w.fetchWorker(
      `${WORKER_ORIGIN}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: body.stream,
        duplex: "half",
      } as RequestInit,
      ATTACKER_IP,
    );
    expect(res.status).toBe(413);
    expect(body.consumed()).toBeLessThanOrEqual(MAX_FORM_BODY_BYTES + CHUNK);
    expect(keysWith(w, "consent-used:")).toEqual([]);
  });

  it("FIXED (A-3): POST /authorize declaring Content-Length 25165824 is 413 with nothing read", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const body = meteredBody(24 * 1024 * 1024);
    const res = await w.fetchWorker(
      `${WORKER_ORIGIN}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "content-length": "25165824" },
        body: body.stream,
        duplex: "half",
      } as RequestInit,
      ATTACKER_IP,
    );
    expect(res.status).toBe(413);
    expect(body.consumed()).toBe(0);
  });

  it("FIXED (A-3): chunked POST /register with 24 MiB is 413 after at most 1 MiB + one chunk; the library is not reached and no client is written", async () => {
    const w = makeWorker({ limits: SHIPPED() });
    const libSpy = vi.spyOn(w.oauth as unknown as { fetch: (...a: unknown[]) => unknown }, "fetch");
    const total = 24 * 1024 * 1024; // 24x the 1 MiB the code allows
    const body = meteredBody(total);
    const res = await w.fetchWorker(
      `${WORKER_ORIGIN}/register`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: body.stream,
        duplex: "half",
      } as RequestInit,
      ATTACKER_IP,
    );
    expect(res.status).toBe(413);
    expect(body.consumed()).toBeLessThanOrEqual(MAX_REGISTRATION_BODY_BYTES + CHUNK);
    expect(libSpy).not.toHaveBeenCalled();
    expect(keysWith(w, "client:")).toEqual([]);
  });
});

describe("A-5 client records carry a TTL; there is no sweep", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("FIXED (A-5): the sweep module is gone, and every client /register writes carries the 30-day TTL", async () => {
    expect(existsSync(new URL("../oauth-client-sweep.ts", import.meta.url))).toBe(false);
    const w = makeWorker();
    // The PoC's junk registrations (a sample; each is a distinct never-used client).
    for (let i = 0; i < 20; i++) {
      await registerClient(w, {
        redirect_uris: ["https://attacker.example/cb"],
        token_endpoint_auth_method: "none",
      });
    }
    const clients = keysWith(w, "client:");
    expect(clients).toHaveLength(20);
    for (const k of clients) {
      expect(w.kv.data.get(k)!.opts).toEqual({ expirationTtl: 30 * 86_400 });
    }
    expect(keysWith(w, "clientreg:")).toEqual([]);
  });

  it("FIXED (A-5): a legitimate client outlives its removed grant (+40 d, +90 d) and is forgotten 120 days after its last token call", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(T0);
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const w = makeWorker();
    stubUpstream({ sub: "victim-sub", email: "victim@tenant.example", refresh_token: "VICTIM-RT" });
    const redirect = "https://claude.ai/api/mcp/auth_callback";
    const reg = await registerClient(w, {
      client_name: "Claude",
      redirect_uris: [redirect],
      token_endpoint_auth_method: "none",
    });
    const clientId = reg.json.client_id as string;
    expect(w.kv.data.get(`client:${clientId}`)!.opts).toEqual({ expirationTtl: 30 * 86_400 });
    const leg = await runBrowserLeg(w, {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirect,
      state: "s",
    });
    const tokens = await exchangeCode(w, {
      grant_type: "authorization_code",
      code: leg.finalLocation!.searchParams.get("code")!,
      client_id: clientId,
      redirect_uri: redirect,
      code_verifier: leg.codeVerifier!,
    });
    expect(tokens.res.status).toBe(200);
    // The token call renewed the record: grant life (90 d) + 30 d.
    expect(w.kv.data.get(`client:${clientId}`)!.opts).toEqual({ expirationTtl: 120 * 86_400 });
    const accessToken = tokens.json.access_token as string;

    // The grant goes away: the PoC's A-4 step, kept as the regression input
    // (the same state is reached with no attacker when KV expires the grant).
    const [userId, grantId] = accessToken.split(":");
    const attacker = await registerClient(w, {
      redirect_uris: ["https://attacker.example/cb"],
      token_endpoint_auth_method: "none",
    });
    await exchangeCode(w, {
      grant_type: "authorization_code",
      code: `${userId}:${grantId}:x`,
      client_id: attacker.json.client_id as string,
    });
    w.kv.data.delete(`grant:${userId}:${grantId}`);

    const reauthorise = async (state: string) => {
      const q = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirect,
        state,
        code_challenge: await sha256Base64Url(generateCodeVerifier()),
        code_challenge_method: "S256",
      });
      return w.fetchWorker(`${WORKER_ORIGIN}/authorize?${q.toString()}`);
    };

    // Pre-fix: reaped five minutes after the grant went away, then 400 "Invalid client".
    vi.setSystemTime(T0 + 40 * DAY_MS);
    expect((await reauthorise("again-40")).status).toBe(200);
    vi.setSystemTime(T0 + 90 * DAY_MS);
    expect((await reauthorise("again-90")).status).toBe(200);
    expect(keysWith(w, "clientreg:")).toEqual([]);

    // By design: 120 days after the last token call the record has expired.
    vi.setSystemTime(T0 + 121 * DAY_MS);
    const gone = await reauthorise("again-121");
    expect(gone.status).toBe(400);
    expect(await gone.text()).toContain("Invalid client");
  });

  it("FIXED (A-5 review): a multipart revocation naming a victim in a smuggled part leaves the victim at 30 days", async () => {
    const w = makeWorker();
    const victim = await registerClient(w, {
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      token_endpoint_auth_method: "none",
    });
    const attacker = await registerClient(w, {
      redirect_uris: ["https://attacker.example/cb"],
      token_endpoint_auth_method: "none",
    });
    const victimId = victim.json.client_id as string;
    const b = "XXB";
    const part = (n: string, v: string) =>
      `--${b}\r\nContent-Disposition: form-data; name="${n}"\r\n\r\n${v}\r\n`;
    const res = await w.fetchWorker(`${WORKER_ORIGIN}/token`, {
      method: "POST",
      headers: { "content-type": `multipart/form-data; boundary=${b}; application/x-www-form-urlencoded` },
      body:
        part("z", `&client_id=${victimId}&grant_type=refresh_token&`) +
        part("client_id", attacker.json.client_id as string) +
        part("token", "junk") +
        `--${b}--\r\n`,
    }, ATTACKER_IP);
    // The library treats it as the attacker revoking a junk token.
    expect(res.status).toBe(200);
    expect(w.kv.data.get(`client:${victimId}`)!.opts).toEqual({ expirationTtl: 30 * 86_400 });
  });
});
