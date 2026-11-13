// D-2 (Medium) regression, end to end with the real Gmail + Calendar
// provider: query parameter names were never checked.
//
// Attacker: code running in the sandbox (prompt-injected model) with a valid
//   session.
// Precondition: none beyond a session.
// Payloads: Google system parameters that override the method or headers
//   (`$httpMethod=DELETE` on messages.get, `$httpHeaders` carrying the refused
//   X-HTTP-Method-Override header on filters.get), sandbox-supplied
//   credentials (`access_token`, `oauth_token`, `key`) and an undeclared name
//   on drafts.create, and the same overrides on the inspected messages.send.
// Control: each query name must be declared by the matched operation or be
//   one of Gmail's `standardQueryParams` (`fields`, `prettyPrint`,
//   `quotaUser`, `upload_protocol`); `$`-prefixed, credential and
//   method-override names are refused whatever is declared. Checked before
//   the URL is built; the deny audit line carries the names.
// Why the pre-fix code failed: every key was copied onto the upstream URL and
//   the audit line recorded two harmless reads.

import { describe, it, expect, vi, afterEach } from "vitest";
import { buildProviderDocs, handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "ok@allowed.example", ALLOW_PII_IN_LOGS: "true" };

function run(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(async () => new Response('{"id":"x"}', { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  const audits: Array<Record<string, unknown>> = [];
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    if (typeof line === "string" && line.startsWith("AUDIT ")) audits.push(JSON.parse(line.slice(6)) as Record<string, unknown>);
  });
  const promise = handleUpstreamRequest({
    ctx,
    spec: gmailProvider.spec,
    surfaceReview: gmailProvider.surfaceReview,
    apiBaseUrl: gmailProvider.apiBaseUrl,
    deploymentName: "test",
    props: { refreshToken: "r", userId: "u" },
    server: {} as never,
    oauth: {
      refreshTokenAccessor: () => "r",
      userIdAccessor: () => "u",
      broker: { getOrRefreshAccessToken: async () => "AT" },
    },
    ...(gmailProvider.standardQueryParams ? { standardQueryParams: gmailProvider.standardQueryParams } : {}),
    audit: {},
    env: ENV as { ALLOW_PII_IN_LOGS?: string },
  });
  return { promise, fetchSpy, audits, urls: () => fetchSpy.mock.calls.map((c) => new URL(String(c[0]))) };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Gmail provider: query names (D-2)", () => {
  it("declares Google's response-shaping/quota parameters as standard, nothing else", () => {
    expect(gmailProvider.standardQueryParams).toEqual(["fields", "prettyPrint", "quotaUser", "upload_protocol"]);
  });

  it("FIXED (D-2): $httpMethod=DELETE on messages.get is refused, audited with its name, nothing sent", async () => {
    const r = run({ method: "GET", path: "/gmail/v1/users/me/messages/18c0ffee", query: { $httpMethod: "DELETE" } as never });
    await expect(r.promise).rejects.toThrow('Query parameter "$httpMethod" cannot be set from sandbox code');
    expect(r.fetchSpy).not.toHaveBeenCalled();
    expect(r.audits.at(-1)).toMatchObject({
      operationId: "gmail.users.messages.get",
      decision: "deny",
      reason: "forbidden-query-param",
      queryKeys: ["$httpMethod"],
    });
  });

  it("FIXED (D-2): $httpHeaders carrying the refused override header on filters.get is refused", async () => {
    const r = run({
      method: "GET",
      path: "/gmail/v1/users/me/settings/filters/FILTER-ID",
      query: { $httpHeaders: "X-HTTP-Method-Override:DELETE\r\n" } as never,
    });
    await expect(r.promise).rejects.toThrow(/cannot be set from sandbox code/);
    expect(r.fetchSpy).not.toHaveBeenCalled();
  });

  for (const [name, value] of [
    ["access_token", "ATTACKER-OWNED-TOKEN"],
    ["oauth_token", "x"],
    ["key", "ATTACKER-API-KEY"],
  ] as const) {
    it(`FIXED (D-2): sandbox credential "${name}" on drafts.create is refused`, async () => {
      const r = run({ method: "POST", path: "/gmail/v1/users/me/drafts", body: { message: { raw: "QQ" } }, query: { [name]: value } });
      await expect(r.promise).rejects.toThrow(`Query parameter "${name}" cannot be set from sandbox code`);
      expect(r.fetchSpy).not.toHaveBeenCalled();
      expect(JSON.stringify(r.audits)).not.toContain(value);
    });
  }

  it("FIXED (D-2): an undeclared name on drafts.create is refused (undeclared-query-param)", async () => {
    const r = run({
      method: "POST",
      path: "/gmail/v1/users/me/drafts",
      body: { message: { raw: "QQ" } },
      query: { notAParameterOfThisOperation: 1 },
    });
    await expect(r.promise).rejects.toThrow(
      'Operation gmail.users.drafts.create does not accept query parameter "notAParameterOfThisOperation"; it accepts: fields, prettyPrint, quotaUser, upload_protocol',
    );
    expect(r.audits.at(-1)).toMatchObject({ reason: "undeclared-query-param", queryKeys: ["notAParameterOfThisOperation"] });
  });

  it("FIXED (D-2): on the inspected messages.send the overrides are refused before the inspector rules", async () => {
    const raw = Buffer.from("To: ok@allowed.example\r\nSubject: hi\r\n\r\nbody").toString("base64url");
    const r = run({
      method: "POST",
      path: "/gmail/v1/users/me/messages/send",
      body: { raw },
      query: { $httpHeaders: "Content-Type:message/rfc822\r\n", uploadType: "media", $httpMethod: "PUT" } as never,
    });
    await expect(r.promise).rejects.toThrow(/cannot be set from sandbox code/);
    expect(r.fetchSpy).not.toHaveBeenCalled();
    expect(r.audits.at(-1)).toMatchObject({
      operationId: "gmail.users.messages.send",
      reason: "forbidden-query-param",
      queryKeys: ["$httpHeaders", "$httpMethod", "uploadType"],
    });
  });

  it("control: messages.get format=full and fields=id are forwarded", async () => {
    const r = run({ method: "GET", path: "/gmail/v1/users/me/messages/18c0ffee", query: { format: "full", fields: "id" } });
    await r.promise;
    expect(r.urls()[0]!.search).toBe("?format=full&fields=id");
    expect(r.audits.at(-1)).toMatchObject({ decision: "allow", queryKeys: ["fields", "format"] });
  });

  it("control: calendar events.list timeMin is forwarded", async () => {
    const r = run({ method: "GET", path: "/calendar/v3/calendars/primary/events", query: { timeMin: "2026-11-01T00:00:00Z", singleEvents: true } });
    await r.promise;
    expect(r.urls()[0]!.searchParams.get("timeMin")).toBe("2026-11-01T00:00:00Z");
    expect(r.urls()[0]!.searchParams.get("singleEvents")).toBe("true");
  });

  it("documented limit: a repeated parameter given as an array is refused (one value per name)", async () => {
    const r = run({
      method: "GET",
      path: "/gmail/v1/users/me/messages/18c0ffee",
      query: { format: "metadata", metadataHeaders: ["From", "Subject"] } as never,
    });
    await expect(r.promise).rejects.toThrow(/query parameter "metadataHeaders" must be a string, number or boolean/);
  });

  it("sets no untrusted-field extension, so its docs carry no fence note (F2-8 is Optical-only)", () => {
    expect(gmailProvider.untrustedFieldExtension).toBeUndefined();
    expect(buildProviderDocs(gmailProvider, true, gmailProvider.spec).full).not.toContain("⟦untrusted⟧");
  });
});
