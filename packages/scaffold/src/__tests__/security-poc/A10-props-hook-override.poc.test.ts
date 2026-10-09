// A10 — props assembly in /callback: spread order, subject derivation,
// hook override, missing `sub`.
//
// Status: FIXED (F-23) — `...hookProps` is spread first; the upstream's
// refresh token and userinfo sub/email/name always win.
//
//   FIXED (F-23, was CONFIRMED Informational): `...hookProps` was spread LAST,
//       so a provider's `completeAuthHook` could override `userId`,
//       `refreshToken` and `email` wholesale, and the identity used for the
//       broker DO, the KV slot key, the audit principalId and the grant's
//       `userId` followed the hook. Hooks are first-party code (Xero's returns
//       only `tenantId`); the trust statement is now explicit in code: a hook
//       can add fields and may supply `userId` only when the upstream
//       returned no string `sub`.
//   REFUTED: an upstream `userinfo` with no string `sub` (and no hook
//       supplying `userId`) does not mint a grant — 502, no
//       completeAuthorization call. Non-string `sub` (e.g. number) is ignored
//       rather than coerced.
//   REFUTED: `email`/`name` from userinfo are labels only; identity is `sub`.

import { describe, it, expect, afterEach, vi } from "vitest";
import { createOAuthHandler } from "../../oauth-handler";
import type { ApiProvider } from "../../api-provider";
import { sha256Base64Url } from "../../pkce";
import { POC_PROVIDER, UPSTREAM_TOKEN_URL, UPSTREAM_USERINFO_URL, type PocProps } from "./_harness-oauth-worker";

const STATE = "8a3c1f0e-2b4d-4c6e-9f10-1a2b3c4d5e6f";
const BINDING = "browser-binding-nonce";
const CALLBACK = `https://w/callback?code=C&state=${STATE}`;
const WITH_COOKIE = { headers: { cookie: `__Host-cm-auth-${STATE}=${BINDING}` } };

async function env(completeSpy: ReturnType<typeof vi.fn>) {
  const stash = JSON.stringify({
    oauthReqInfo: { clientId: "c", redirectUri: "https://claude.ai/cb", scope: ["mcp"] },
    codeVerifier: "v",
    bindingHash: await sha256Base64Url(BINDING),
  });
  return {
    OAUTH_PROVIDER: { completeAuthorization: completeSpy } as never,
    OAUTH_KV: { async get() { return stash; }, async put() {}, async delete() {} } as never,
    TEST_CLIENT_ID: "cid",
    TEST_CLIENT_SECRET: "csec",
  };
}

function stubUpstream(userinfo: unknown) {
  vi.stubGlobal("fetch", vi.fn<typeof fetch>(async (input: RequestInfo | URL) => {
    const u = typeof input === "string" ? input : input.toString();
    if (u.startsWith(UPSTREAM_TOKEN_URL)) return new Response(JSON.stringify({ access_token: "AT", refresh_token: "RT-upstream", expires_in: 3600 }), { status: 200 });
    if (u.startsWith(UPSTREAM_USERINFO_URL)) return new Response(JSON.stringify(userinfo), { status: 200 });
    throw new Error("unexpected " + u);
  }));
}

describe("A10 props assembly", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("FIXED (F-23): completeAuthHook output cannot override userId, refreshToken or email from userinfo/token", async () => {
    const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb" }));
    stubUpstream({ sub: "real-sub", email: "real@tenant" });
    const provider: ApiProvider<PocProps> = {
      ...POC_PROVIDER,
      completeAuthHook: async () => ({ userId: "hook-sub", refreshToken: "RT-from-hook", email: "hook@tenant", tenantId: "tenant-1" }),
    };
    const res = await createOAuthHandler(provider).request(CALLBACK, WITH_COOKIE, await env(completeSpy));
    expect(res.status).toBe(302);
    const args = (completeSpy.mock.calls as unknown as unknown[][])[0]![0] as { userId: string; props: PocProps; metadata: { label: string } };
    expect(args.userId).toBe("real-sub");
    expect(args.props.userId).toBe("real-sub");
    expect(args.props.refreshToken).toBe("RT-upstream");
    expect(args.props.email).toBe("real@tenant");
    expect(args.metadata.label).toBe("real@tenant");
    // A hook can still add its own fields (e.g. Xero's tenantId).
    expect(args.props.tenantId).toBe("tenant-1");
  });

  it("FIXED (F-23): a hook may supply userId only when userinfo carries no string sub", async () => {
    const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb" }));
    stubUpstream({ email: "real@tenant" });
    const provider: ApiProvider<PocProps> = {
      ...POC_PROVIDER,
      completeAuthHook: async () => ({ userId: "hook-sub", refreshToken: "RT-from-hook" }),
    };
    const res = await createOAuthHandler(provider).request(CALLBACK, WITH_COOKIE, await env(completeSpy));
    expect(res.status).toBe(302);
    const args = (completeSpy.mock.calls as unknown as unknown[][])[0]![0] as { userId: string; props: PocProps };
    expect(args.userId).toBe("hook-sub");
    expect(args.props.userId).toBe("hook-sub");
    expect(args.props.refreshToken).toBe("RT-upstream");
  });

  it("REFUTED: userinfo without a string `sub` (and no hook) mints no grant", async () => {
    for (const ui of [{ email: "a@b" }, { sub: 12345, email: "a@b" }, { sub: "", email: "a@b" }]) {
      const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb" }));
      stubUpstream(ui);
      const res = await createOAuthHandler(POC_PROVIDER).request(CALLBACK, WITH_COOKIE, await env(completeSpy));
      expect(res.status).toBe(502);
      expect(await res.text()).toContain("no subject identifier");
      expect(completeSpy).not.toHaveBeenCalled();
    }
  });

  it("REFUTED: identity is `sub`; email is only the grant label", async () => {
    const completeSpy = vi.fn(async () => ({ redirectTo: "https://claude.ai/cb" }));
    stubUpstream({ sub: "sub-A", email: "shared-mailbox@tenant" });
    await createOAuthHandler(POC_PROVIDER).request(CALLBACK, WITH_COOKIE, await env(completeSpy));
    const args = (completeSpy.mock.calls as unknown as unknown[][])[0]![0] as { userId: string; metadata: { label: string } };
    expect(args.userId).toBe("sub-A");
    expect(args.metadata.label).toBe("shared-mailbox@tenant");
  });
});
