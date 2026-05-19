// completeAuthHook fetches GET /connections, validates exactly one tenant was granted,
// and returns { tenantId } so it gets merged into props before completeAuthorization.

import { describe, it, expect, vi, afterEach } from "vitest";
import { xeroProvider } from "../index";

describe("xeroProvider.completeAuthHook", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns tenantId from a single-tenant /connections response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify([
        { tenantId: "tnt-001", tenantName: "Demo Company (AU)" },
      ]), { status: 200, headers: { "content-type": "application/json" } }),
    ));

    const out = await xeroProvider.completeAuthHook!({
      tokens: { access_token: "AT", refresh_token: "RT", expires_in: 1800 },
      userInfo: null,
      env: {} as never,
    });
    expect(out).toEqual({ tenantId: "tnt-001" });
  });

  it("rejects when /connections returns zero tenants", async () => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    ));

    await expect(xeroProvider.completeAuthHook!({
      tokens: { access_token: "AT", refresh_token: "RT", expires_in: 1800 },
      userInfo: null,
      env: {} as never,
    })).rejects.toThrow(/no tenant connections/i);
  });

  it("rejects when /connections returns multiple tenants and lists their names in the error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify([
        { tenantId: "t1", tenantName: "Demo Company (AU)" },
        { tenantId: "t2", tenantName: "Real Org Pty Ltd" },
      ]), { status: 200, headers: { "content-type": "application/json" } }),
    ));

    await expect(xeroProvider.completeAuthHook!({
      tokens: { access_token: "AT", refresh_token: "RT", expires_in: 1800 },
      userInfo: null,
      env: {} as never,
    })).rejects.toThrow(/Demo Company \(AU\), Real Org Pty Ltd/);
  });

  it("rejects when /connections itself fails (4xx)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response("forbidden", { status: 403 }),
    ));

    await expect(xeroProvider.completeAuthHook!({
      tokens: { access_token: "AT", refresh_token: "RT", expires_in: 1800 },
      userInfo: null,
      env: {} as never,
    })).rejects.toThrow(/Xero \/connections: 403/);
  });
});
