// D-2 (Medium) regression, end to end with the real Xero provider: query
// parameter names were never checked, and half of Xero's query parameters
// were declared only through `$ref`s the vendored spec could not resolve.
//
// Attacker: code running in the sandbox (prompt-injected model).
// Precondition: none beyond a session.
// Payloads: a method override (`$httpMethod`), a credential (`access_token`)
//   and an undeclared name on Xero operations.
// Control: each query name must be declared by the matched operation (the
//   merged spec now inlines `#/components/parameters/*`, so `unitdp`,
//   `summarizeErrors`, `pageSize`, … are declared); Xero has no standard
//   parameters; forbidden names are refused whatever is declared.
// Why the pre-fix code failed: every key was copied onto the upstream URL.

import { afterEach, describe, expect, it, vi } from "vitest";
import { buildProviderDocs, handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";

function run(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(async () => new Response('{"Status":"OK"}', { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  const audits: Array<Record<string, unknown>> = [];
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    if (typeof line === "string" && line.startsWith("AUDIT ")) audits.push(JSON.parse(line.slice(6)) as Record<string, unknown>);
  });
  const props: XeroProps = { refreshToken: "rt", tenantId: "tenant-a", userId: "user-a" };
  const promise = handleUpstreamRequest<XeroProps>({
    ctx,
    spec: xeroProvider.spec,
    surfaceReview: xeroProvider.surfaceReview,
    apiBaseUrl: xeroProvider.apiBaseUrl,
    deploymentName: "test",
    props,
    server: {} as never,
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken,
      userIdAccessor: (p) => p.userId,
      broker: { getOrRefreshAccessToken: async () => "AT" },
    },
    ...(xeroProvider.requestHeaders ? { requestHeaders: xeroProvider.requestHeaders } : {}),
    ...(xeroProvider.standardQueryParams ? { standardQueryParams: xeroProvider.standardQueryParams } : {}),
    audit: {},
    env: {},
  });
  return { promise, fetchSpy, audits, url: () => new URL(String(fetchSpy.mock.calls[0]![0])) };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Xero provider: query names (D-2)", () => {
  it("has no standard query parameters", () => {
    expect(xeroProvider.standardQueryParams).toBeUndefined();
  });

  it("FIXED (D-2): $httpMethod on getContacts is refused, nothing sent", async () => {
    const r = run({ method: "GET", path: "/api.xro/2.0/Contacts", query: { $httpMethod: "DELETE" } as never });
    await expect(r.promise).rejects.toThrow('Query parameter "$httpMethod" cannot be set from sandbox code');
    expect(r.fetchSpy).not.toHaveBeenCalled();
    expect(r.audits.at(-1)).toMatchObject({
      operationId: "xero.accounting.getContacts",
      reason: "forbidden-query-param",
      queryKeys: ["$httpMethod"],
    });
  });

  it("FIXED (D-2): access_token on getInvoices is refused", async () => {
    const r = run({ method: "GET", path: "/api.xro/2.0/Invoices", query: { access_token: "ATTACKER" } });
    await expect(r.promise).rejects.toThrow(/cannot be set from sandbox code/);
    expect(r.fetchSpy).not.toHaveBeenCalled();
  });

  it("FIXED (D-2): an undeclared name on the inspected createInvoices is refused before the inspector", async () => {
    const r = run({
      method: "PUT",
      path: "/api.xro/2.0/Invoices",
      body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT" }] },
      query: { notAParameterOfThisOperation: "1" },
    });
    await expect(r.promise).rejects.toThrow(
      'Operation xero.accounting.createInvoices does not accept query parameter "notAParameterOfThisOperation"; it accepts: summarizeErrors, unitdp',
    );
    expect(r.fetchSpy).not.toHaveBeenCalled();
  });

  it("control: getContacts where/page/includeArchived are forwarded", async () => {
    const r = run({
      method: "GET",
      path: "/api.xro/2.0/Contacts",
      query: { where: 'Name=="Acme"', page: 1, includeArchived: true },
    });
    await r.promise;
    expect(r.url().searchParams.get("where")).toBe('Name=="Acme"');
    expect(r.url().searchParams.get("page")).toBe("1");
    expect(r.url().searchParams.get("includeArchived")).toBe("true");
    expect(r.audits.at(-1)).toMatchObject({ decision: "allow", queryKeys: ["includeArchived", "page", "where"] });
  });

  it("control: createInvoices unitdp/summarizeErrors (declared through inlined $refs) are forwarded", async () => {
    const r = run({
      method: "PUT",
      path: "/api.xro/2.0/Invoices",
      body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT", Contact: { ContactID: "c1" } }] },
      query: { unitdp: 4, summarizeErrors: true },
    });
    await r.promise;
    expect(r.url().searchParams.get("unitdp")).toBe("4");
    expect(r.url().searchParams.get("summarizeErrors")).toBe("true");
  });

  it("control: comma-list parameters (type array, explode:false) take an array and go out comma-joined exactly as before", async () => {
    const ids = ["0f1e2d3c-0000-4000-8000-000000000001", "0f1e2d3c-0000-4000-8000-000000000002"];
    const r = run({
      method: "GET",
      path: "/api.xro/2.0/Invoices",
      query: { IDs: ids, Statuses: ["DRAFT", "AUTHORISED"], InvoiceNumbers: ["INV-1", 2] } as never,
    });
    await r.promise;
    // The pre-D-2 wire form: buildUpstreamUrl's String(array), URL-encoded.
    const expected = new URL("https://x.example/");
    expected.searchParams.set("IDs", String(ids));
    expected.searchParams.set("Statuses", String(["DRAFT", "AUTHORISED"]));
    expected.searchParams.set("InvoiceNumbers", String(["INV-1", 2]));
    expect(r.url().search).toBe(expected.search);
    expect(r.url().searchParams.get("Statuses")).toBe("DRAFT,AUTHORISED");
  });

  it("FIXED (D-2): a comma-list with a nested array or object element is refused", async () => {
    for (const IDs of [[["a"], "b"], [{ a: 1 }]]) {
      const r = run({ method: "GET", path: "/api.xro/2.0/Invoices", query: { IDs } as never });
      await expect(r.promise).rejects.toThrow(
        'Operation xero.accounting.getInvoices: query parameter "IDs" is a comma-separated list; its elements must be strings, numbers or booleans',
      );
      expect(r.fetchSpy).not.toHaveBeenCalled();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (D-2): an array for a non-list parameter (getContacts where) is refused with how to pass it", async () => {
    const r = run({ method: "GET", path: "/api.xro/2.0/Contacts", query: { where: ["a", "b"] } as never });
    await expect(r.promise).rejects.toThrow(/does not declare it as a comma-separated list, so pass one value per request/);
    expect(r.fetchSpy).not.toHaveBeenCalled();
  });

  it("sets no untrusted-field extension, so its docs carry no fence note (F2-8 is Optical-only)", () => {
    expect(xeroProvider.untrustedFieldExtension).toBeUndefined();
    expect(buildProviderDocs(xeroProvider, true, xeroProvider.spec).full).not.toContain("⟦untrusted⟧");
  });
});
