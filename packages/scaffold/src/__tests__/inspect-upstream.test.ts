// packages/scaffold/src/__tests__/inspect-upstream.test.ts
//
// F1-2b (High) scaffold support: an inspector could not see which target a
// write is aimed at, and nothing host-side could read upstream state before
// deciding.
//
// Attacker: code running in the sandbox (prompt-injected model) that edits a
//   resource it does not own (e.g. a Calendar event organised by someone
//   else), counting on the inspector judging the body alone.
// Precondition: an operation whose safety depends on stored upstream state
//   (who organises the stored event, who is already invited).
// Payloads: writes to targets whose stored state should refuse them; hooks
//   that try to read gated, denied, inspected or unmatched paths, more than
//   four paths, or read after an aborted run; a write whose body is opaque or
//   staged on an operation with an upstream hook.
// Control: inspectors receive the decoded, frozen `pathParams`; the
//   `inspectUpstream` hook runs after a non-deny sync inspection and may only
//   GET plain-allow reads through the same request handler (path guards,
//   query policy, audit, no redirects), at most four per request; a failed
//   lookup or a misbehaving hook denies the write (fail closed); the hook
//   never runs on an opaque or staged body.
// Why the pre-fix code failed: `InspectRequest` carried no path parameters
//   and there was no hook, so a body-only inspector allowed the write
//   whatever the stored target was.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx, type HandleArgs } from "../request-handler";
import { createUpstreamLookup, MAX_UPSTREAM_LOOKUPS } from "../index";
import { inspectUpstreamProblems } from "../testing";
import { mintFileHandle, mintToken } from "../staging/tokens";
import type { TransferGateLike } from "../staging/gate-dep";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { InspectRequest, InspectResult, SurfaceReview, UpstreamLookup } from "@local/shared";
import { encodeLookupPath } from "@local/shared";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/things/{id}": {
      get: {
        operationId: "getThing",
        parameters: [
          { name: "id", in: "path", required: true, schema: { type: "string" } },
          { name: "fields", in: "query", schema: { type: "string" } },
        ],
        responses: { "200": { description: "OK" } },
      },
      patch: {
        operationId: "patchThing",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        requestBody: { content: { "application/json": { schema: { type: "object", properties: { title: { type: "string" } } } } } },
        responses: { "200": { description: "OK" } },
      },
      put: {
        operationId: "putThing",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        requestBody: { content: { "application/octet-stream": { schema: { type: "string" } } } },
        responses: { "200": { description: "OK" } },
      },
    },
    "/things": {
      post: {
        operationId: "createThing",
        requestBody: { content: { "application/json": { schema: { type: "object" } } } },
        responses: { "200": { description: "OK" } },
      },
    },
    "/secret/{id}": {
      get: {
        operationId: "getSecret",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
    "/inspected/{id}": {
      get: {
        operationId: "getInspected",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
    "/elicited/{id}": {
      get: {
        operationId: "getElicited",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

/** The stored things the fake upstream answers GET /things/<id> with. */
const STORED: Record<string, { status: number; body: unknown }> = {};

const syncSpy = vi.fn<(req: InspectRequest) => void>();
let syncDecision: InspectResult = { decision: "allow" };

type Hook = (req: InspectRequest, lookup: UpstreamLookup) => Promise<InspectResult>;
const hookSpy = vi.fn<(req: InspectRequest) => void>();
const seen: Array<{ status: number; body: unknown }> = [];

/** Default hook: read the stored thing; deny unless the user owns it; ask
 *  when it already has guests. */
const defaultHook: Hook = async (req, lookup) => {
  const id = req.pathParams?.["id"];
  if (id === undefined) return { decision: "deny", category: "malformed", reason: "no-id" };
  const r = await lookup.get(`/things/${encodeURIComponent(id)}`);
  seen.push(r);
  if (r.status < 200 || r.status >= 300) {
    return { decision: "deny", category: "malformed", reason: "read-failed", message: `stored read failed (HTTP ${r.status})` };
  }
  const body = r.body as { owner?: unknown; guests?: unknown };
  if (body.owner !== "me") {
    return { decision: "deny", category: "external_data_flow", reason: "not-owner", message: "This thing belongs to someone else." };
  }
  if (Array.isArray(body.guests) && body.guests.length > 0) {
    return {
      decision: "elicit",
      category: "external_data_flow",
      reason: "has-guests",
      summary: { guests: body.guests.join(", ") },
    };
  }
  return { decision: "allow" };
};
let hook: Hook = defaultHook;

const SR: SurfaceReview = {
  getThing: { decision: "allow", category: "standard_read" },
  patchThing: {
    decision: "allow",
    inspect: (req) => {
      syncSpy(req);
      return {
        ...syncDecision,
        summary: { ...(syncDecision.summary ?? {}), target: req.pathParams?.["id"] ?? "(none)" },
      };
    },
    inspectUpstream: (req, lookup) => {
      hookSpy(req);
      return hook(req, lookup);
    },
  },
  putThing: {
    decision: "allow",
    acceptsStaged: true,
    inspect: () => ({ decision: "allow" }),
    inspectUpstream: (req, lookup) => {
      hookSpy(req);
      return hook(req, lookup);
    },
  },
  createThing: { decision: "allow", category: "standard_write" },
  getSecret: { decision: "deny", category: "credential_change", reasoning: "test" },
  getInspected: { decision: "allow", inspect: () => ({ decision: "allow" }) },
  getElicited: { decision: "elicit", category: "persistent_state" },
};

function harness(
  ctx: UpstreamCtx,
  opts: { server?: unknown; extra?: Partial<HandleArgs<Record<string, unknown>>> } = {},
) {
  const fetchSpy = vi.fn<typeof fetch>(async (url: RequestInfo | URL, init?: RequestInit) => {
    const u = new URL(typeof url === "string" ? url : url.toString());
    if (u.pathname === "/token") {
      return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
    }
    if (u.pathname === "/things/boom") {
      await new Promise((r) => setTimeout(r, 5));
      throw new TypeError("network down");
    }
    if (u.pathname === "/things/hang") {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
      });
    }
    const m = /^\/things\/([^/]+)$/.exec(u.pathname);
    if ((init?.method ?? "GET") === "GET" && m) {
      const stored = STORED[decodeURIComponent(m[1]!)] ?? { status: 404, body: { error: "not found" } };
      return new Response(JSON.stringify(stored.body), { status: stored.status, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const elicitInput = vi.fn(async (_params: unknown, _options?: unknown) => ({ action: "accept", content: { confirm: true } }));
  const server = opts.server ?? { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } };
  const args: HandleArgs<Record<string, unknown>> = {
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "test",
    props: { refreshToken: "RT-1", userId: "test-user" },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: server as any,
    env: { ALLOW_PII_IN_LOGS: "true" },
    audit: {},
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken as string,
      userIdAccessor: (p) => p.userId as string | undefined,
      broker: {
        getOrRefreshAccessToken: async () => {
          await fetch("https://api.example.com/token", { method: "POST" });
          return "AT-x";
        },
      },
    },
    ...opts.extra,
  };
  return {
    args,
    fetchSpy,
    elicitInput,
    audit: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>),
    upstream: () =>
      fetchSpy.mock.calls
        .filter((c) => !String(c[0]).endsWith("/token"))
        .map((c) => ({ url: String(c[0]), init: c[1] ?? {} })),
    messages: () => elicitInput.mock.calls.map((c) => (c[0] as { message: string }).message),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  syncSpy.mockReset();
  hookSpy.mockReset();
  syncDecision = { decision: "allow" };
  hook = defaultHook;
  seen.length = 0;
  for (const k of Object.keys(STORED)) delete STORED[k];
});

describe("pathParams reach inspectors", () => {
  it("FIXED (F1-2b): the sync inspector and the hook get the decoded, frozen path parameters", async () => {
    STORED["a b"] = { status: 200, body: { owner: "me" } };
    const h = harness({ method: "PATCH", path: "/things/a%20b", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    const req = syncSpy.mock.calls[0]![0];
    expect(req.pathParams).toEqual({ id: "a b" });
    expect(Object.isFrozen(req.pathParams)).toBe(true);
    expect(req.body).toEqual({ title: "x" });
    expect(hookSpy.mock.calls[0]![0].pathParams).toEqual({ id: "a b" });
  });

  it("pathParams are present on a body-less request too", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    const h = harness({ method: "PATCH", path: "/things/t1" });
    await handleUpstreamRequest(h.args);
    expect(syncSpy.mock.calls[0]![0].pathParams).toEqual({ id: "t1" });
  });
});

describe("inspectUpstream: ordering, decisions and audit", () => {
  it("FIXED (F1-2b): a write to a thing someone else owns is denied after the lookup; the PATCH is never sent", async () => {
    STORED["t1"] = { status: 200, body: { owner: "other" } };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "SECRET" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("This thing belongs to someone else.");
    const up = h.upstream();
    expect(up).toHaveLength(1);
    expect(up[0]!.url).toBe("https://api.example.com/things/t1");
    expect(up[0]!.init.method).toBe("GET");
    expect(up[0]!.init.redirect).toBe("manual");
    expect(new Headers(up[0]!.init.headers).get("authorization")).toBe("Bearer AT-x");
    const audit = h.audit();
    const getIdx = audit.findIndex((a) => a.operationId === "getThing" && a.decision === "allow" && a.upstreamStatus === 200);
    const denyIdx = audit.findIndex((a) => a.operationId === "patchThing" && a.decision === "deny" && a.reason === "not-owner");
    expect(getIdx).toBeGreaterThanOrEqual(0);
    expect(denyIdx).toBeGreaterThan(getIdx);
    expect(audit[denyIdx]).toMatchObject({ category: "external_data_flow" });
  });

  it("the user's own thing: the GET goes out first, then the PATCH with the judged body", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "ok" } });
    const res = (await handleUpstreamRequest(h.args)) as { success: boolean };
    expect(res.success).toBe(true);
    const up = h.upstream();
    expect(up.map((c) => c.init.method)).toEqual(["GET", "PATCH"]);
    expect(up[1]!.init.body).toBe('{"title":"ok"}');
    expect(new Headers(up[1]!.init.headers).get("authorization")).toBe("Bearer AT-x");
  });

  it("a sync inspector deny skips the hook: no lookup, no token, nothing fetched", async () => {
    syncDecision = { decision: "deny", category: "malformed", reason: "sync-no" };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
    expect(hookSpy).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "sync-no" });
  });

  it("has-guests: the dialog shows the merged summary; confirm sends the PATCH", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me", guests: ["outsider@evil.example"] } };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    const [msg] = h.messages();
    expect(msg).toContain("Request: PATCH /things/t1");
    expect(msg).toContain('guests: "outsider@evil.example"');
    expect(msg).toContain('target: "t1"');
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET", "PATCH"]);
    expect(h.audit().find((a) => a.operationId === "patchThing" && a.decision === "elicit")).toMatchObject({
      reason: "has-guests",
      elicitationOutcome: "accepted",
    });
  });

  it("has-guests on a client without elicitation: unsupported, the PATCH is not sent", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me", guests: ["outsider@evil.example"] } };
    const elicitInput = vi.fn();
    const h = harness(
      { method: "PATCH", path: "/things/t1", body: { title: "x" } },
      { server: { server: { getClientCapabilities: () => ({ tools: {} }), elicitInput } } },
    );
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/outcome: unsupported/);
    expect(elicitInput).not.toHaveBeenCalled();
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET"]);
  });

  it("a hook allow does not wash out a sync elicit (labels stay the sync inspector's)", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    syncDecision = { decision: "elicit", category: "persistent_state", reason: "sync-ask" };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    expect(h.elicitInput).toHaveBeenCalledTimes(1);
    expect(h.audit().find((a) => a.operationId === "patchThing" && a.decision === "elicit")).toMatchObject({
      reason: "sync-ask",
      category: "persistent_state",
    });
  });

  it("a hook allow carrying its own labels does not relabel a sync elicit", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    syncDecision = { decision: "elicit", category: "persistent_state", reason: "sync-ask" };
    hook = async () => ({ decision: "allow", category: "standard_write", reason: "hook-ok" });
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    expect(h.audit().find((a) => a.operationId === "patchThing" && a.decision === "elicit")).toMatchObject({
      reason: "sync-ask",
      category: "persistent_state",
    });
  });

  it("when sync and hook both elicit, the hook's labels win", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me", guests: ["outsider@evil.example"] } };
    syncDecision = { decision: "elicit", category: "persistent_state", reason: "sync-ask" };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    expect(h.audit().find((a) => a.operationId === "patchThing" && a.decision === "elicit")).toMatchObject({
      reason: "has-guests",
      category: "external_data_flow",
    });
  });

  it("a non-2xx read is passed through to the hook (status and parsed body), which decides", async () => {
    STORED["t1"] = { status: 500, body: { error: "boom" } };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("stored read failed (HTTP 500)");
    expect(seen).toEqual([{ status: 500, body: { error: "boom" } }]);
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET"]);
  });

  it("a 404 read is passed through as status 404", async () => {
    const h = harness({ method: "PATCH", path: "/things/missing", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("stored read failed (HTTP 404)");
    expect(seen[0]!.status).toBe(404);
  });

  it("a declared query name rides on the lookup; an undeclared one is refused before any fetch", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    hook = async (_req, lookup) => {
      const r = await lookup.get("/things/t1", { fields: "owner" });
      return (r.body as { owner?: string }).owner === "me" ? { decision: "allow" } : { decision: "deny" };
    };
    const ok = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await handleUpstreamRequest(ok.args);
    expect(ok.upstream()[0]!.url).toBe("https://api.example.com/things/t1?fields=owner");

    vi.restoreAllMocks();
    hook = async (_req, lookup) => {
      await lookup.get("/things/t1", { evil: "1" });
      return { decision: "allow" };
    };
    const bad = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(bad.args)).rejects.toThrow();
    expect(bad.upstream()).toEqual([]);
  });

  it("the lookup takes no transfer-gate slot and no gate lease", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    const acquire = vi.fn(async () => () => {});
    const lease = vi.fn(async () => {});
    const h = harness(
      { method: "PATCH", path: "/things/t1", body: { title: "x" } },
      { extra: { transferGate: { acquire } as unknown as TransferGateLike, gateLease: { acquire: lease } } },
    );
    await handleUpstreamRequest(h.args);
    expect(acquire).not.toHaveBeenCalled();
    expect(lease).not.toHaveBeenCalled();
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET", "PATCH"]);
  });
});

describe("inspectUpstream: lookups are restricted and fail closed", () => {
  const refused: Array<[string, string]> = [
    ["a denied read", "/secret/1"],
    ["an inspected read", "/inspected/1"],
    ["an approval-gated read", "/elicited/1"],
    ["an unmatched path", "/nowhere/1"],
    ["a path with a GET-less template", "/things"],
    ["an unsafe path", "/things/../secret/1"],
  ];
  for (const [name, path] of refused) {
    it(`FIXED (F1-2b): ${name} (${path}) is refused before any fetch and the write is denied`, async () => {
      hook = async (_req, lookup) => {
        await lookup.get(path);
        return { decision: "allow" };
      };
      const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
      expect(h.upstream()).toEqual([]);
      expect(h.audit().at(-1)).toMatchObject({
        operationId: "patchThing",
        decision: "deny",
        reason: "upstream-inspect-failed",
      });
    });
  }

  it(`a lookup past the cap of ${MAX_UPSTREAM_LOOKUPS} is refused; the write is denied`, async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    expect(MAX_UPSTREAM_LOOKUPS).toBe(4);
    hook = async (_req, lookup) => {
      for (let i = 0; i < 5; i++) await lookup.get("/things/t1");
      return { decision: "allow" };
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/at most 4/);
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET", "GET", "GET", "GET"]);
  });

  it("a hook that swallows a failed lookup and allows is still denied", async () => {
    hook = async (_req, lookup) => {
      try {
        await lookup.get("/secret/1");
      } catch {
        /* pretend nothing happened */
      }
      return { decision: "allow" };
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
    expect(h.upstream()).toEqual([]);
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "upstream-inspect-failed" });
  });

  it("a hook that throws a plain error denies the write", async () => {
    hook = async () => {
      throw new TypeError("oops");
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied/);
    expect(h.upstream()).toEqual([]);
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "upstream-inspect-failed" });
  });

  const bogus: Array<[string, unknown]> = [
    ["an unknown decision", { decision: "maybe" }],
    ["a non-object", "allow"],
    ["undefined", undefined],
  ];
  for (const [name, result] of bogus) {
    it(`a hook returning ${name} denies the write`, async () => {
      hook = async () => result as InspectResult;
      const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
      expect(h.upstream()).toEqual([]);
      expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "upstream-inspect-failed" });
    });
  }

  it("a lookup after the run's signal aborted is refused before anything is fetched", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    const ac = new AbortController();
    ac.abort();
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } }, { extra: { signal: ac.signal } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  it("a lookup kept and fired after the hook returned is refused", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    let kept: UpstreamLookup | undefined;
    hook = async (_req, lookup) => {
      kept = lookup;
      return { decision: "allow" };
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    const before = h.upstream().length;
    await expect(kept!.get("/things/t1")).rejects.toThrow();
    expect(h.upstream().length).toBe(before);
  });
});

describe("inspectUpstream never runs on opaque or staged bodies", () => {
  const opaque: Array<[string, Partial<UpstreamCtx>]> = [
    ["a raw non-JSON body", { body: "plain text", rawBody: true, contentType: "text/plain" }],
    ["base64 bytes", { bodyBase64: "aGVsbG8=", contentType: "application/octet-stream" }],
    ["inline multipart", { multipart: [{ name: "a", value: "b" }] }],
  ];
  for (const [name, extra] of opaque) {
    it(`${name}: denied before the hook, nothing fetched`, async () => {
      STORED["t1"] = { status: 200, body: { owner: "me" } };
      const h = harness({ method: "PATCH", path: "/things/t1", ...extra } as UpstreamCtx);
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
      expect(hookSpy).not.toHaveBeenCalled();
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "opaque-body-on-upstream-inspected-op" });
    });
  }

  it("a staged (composed) body: denied before the hook, nothing fetched", async () => {
    STORED["t1"] = { status: 200, body: { owner: "me" } };
    const ref = { file_handle: mintFileHandle(), token: mintToken() };
    const h = harness(
      { method: "PUT", path: "/things/t1", composed: { segments: [{ staged: ref, encoding: "identity" }] } },
      {
        extra: {
          openStaged: async () => ({
            ok: true,
            file: { meta: { byteLength: 3, contentType: "application/octet-stream", filename: "a.bin", fileRef: "000000000000" }, readBlocks: async () => {} },
          }),
        },
      },
    );
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
    expect(hookSpy).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "opaque-body-on-upstream-inspected-op" });
  });
});

describe("lookup session: in-flight lookups, own errors, timeouts", () => {
  it("a lookup fired without await that fails later still denies the write", async () => {
    hook = async (_req, lookup) => {
      void lookup.get("/things/boom");
      return { decision: "allow" };
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied/);
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET"]);
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "upstream-inspect-failed" });
  });

  it("errors raised by the session itself are named to the caller", async () => {
    hook = async (_req, lookup) => {
      await lookup.get("/secret/1");
      return { decision: "allow" };
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/not a plain-allow read/);
  });

  it("errors from the nested request are not forwarded (their text may carry lookup strings)", async () => {
    hook = async (_req, lookup) => {
      await lookup.get("/things/t1", { "SENSITIVE-NAME": "1" });
      return { decision: "allow" };
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    const err = (await handleUpstreamRequest(h.args).catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/check of the stored upstream state failed/);
    expect(err.message).not.toContain("SENSITIVE-NAME");
  });

  it("a hook's own ToolError text is not forwarded either", async () => {
    const { ToolError } = await import("../elicit");
    hook = async () => {
      throw new ToolError("stored title: SENSITIVE-TITLE");
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    const err = (await handleUpstreamRequest(h.args).catch((e: unknown) => e)) as Error;
    expect(err.message).not.toContain("SENSITIVE-TITLE");
  });

  it("a lookup that runs past the transfer timeout says the lookup timed out", async () => {
    hook = async (_req, lookup) => {
      await lookup.get("/things/hang");
      return { decision: "allow" };
    };
    const h = harness(
      { method: "PATCH", path: "/things/t1", body: { title: "x" } },
      { extra: { stagingLimits: { transferTimeoutMs: 20 } } },
    );
    const err = (await handleUpstreamRequest(h.args).catch((e: unknown) => e)) as Error;
    expect(err.message).toMatch(/upstream lookup timed out/);
    expect(err.message).not.toMatch(/staged transfer/);
    expect(h.upstream().map((c) => c.init.method)).toEqual(["GET"]);
  });

  it("FIXED (F1-2b): a GET entry that itself has inspectUpstream is refused by the session, before the nested handler", async () => {
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    h.args.surfaceReview = {
      ...SR,
      getThing: { decision: "allow", category: "standard_read", inspectUpstream: async () => ({ decision: "allow" }) },
    };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/not a plain-allow read/);
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().some((a) => a.operationId === "getThing")).toBe(false);
  });
});

describe("encodeLookupPath", () => {
  it("encodes each decoded path parameter as one segment", () => {
    expect(encodeLookupPath("/things/{id}", { id: "a#b" })).toBe("/things/a%23b");
    expect(encodeLookupPath("/things/{id}", { id: "%25" })).toBe("/things/%2525");
    expect(encodeLookupPath("/a/{x}/b/{y}", { x: "p/q", y: "r?s" })).toBe("/a/p%2Fq/b/r%3Fs");
  });

  it("throws on a missing or empty parameter", () => {
    expect(() => encodeLookupPath("/things/{id}", {})).toThrow();
    expect(() => encodeLookupPath("/things/{id}", { id: "" })).toThrow();
  });

  for (const id of ["a#b", "%25", "a b"]) {
    it(`a hook using it reads the same decoded target (${JSON.stringify(id)})`, async () => {
      STORED[id] = { status: 200, body: { owner: "me" } };
      const got: unknown[] = [];
      hook = async (req, lookup) => {
        const r = await lookup.get(encodeLookupPath("/things/{id}", req.pathParams ?? {}));
        got.push(r.body);
        return { decision: "allow" };
      };
      const h = harness({ method: "PATCH", path: `/things/${encodeURIComponent(id)}`, body: { title: "x" } });
      await handleUpstreamRequest(h.args);
      expect(got).toEqual([{ owner: "me" }]);
      expect(h.upstream()[0]!.url).toBe(`https://api.example.com/things/${encodeURIComponent(id)}`);
    });
  }
});

describe("a misconfigured hook fails closed", () => {
  it("an entry with inspectUpstream but no inspect denies instead of sending unchecked", async () => {
    STORED["t1"] = { status: 200, body: { owner: "other" } };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    h.args.surfaceReview = {
      ...SR,
      patchThing: { decision: "allow", inspectUpstream: (req, lookup) => hook(req, lookup) },
    };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "upstream-inspector-without-inspect" });
  });
});

describe("createUpstreamLookup (direct)", () => {
  it("reads a plain-allow path and returns { status, body } untruncated", async () => {
    const big = Array.from({ length: 3000 }, (_, i) => ({ i, pad: "x".repeat(20) }));
    STORED["big"] = { status: 200, body: { owner: "me", items: big } };
    const h = harness({ method: "PATCH", path: "/things/t1" });
    const session = createUpstreamLookup(h.args, handleUpstreamRequest);
    const r = await session.lookup.get("/things/big");
    expect(r.status).toBe(200);
    expect((r.body as { items: unknown[] }).items).toHaveLength(3000);
    expect(session.failed()).toBe(false);
  });
});

describe("provider battery: inspectUpstream pairing", () => {
  const provider = (sr: SurfaceReview) => ({ spec: SPEC, surfaceReview: sr });
  const hookFn = async (): Promise<InspectResult> => ({ decision: "allow" });

  it("FIXED (F1-2b): an entry with inspectUpstream but no inspect is reported", () => {
    expect(inspectUpstreamProblems(provider({ patchThing: { decision: "allow", inspectUpstream: hookFn } }))).toEqual([
      "patchThing: inspectUpstream without inspect",
    ]);
  });

  it("an entry with inspectUpstream on a GET is reported", () => {
    expect(
      inspectUpstreamProblems(
        provider({ getThing: { decision: "allow", inspect: () => ({ decision: "allow" }), inspectUpstream: hookFn } }),
      ),
    ).toEqual(["getThing: inspectUpstream on a non-body method (GET)"]);
  });

  it("a paired entry on a body-bearing method passes", () => {
    expect(inspectUpstreamProblems(provider(SR))).toEqual([]);
  });
});

// w2 secrev Lows: deny audit lines always carry a category, and a throw from
// a sync `inspect` (e.g. a provider parsing a malformed operator allow-list
// var, whose message quotes the config text) is a fail-closed deny with an
// audit line and fixed text, never an escaping exception.
describe("deny hygiene: audit category and inspector throws", () => {
  it("an upstream-inspect-failed deny on an entry with no static category is audited as malformed", async () => {
    hook = async () => {
      throw new TypeError("oops");
    };
    const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied/);
    expect(h.audit().at(-1)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "upstream-inspect-failed",
    });
  });

  for (const [name, thrown] of [
    ["a plain Error", new Error('Invalid ALLOWLIST entry: "CONFIG-TEXT-SENTINEL"')],
    ["a ToolError", null],
    ["a non-Error value", "CONFIG-TEXT-SENTINEL"],
  ] as const) {
    it(`a sync inspect that throws ${name} is denied (inspector-threw), audited, text not forwarded, nothing sent`, async () => {
      const { ToolError } = await import("../elicit");
      const err = thrown ?? new ToolError("CONFIG-TEXT-SENTINEL");
      const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
      h.args.surfaceReview = {
        ...SR,
        patchThing: {
          decision: "allow",
          inspect: () => {
            throw err;
          },
          inspectUpstream: (req, lookup) => {
            hookSpy(req);
            return hook(req, lookup);
          },
        },
      };
      const got = (await handleUpstreamRequest(h.args).catch((e: unknown) => e)) as Error;
      expect(got).toBeInstanceOf(ToolError);
      expect(got.message).toMatch(/denied/);
      expect(got.message).not.toContain("CONFIG-TEXT-SENTINEL");
      expect(hookSpy).not.toHaveBeenCalled();
      expect(h.fetchSpy).not.toHaveBeenCalled();
      const last = h.audit().at(-1)!;
      expect(last).toMatchObject({ decision: "deny", category: "malformed", reason: "inspector-threw", operationId: "patchThing" });
      expect(JSON.stringify(last)).not.toContain("CONFIG-TEXT-SENTINEL");
    });
  }

  it("a throwing inspect on an operation without a hook is denied the same way", async () => {
    const h = harness({ method: "POST", path: "/things", body: { a: 1 } });
    h.args.surfaceReview = {
      ...SR,
      createThing: {
        decision: "allow",
        category: "standard_write",
        inspect: () => {
          throw new Error("CONFIG-TEXT-SENTINEL");
        },
      },
    };
    const got = (await handleUpstreamRequest(h.args).catch((e: unknown) => e)) as Error;
    expect(got.message).not.toContain("CONFIG-TEXT-SENTINEL");
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "inspector-threw" });
  });
});

describe("deny hygiene: a sync inspect returning a non-InspectResult", () => {
  for (const [name, fn] of [
    ["an empty object", () => ({})],
    ["a Promise (async inspect)", async () => ({ decision: "deny" })],
    ["undefined", () => undefined],
  ] as const) {
    it(`an inspect returning ${name} is denied (inspector-invalid-result), audited, nothing sent`, async () => {
      const h = harness({ method: "PATCH", path: "/things/t1", body: { title: "x" } });
      h.args.surfaceReview = {
        ...SR,
        patchThing: {
          decision: "allow",
          inspect: fn as unknown as () => InspectResult,
          inspectUpstream: (req, lookup) => {
            hookSpy(req);
            return hook(req, lookup);
          },
        },
      };
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied/);
      expect(hookSpy).not.toHaveBeenCalled();
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit().at(-1)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "inspector-invalid-result",
        operationId: "patchThing",
      });
    });
  }
});
