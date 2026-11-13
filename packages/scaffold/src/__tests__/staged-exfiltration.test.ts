// packages/scaffold/src/__tests__/staged-exfiltration.test.ts
//
// E-1 (2026-11 review, reduced scope) end to end: staged files are bound to
// the principal that created them, every staging event is audited, the public
// download is counted against STAGING_FETCH_MAX_USES (default 5), and `putFile`
// is budgeted.
//
// Attacker: (3) a prompt-injected LLM in user A's session, with (1) an
//   anonymous internet client collecting; and (2) tenant user B, who learns
//   A's `{ file_handle, token }` pair.
// Precondition: staging bindings configured; a session with a principal.
// Payloads: an allowed read with `returnAs: "stage"`; `putFile` ×25 under a
//   three-call budget; the public `fetch_url` GET past its use limit with the
//   `stg_` bearer;
//   B's `composed` send referencing A's pair; B's `getFile(A.handle, A.token)`;
//   a row written before migration 0003 (no owner); a session whose
//   principal is the empty string.
// Control: `owner` on every row, checked by every in-MCP reader (same 403
//   "file not found or not yours" as a wrong token — no ownership oracle);
//   `countPublicFetch` counts each public download atomically before any R2
//   read (GET past STAGING_FETCH_MAX_USES → 410); one audit line per staging event carrying only
//   `fileRef` (SHA-256 digest of the handle), never the handle or token;
//   `getFile`/`putFile` join the per-run upstream budget.
// Why the pre-fix code failed it: rows had no owner column, so B's session
//   sent A's bytes under B's token and `getFile` read anyone's file; the
//   public GET answered 200 for the whole fetch TTL and wrote no audit line;
//   the stage left one ordinary read line with nothing saying the bytes were
//   copied to a public endpoint; `putFile` was outside the budget (25 rows
//   under a budget of 3, 0 lines).
//
// Real code under test: setupProvider().default.fetch (the deployed worker
// entry), handleUpstreamRequest, createPutFileCapability,
// createGetFileCapability, createStagedFileOpener, createGuardedExecutor and
// buildStagingHostFns. Only D1/R2/KV and the upstream `fetch` are faked.
// Hosts and ids are invented (`*.example`).

import { describe, it, expect, vi, afterEach } from "vitest";
import { setupProvider } from "../setup-provider";
import type { ApiProvider } from "../api-provider";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../request-handler";
import { createAuditSink } from "../audit";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { createStagedFileOpener } from "../staging/staged-file";
import { createPutFileCapability, type PutFileCapabilityDeps } from "../staging/putfile-capability";
import { createGetFileCapability } from "../staging/getfile-capability";
import { fileRefOf } from "../staging/crypto";
import {
  buildStagingHostFns,
  createGuardedExecutor,
  type HostProvider,
  type SandboxExecutor,
} from "../mcp-agent-factory";
import type { StagingConfig } from "../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
const ORIGIN = "https://mcp.example";
const DEPLOYMENT = "test-deployment";

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example" }],
  paths: {
    "/files/{id}/content": { get: op("getFileContent") }, // an ordinary allowed read
    "/attach/{name}": { put: op("attach") }, // an ordinary allowed write
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;
const SR: SurfaceReview = {
  getFileContent: { decision: "allow" },
  attach: { decision: "allow" },
};

const PROVIDER = {
  name: "t",
  displayName: "T",
  oauth: {
    authorizeUrl: "https://login.example/authorize",
    tokenUrl: "https://login.example/token",
    scopes: ["s"],
    clientIdSecretName: "CID",
    clientSecretSecretName: "CSEC",
  },
  spec: {} as never,
  surfaceReview: {},
  apiBaseUrl: "https://api.example",
} as ApiProvider<Record<string, unknown>>;

type Line = Record<string, unknown> & { staging?: { event: string; fileRef?: string; byteLength?: number; status: number } };

function world(vars: Record<string, string> = {}) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const kvData = new Map<string, string>();
  const kv = {
    async get(k: string) { return kvData.get(k) ?? null; },
    async put(k: string, v: string) { kvData.set(k, v); },
    async delete(k: string) { kvData.delete(k); },
  };
  /** Store deps as `mcp-agent-factory` builds them for a session: owner = the session principal. */
  const storeFor = (owner: string): PutFileCapabilityDeps => ({
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: ORIGIN,
    owner,
  });
  // The deployed worker entry, exactly as apps/*/src/index.ts exports it.
  const worker = setupProvider(PROVIDER).default;
  const env = {
    COOKIE_ENCRYPTION_KEY: "k".repeat(32),
    DEPLOYMENT_NAME: DEPLOYMENT,
    OAUTH_KV: kv,
    STAGING_D1: d1,
    STAGING_R2: r2,
    ...vars,
  };
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException() {} };
  const internet = async (req: Request) => {
    const res = await worker.fetch(req, env as never, ctx as never);
    await Promise.all(pending.splice(0));
    return res;
  };

  const raw: string[] = [];
  const logSpy = vi.spyOn(console, "log").mockImplementation((s: unknown) => {
    if (typeof s === "string" && s.startsWith("AUDIT ")) raw.push(s);
  });
  const audits = (): Line[] => raw.map((s) => JSON.parse(s.slice(6)) as Line);

  const sessionArgs = (
    user: { userId: string; accessToken: string },
    reqCtx: UpstreamCtx,
  ): HandleArgs<Record<string, unknown>> => ({
    ctx: reqCtx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example",
    deploymentName: DEPLOYMENT,
    props: { refreshToken: `RT-${user.userId}`, userId: user.userId },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: { server: { getClientCapabilities: () => ({}) } } as any,
    env: {},
    audit: { principalIdAccessor: (p) => p.userId as string },
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken as string,
      userIdAccessor: (p) => p.userId as string,
      broker: { getOrRefreshAccessToken: async () => user.accessToken },
    },
    openStaged: createStagedFileOpener(storeFor(user.userId)),
    stagingStore: storeFor(user.userId),
  });
  /** The session sink `init()` gives the staging capabilities: deployment + principal. */
  const sinkFor = (owner: string) => createAuditSink({ deployment: DEPLOYMENT, principalId: owner });
  return { d1, r2, kvData, storeFor, sinkFor, internet, audits, raw, sessionArgs, logSpy };
}

const SECRET = "CONFIDENTIAL: payroll export for user A / 4111 1111 1111 1111";
const USER_A = { userId: "user-A", accessToken: "AT-user-A" };
const USER_B = { userId: "user-B", accessToken: "AT-user-B" };
const HEX12 = /^[0-9a-f]{12}$/;

/** No line may carry a handle, a token or an access token. */
function expectNoSecrets(raw: string[], ...secrets: string[]): void {
  for (const s of raw) {
    for (const secret of secrets) expect(s).not.toContain(secret);
    expect(s).not.toMatch(/fh_[A-Za-z0-9_-]{8,}/);
    expect(s).not.toMatch(/stg_[A-Za-z0-9_-]{8,}/);
    expect(s).not.toContain("AT-user-");
  }
}

function upstreamServesSecret(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(SECRET, {
        status: 200,
        headers: {
          "content-type": "application/pdf",
          "content-length": String(new TextEncoder().encode(SECRET).byteLength),
          "content-disposition": 'attachment; filename="payroll.pdf"',
        },
      }),
    ),
  );
}

async function stageInSession(w: ReturnType<typeof world>, user: typeof USER_A) {
  const staged = (await handleUpstreamRequest(
    w.sessionArgs(user, { method: "GET", path: "/files/123/content", returnAs: "stage" }),
  )) as { success: boolean; result: { file_handle: string; token: string; fetch_url: string } };
  expect(staged.success).toBe(true);
  return staged.result;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("E-1: staged files are bound to their principal, audited and use-limited", () => {
  it("FIXED (E-1): a stage in A's session writes an owned row and a store line with a fileRef, never the handle or token", async () => {
    const w = world();
    upstreamServesSecret();
    const { file_handle, token, fetch_url } = await stageInSession(w, USER_A);
    expect(fetch_url).toBe(`${ORIGIN}/staging/fetch/${file_handle}`);

    // The row is owned and its public download is not yet counted.
    expect(w.d1.rows.size).toBe(1);
    const row = [...w.d1.rows.values()][0]!;
    expect(Object.keys(row)).toContain("owner");
    expect(row.owner).toBe("user-A");
    expect(row.fetch_count).toBe(0);

    // The read's allow line says the bytes were copied into the store.
    const lines = w.audits();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      deployment: DEPLOYMENT,
      operationId: "getFileContent",
      decision: "allow",
      upstreamStatus: 200,
      principalId: "user-A",
      staging: { event: "store", byteLength: SECRET.length, status: 200 },
    });
    expect(lines[0]!.staging!.fileRef).toMatch(HEX12);
    expect(lines[0]!.staging!.fileRef).toBe(await fileRefOf(file_handle));
    expectNoSecrets(w.raw, file_handle, token);
  });

  it("FIXED (E-1): with STAGING_FETCH_MAX_USES=1 the public fetch_url works once and is 410 after; both downloads are audited under A's principal", async () => {
    const w = world({ STAGING_FETCH_MAX_USES: "1" });
    upstreamServesSecret();
    const { file_handle, token, fetch_url } = await stageInSession(w, USER_A);
    const storeRef = w.audits()[0]!.staging!.fileRef!;

    // An anonymous third party, different IP, no MCP/OAuth credentials.
    const anon = () =>
      w.internet(
        new Request(fetch_url, {
          headers: { Authorization: `Bearer ${token}`, "CF-Connecting-IP": "198.51.100.77" },
        }),
      );
    const res1 = await anon();
    expect(res1.status).toBe(200);
    expect(await res1.text()).toBe(SECRET);
    expect(res1.headers.get("content-type")).toBe("application/pdf");
    expect([...w.d1.rows.values()][0]!.fetch_count).toBe(1);

    // Limit 1 reached: the same pointer is gone.
    const res2 = await anon();
    expect(res2.status).toBe(410);
    expect(await res2.text()).toBe("gone");
    // A 410 is not a bearer-guessing failure: the throttle recorded nothing.
    expect(w.kvData.size).toBe(0);

    const downloads = w.audits().filter((l) => l.operationId === "staging.download");
    expect(downloads).toHaveLength(2);
    expect(downloads[0]).toMatchObject({
      deployment: DEPLOYMENT,
      method: "GET",
      path: "/staging/fetch",
      decision: "allow",
      principalId: "user-A",
      staging: { event: "download", fileRef: storeRef, byteLength: SECRET.length, status: 200 },
    });
    expect(downloads[1]).toMatchObject({
      method: "GET",
      path: "/staging/fetch",
      decision: "deny",
      reason: "staging-refused",
      principalId: "user-A",
      staging: { event: "download", fileRef: storeRef, status: 410 },
    });
    expectNoSecrets(w.raw, file_handle, token);
    // Create and download are joined by fileRef; the only staging identifier anywhere.
    expect(new Set(w.audits().map((l) => l.staging?.fileRef).filter(Boolean)).size).toBe(1);
  });

  it("FIXED (E-1): with STAGING_FETCH_MAX_USES unset the public fetch_url works 5 times, the 6th is 410 (residual, by decision); the owner's getFile and staged attach still work after", async () => {
    const w = world();
    upstreamServesSecret();
    const { file_handle, token, fetch_url } = await stageInSession(w, USER_A);
    const anon = () =>
      w.internet(
        new Request(fetch_url, {
          headers: { Authorization: `Bearer ${token}`, "CF-Connecting-IP": "198.51.100.78" },
        }),
      );
    for (let i = 0; i < 5; i++) {
      const res = await anon();
      expect(res.status).toBe(200);
      expect(await res.text()).toBe(SECRET);
    }
    const sixth = await anon();
    expect(sixth.status).toBe(410);
    expect(await sixth.text()).toBe("gone");
    expect([...w.d1.rows.values()][0]!.fetch_count).toBe(5);
    expect(w.kvData.size).toBe(0); // a 410 does not spend the failure budget
    const downloads = w.audits().filter((l) => l.operationId === "staging.download");
    expect(downloads.map((l) => l.staging!.status)).toEqual([200, 200, 200, 200, 200, 410]);

    // In-MCP use is uncounted and owner-bound: A's getFile still reads it ...
    const getFile = createGetFileCapability({ ...w.storeFor("user-A"), audit: w.sinkFor("user-A") });
    const r = await getFile(file_handle, token);
    expect(r.ok).toBe(true);
    if (r.ok) expect(atob(r.bytesBase64)).toBe(SECRET);
    // ... and A's session can still attach it.
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
        seen.push(await new Response(init?.body as BodyInit).text());
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }),
    );
    const sent = (await handleUpstreamRequest(
      w.sessionArgs(USER_A, {
        method: "PUT",
        path: "/attach/payroll.pdf",
        contentType: "application/pdf",
        composed: { segments: [{ staged: { file_handle, token }, encoding: "identity" }] },
      }),
    )) as { success: boolean };
    expect(sent.success).toBe(true);
    expect(seen).toEqual([SECRET]);
    expect([...w.d1.rows.values()][0]!.fetch_count).toBe(5);
    expectNoSecrets(w.raw, file_handle, token);
  });

  it("REFUTED (E-1): a wrong token and a bearer-less GET are still 403, and in-MCP reuse by the owner is unchanged", async () => {
    const w = world();
    upstreamServesSecret();
    const { file_handle, token, fetch_url } = await stageInSession(w, USER_A);
    const wrong = await w.internet(
      new Request(fetch_url, { headers: { Authorization: "Bearer stg_" + "x".repeat(43), "CF-Connecting-IP": "198.51.100.1" } }),
    );
    expect(wrong.status).toBe(403);
    const bare = await w.internet(new Request(fetch_url, { headers: { "CF-Connecting-IP": "198.51.100.1" } }));
    expect(bare.status).toBe(403);
    // Both refusals are on record (deny, no principal: no row resolved).
    const denies = w.audits().filter((l) => l.operationId === "staging.download");
    expect(denies).toHaveLength(2);
    for (const d of denies) {
      expect(d).toMatchObject({ decision: "deny", reason: "staging-refused", staging: { event: "download", status: 403 } });
      expect(d).not.toHaveProperty("principalId");
      expect(d.staging).not.toHaveProperty("fileRef");
    }
    // A's own session reads the same pair twice: the count is public-only.
    const getFile = createGetFileCapability({ ...w.storeFor("user-A"), audit: w.sinkFor("user-A") });
    for (let i = 0; i < 2; i++) {
      const r = await getFile(file_handle, token);
      expect(r.ok).toBe(true);
      if (r.ok) expect(atob(r.bytesBase64)).toBe(SECRET);
    }
    expectNoSecrets(w.raw, file_handle, token);
  });

  it("FIXED (E-1): putFile is budgeted with the upstream calls, and every store is audited under the principal", async () => {
    const w = world({ STAGING_FETCH_MAX_USES: "1" });
    const store = { ...w.storeFor("user-A"), audit: w.sinkFor("user-A") };
    const putFile = createPutFileCapability({ ...store, auditPath: "__stagingHost.putFile" });
    const getFile = createGetFileCapability(store);
    const stagingProvider = buildStagingHostFns({
      getFile,
      putFile,
      stageFromUpstreamJson: async () => ({ ok: false, status: 500, message: "unused" }),
    });

    // A base executor standing in for the Worker-Loader sandbox: it runs the
    // "LLM code" against the providers the guard hands it, as codemode does.
    const handles: Array<{ file_handle: string; token: string }> = [];
    const failures: string[] = [];
    const base: SandboxExecutor = {
      async execute(_code, providers) {
        const staging = (providers as HostProvider[]).find((p) => p.name === "__stagingHost")!;
        for (let i = 0; i < 25; i++) {
          try {
            const r = (await staging.fns.putFile!(btoa(`${SECRET} #${i}`), "text/plain", `dump-${i}.txt`)) as {
              ok: boolean;
              file_handle: string;
              token: string;
            };
            if (!r.ok) throw new Error("putFile refused");
            handles.push({ file_handle: r.file_handle, token: r.token });
          } catch (e) {
            failures.push((e as Error).message);
          }
        }
        return { result: handles.length };
      },
    };
    const guarded = createGuardedExecutor(base, {
      stagingProvider,
      docsProvider: { name: "__docsHost", fns: {} },
      // A budget of THREE upstream calls per execution…
      limits: { hostTimeoutMs: 10_000, maxUpstreamCalls: 3 },
      audit: w.sinkFor("user-A"),
    });
    const out = await guarded.execute("/* llm code */", [
      { name: "__openapiHost", fns: { request: async () => ({}) } },
    ]);
    // …stops the 4th putFile: it is counted like a request.
    expect(out.error).toBeUndefined();
    expect(out.result).toBe(3);
    expect(failures).toHaveLength(22);
    for (const f of failures) expect(f).toMatch(/^upstream call budget exceeded: at most 3 upstream requests per execution/);
    expect(w.d1.rows.size).toBe(3);
    for (const row of w.d1.rows.values()) expect(row.owner).toBe("user-A");

    // One store line per stored file, distinct fileRefs, no handle or token.
    const stores = w.audits().filter((l) => l.operationId === "staging.store");
    expect(stores).toHaveLength(3);
    for (const s of stores) {
      expect(s).toMatchObject({
        deployment: DEPLOYMENT,
        method: "HOST",
        path: "__stagingHost.putFile",
        decision: "allow",
        principalId: "user-A",
        staging: { event: "store", status: 200 },
      });
      expect(s.staging!.fileRef).toMatch(HEX12);
    }
    expect(new Set(stores.map((s) => s.staging!.fileRef)).size).toBe(3);
    expect(stores.map((s) => s.staging!.byteLength)).toEqual(handles.map((_, i) => `${SECRET} #${i}`.length));
    // The budget refusals are not denials of the handler: no deny line, no summary.
    expect(w.audits().filter((l) => l.decision === "deny")).toHaveLength(0);
    expectNoSecrets(w.raw, ...handles.flatMap((h) => [h.file_handle, h.token]));

    // The last file downloads exactly once from the public endpoint (limit 1).
    const last = handles[2]!;
    const fetchIt = () =>
      w.internet(
        new Request(`${ORIGIN}/staging/fetch/${last.file_handle}`, {
          headers: { Authorization: `Bearer ${last.token}`, "CF-Connecting-IP": "198.51.100.78" },
        }),
      );
    const res = await fetchIt();
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(`${SECRET} #2`);
    expect((await fetchIt()).status).toBe(410);
    const downloads = w.audits().filter((l) => l.operationId === "staging.download");
    expect(downloads.map((d) => d.staging!.status)).toEqual([200, 410]);
    expect(downloads[0]!.staging!.fileRef).toBe(stores[2]!.staging!.fileRef);
    expect(downloads[0]!.principalId).toBe("user-A");
  });

  it("FIXED (E-1): user B's session cannot send user A's staged bytes; REFUTED: A's own session still can, with stagedRefs on record", async () => {
    const w = world();
    // A stages something through the sandbox capability.
    const putFile = createPutFileCapability({ ...w.storeFor("user-A"), audit: w.sinkFor("user-A") });
    const a = await putFile(btoa(SECRET), "application/pdf", "payroll.pdf");
    if (!a.ok) throw new Error("stage failed");
    const storeLine = w.audits().find((l) => l.operationId === "staging.store")!;
    expect(storeLine.staging!.fileRef).toBe(a.file_ref);

    const seen: Array<{ auth: string | null; body: string }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        const body = await new Response(init?.body as BodyInit).text();
        seen.push({ auth: headers.get("authorization"), body });
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }),
    );
    const sendAs = (user: typeof USER_A) =>
      handleUpstreamRequest(
        w.sessionArgs(user, {
          method: "PUT",
          path: "/attach/stolen.pdf",
          contentType: "application/pdf",
          composed: {
            segments: [{ staged: { file_handle: a.file_handle, token: a.token }, encoding: "identity" }],
          },
        }),
      );

    // B (a different principal, different grant) references A's handle+token.
    await expect(sendAs(USER_B)).rejects.toThrow("composed segment 0: file not found or not yours (HTTP 403)");
    expect(seen).toHaveLength(0);
    expect(w.r2.getCalls).toBe(0);
    const deny = w.audits().at(-1)!;
    expect(deny).toMatchObject({
      operationId: "attach",
      decision: "deny",
      reason: "staged-ref-unresolved",
      principalId: "user-B",
      staging: { event: "attach", status: 403 },
    });
    // The refusal names no file: nothing confirms the pair to a non-owner.
    expect(deny.staging).not.toHaveProperty("fileRef");
    expect(JSON.stringify(deny)).not.toContain("user-A");

    // REFUTED control: the owner's own session sends it.
    const r = (await sendAs(USER_A)) as { success: boolean };
    expect(r.success).toBe(true);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.auth).toBe("Bearer AT-user-A");
    expect(seen[0]!.body).toBe(SECRET);
    const [dispatch, final] = w.audits().slice(-2);
    expect(dispatch).toMatchObject({ operationId: "attach", decision: "allow", phase: "dispatch", principalId: "user-A", stagedCount: 1, stagedRefs: [a.file_ref] });
    expect(final).toMatchObject({ operationId: "attach", decision: "allow", upstreamStatus: 200, principalId: "user-A", stagedCount: 1, bodyComplete: true, stagedRefs: [a.file_ref] });
    expect(final).not.toHaveProperty("phase");
    expectNoSecrets(w.raw, a.file_handle, a.token);
  });

  it("FIXED (E-1): user B's getFile(A.handle, A.token) is 403 with no R2 read and a read deny line that names no file", async () => {
    const w = world();
    const a = await createPutFileCapability(w.storeFor("user-A"))(btoa(SECRET), "text/plain", null);
    if (!a.ok) throw new Error("stage failed");
    const getFileB = createGetFileCapability({ ...w.storeFor("user-B"), audit: w.sinkFor("user-B") });
    const r = await getFileB(a.file_handle, a.token);
    expect(r).toMatchObject({ ok: false, status: 403, message: "file not found or not yours" });
    expect(w.r2.getCalls).toBe(0);
    const line = w.audits().at(-1)!;
    expect(line).toMatchObject({
      method: "HOST",
      path: "__stagingHost.getFile",
      operationId: "staging.read",
      decision: "deny",
      reason: "staging-refused",
      principalId: "user-B",
      staging: { event: "read", status: 403 },
    });
    expect(line.staging).not.toHaveProperty("fileRef");
    expectNoSecrets(w.raw, a.file_handle, a.token);
  });

  it("FIXED (E-1): a row without an owner (pre-0003 shape) is refused by every reader with no R2 read", async () => {
    const w = world();
    const a = await createPutFileCapability(w.storeFor("user-A"))(btoa(SECRET), "text/plain", null);
    if (!a.ok) throw new Error("stage failed");
    // The row as migration 0003 leaves pre-existing rows: owner NULL.
    for (const row of w.d1.rows.values()) row.owner = null;

    const getFile = createGetFileCapability({ ...w.storeFor("user-A"), audit: w.sinkFor("user-A") });
    expect(await getFile(a.file_handle, a.token)).toMatchObject({ ok: false, status: 403 });

    const pub = await w.internet(
      new Request(`${ORIGIN}/staging/fetch/${a.file_handle}`, {
        headers: { Authorization: `Bearer ${a.token}`, "CF-Connecting-IP": "198.51.100.79" },
      }),
    );
    expect(pub.status).toBe(403);
    expect(await pub.text()).toBe("forbidden");

    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    await expect(
      handleUpstreamRequest(
        w.sessionArgs(USER_A, {
          method: "PUT",
          path: "/attach/x.pdf",
          composed: { segments: [{ staged: { file_handle: a.file_handle, token: a.token }, encoding: "identity" }] },
        }),
      ),
    ).rejects.toThrow("composed segment 0: file not found or not yours (HTTP 403)");
    expect(fetch).not.toHaveBeenCalled();
    expect(w.r2.getCalls).toBe(0);
    expect([...w.d1.rows.values()][0]!.fetch_count).toBe(0);

    const reasons = w.audits().map((l) => [l.operationId, l.decision, l.reason, l.staging?.status]);
    expect(reasons).toEqual([
      ["staging.read", "deny", "staging-refused", 403],
      ["staging.download", "deny", "staging-refused", 403],
      ["attach", "deny", "staged-ref-unresolved", 403],
    ]);
    // A legacy row has no principal to attribute the download to.
    expect(w.audits()[1]).not.toHaveProperty("principalId");
    expectNoSecrets(w.raw, a.file_handle, a.token);
  });

  it("FIXED (E-1): a session whose principal is the empty string cannot store (no shared anonymous owner)", async () => {
    const w = world();
    upstreamServesSecret();
    const nobody = { userId: "", accessToken: "AT-nobody" };
    // The handler itself refuses to mint for an empty principal (no-principal);
    // the store is reached only through a session the factory would not have
    // given staging to — the capability still refuses on its own.
    const direct = await createPutFileCapability({ ...w.storeFor(""), audit: w.sinkFor("user-X") })(btoa(SECRET), "text/plain", null);
    expect(direct).toEqual({ ok: false, status: 403, message: "staging requires an authenticated principal" });
    expect(w.d1.rows.size).toBe(0);
    expect(w.r2.store.size).toBe(0);
    expect(w.audits().at(-1)).toMatchObject({ operationId: "staging.store", decision: "deny", reason: "staging-refused", staging: { event: "store", status: 403 } });
    await expect(
      handleUpstreamRequest(w.sessionArgs(nobody, { method: "GET", path: "/files/1/content", returnAs: "stage" })),
    ).rejects.toThrow(/Cannot mint access token: principal has no userId/);
    expect(w.audits().at(-1)).toMatchObject({ operationId: "getFileContent", decision: "deny", reason: "no-principal" });
    expect(w.d1.rows.size).toBe(0);
  });
});
