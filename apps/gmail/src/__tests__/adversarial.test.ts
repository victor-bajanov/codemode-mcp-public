import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Buffer } from "node:buffer";
import { handleUpstreamRequest, getOrRefreshAccessToken, staging } from "@local/scaffold";
import { spec, surfaceReview } from "@local/providers-gmail";

function makeFakeBroker() {
  const data = new Map<string, unknown>();
  const storage = {
    get: async <T>(k: string) => data.get(k) as T | undefined,
    put: async <T>(k: string, v: T) => { data.set(k, v); },
  };
  return {
    async getOrRefreshAccessToken(args: { userId: string; refreshToken: string }) {
      return getOrRefreshAccessToken({
        storage,
        rotation: "static",
        refreshToken: args.refreshToken,
        clientId: "CID",
        clientSecret: "CSEC",
        tokenUrl: "https://oauth2.googleapis.com/token",
      });
    },
  };
}

const baseProps = {
  refreshToken: "RT-fake",
  googleUserId: "u",
  userId: "u",
  email: "u@example.com",
  name: "u",
};

const baseScaffoldArgs = {
  spec,
  surfaceReview,
  props: baseProps,
  apiBaseUrl: "https://gmail.googleapis.com",
  deploymentName: "gmail-test",
  server: {} as never,
  oauth: {
    refreshTokenAccessor: (p: typeof baseProps) => p.refreshToken,
    userIdAccessor: (p: typeof baseProps) => p.userId,
    broker: makeFakeBroker(),
  },
  audit: {},
  env: {} as { ALLOW_PII_IN_LOGS?: string },
};

describe("adversarial: surface-review enforcement", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("nope", { status: 500 }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("denies unrecognised paths before any fetch", async () => {
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "GET", path: "/totally-unknown" },
      }),
    ).rejects.toThrow(/No operation found/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("denies Tier 3 capability-escalation ops before any fetch", async () => {
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "POST", path: "/gmail/v1/users/me/settings/delegates" },
      }),
    ).rejects.toThrow(/denied by surface review/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("Tier 2 (elicit) ops route through runElicitation; fail with transport-error when server stub lacks elicitInput", async () => {
    // messages.send is now `allow + inspect` (Task 9). Use messages.import,
    // which is still `elicit`, to cover the elicit path via runElicitation.
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "POST", path: "/gmail/v1/users/me/messages/import" },
      }),
    ).rejects.toThrow(/requires user approval/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("routes messages.batchDelete through runElicitation; audit decision=elicit, elicitationOutcome=transport-error", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: {
          method: "POST",
          path: "/gmail/v1/users/me/messages/batchDelete",
          body: { ids: ["m1", "m2"] },
        },
      }),
    ).rejects.toThrow(/requires user approval/);
    expect(globalThis.fetch).not.toHaveBeenCalled();

    const auditLines = logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice("AUDIT ".length)));
    const last = auditLines.find((l: { operationId?: string }) => l.operationId === "gmail.users.messages.batchDelete");
    expect(last).toMatchObject({
      decision: "elicit",
      elicitationOutcome: "transport-error",
      operationId: "gmail.users.messages.batchDelete",
    });
  });

  it("does not allow path-encoding attacks to escalate to denied operations", async () => {
    // An encoded "/" decodes to a segment separator: refused outright (F-6).
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "POST", path: "/gmail/v1/users/me/settings%2Fdelegates" },
      }),
    ).rejects.toThrow(/disallowed segment/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("refuses dot-segment and backslash paths that the URL parser would rewrite to another operation (F-1)", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    for (const ctx of [
      // Matches labels.delete (allow) but would be sent as messages.delete (elicit).
      { method: "DELETE", path: "/gmail/v1/users/me/labels/..\\messages\\abc" },
      { method: "DELETE", path: "/gmail/v1/users/me/labels/%2e%2e" },
      // Matches calendar.events.patch but would be sent as calendars.patch.
      { method: "PATCH", path: "/calendar/v3/calendars/primary/events/..", body: {} },
      // Query smuggled through a path parameter, invisible to the inspector.
      { method: "GET", path: "/gmail/v1/users/me/messages/abc?format=raw" },
    ]) {
      await expect(handleUpstreamRequest({ ...baseScaffoldArgs, ctx })).rejects.toThrow(/disallowed segment/);
    }
    expect(globalThis.fetch).not.toHaveBeenCalled();
    const audits = logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice("AUDIT ".length)));
    expect(audits).toHaveLength(4);
    for (const a of audits) {
      expect(a).toMatchObject({ decision: "deny", category: "url_safety", reason: "unsafe-path-segment" });
    }
  });
});

describe("adversarial: bearer token never appears in returned values", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
      const urlStr = typeof url === "string" ? url : url.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "AT-fake-secret", expires_in: 3600 }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ messages: [{ id: "abc" }, { id: "def" }] }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("response body does not contain the refresh token, client secret, or access token", async () => {
    // Use unique refreshToken so the module-scoped tokenCache doesn't skip mint flow.
    const uniqueProps = { ...baseProps, refreshToken: "RT-fresh-for-leak-test" };
    const result = await handleUpstreamRequest({
      ...baseScaffoldArgs,
      props: uniqueProps,
      oauth: {
        ...baseScaffoldArgs.oauth,
        refreshTokenAccessor: (p: typeof uniqueProps) => p.refreshToken,
      },
      ctx: { method: "GET", path: "/gmail/v1/users/me/messages" },
    });

    const serialised = JSON.stringify(result);
    expect(serialised).not.toContain(uniqueProps.refreshToken);
    expect(serialised).not.toContain("CSEC");
    expect(serialised).not.toContain("AT-fake-secret");
    expect(serialised).toContain("abc");  // sanity: legitimate response present
  });
});

// ---------------------------------------------------------------------------
// Issue #59 (Task C4): a composed media send end to end, through the real
// Gmail spec and surface review, with staged files in FakeD1/FakeR2 and a
// fetch stub that records the exact bytes the upstream receives.
// ---------------------------------------------------------------------------

// The staging fakes (FakeD1/FakeR2) live in the scaffold's test fixtures,
// outside this app's tsc rootDir; load them at run time so the app's
// typecheck does not pull them into its project.
interface FakeR2Like {
  get(key: string): Promise<unknown>;
}
const FIXTURES = "../../../../packages/scaffold/src/staging/__tests__/__fixtures__/";
const { FakeD1 } = (await import(/* @vite-ignore */ new URL(FIXTURES + "fake-d1.ts", import.meta.url).href)) as {
  FakeD1: new () => object;
};
const { FakeR2 } = (await import(/* @vite-ignore */ new URL(FIXTURES + "fake-r2.ts", import.meta.url).href)) as {
  FakeR2: new () => FakeR2Like;
};

const STAGING_CFG = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
const STAGING_NOW = 1_700_000_000;
const ALLOW_ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com" };

function filePattern(n: number, seed = 7): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}

/** Reference `base64-lines` encoding: 76-char lines, CRLF after every line. */
function base64Lines(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString("base64");
  let out = "";
  for (let i = 0; i < b64.length; i += 76) out += b64.slice(i, i + 76) + "\r\n";
  return out;
}

function mimeHead(opts: { to?: string; subject?: string; extra?: string[] } = {}): string {
  return [
    "From: me",
    `To: ${opts.to ?? "bob@example.com"}`,
    `Subject: ${opts.subject ?? "Quarterly report"}`,
    ...(opts.extra ?? []),
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b1"',
    "",
    "--b1",
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    "hello",
    "",
    "--b1",
    'Content-Type: application/pdf; name="q.pdf"',
    'Content-Disposition: attachment; filename="q.pdf"',
    "Content-Transfer-Encoding: base64",
    "",
    "",
  ].join("\r\n");
}
const MIME_TAIL = "--b1--\r\n";

interface ComposedWorld {
  r2Reads: () => number;
  sent: Array<{ url: string; init: RequestInit; body: Uint8Array }>;
  audits: () => Array<Record<string, unknown>>;
  stage: (bytes: Uint8Array, contentType?: string, filename?: string | null) => Promise<{ file_handle: string; token: string }>;
  run: (ctx: Record<string, unknown>, env?: Record<string, unknown>) => Promise<unknown>;
}

function composedWorld(): ComposedWorld {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  let reads = 0;
  const realGet = r2.get.bind(r2);
  r2.get = (async (key: string) => {
    reads++;
    return realGet(key);
  }) as typeof r2.get;
  const deps = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: STAGING_CFG,
    uploadOrigin: "https://x.test",
    now: () => STAGING_NOW,
  };
  const opener = staging.createStagedFileOpener(deps);
  const sent: ComposedWorld["sent"] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url);
      if (u.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "AT-composed", expires_in: 3600 }), { status: 200 });
      }
      const rec: ComposedWorld["sent"][number] = { url: u, init: init ?? {}, body: new Uint8Array(0) };
      sent.push(rec);
      const body = init?.body;
      if (body instanceof ReadableStream) {
        const chunks: Uint8Array[] = [];
        const reader = (body as ReadableStream<Uint8Array>).getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        rec.body = Buffer.concat(chunks);
      } else if (typeof body === "string") {
        rec.body = new TextEncoder().encode(body);
      }
      return new Response(JSON.stringify({ id: "m1" }), { status: 200, headers: { "content-type": "application/json" } });
    }),
  );
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  let n = 0;
  return {
    r2Reads: () => reads,
    sent,
    audits: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .map((s) => JSON.parse(s.slice("AUDIT ".length)) as Record<string, unknown>),
    stage: async (bytes, contentType = "application/pdf", filename = "q.pdf") => {
      const r = await staging.stageFromBlocks(deps, staging.blockSourceFromBytes(bytes), contentType, filename);
      if (!r.ok) throw new Error("stage failed");
      return { file_handle: r.file_handle, token: r.token };
    },
    run: (ctx, env = ALLOW_ENV) => {
      const props = { ...baseProps, refreshToken: `RT-composed-${++n}-${Math.random()}` };
      return handleUpstreamRequest({
        ...baseScaffoldArgs,
        props,
        oauth: { ...baseScaffoldArgs.oauth, refreshTokenAccessor: (p: typeof props) => p.refreshToken },
        env: env as { ALLOW_PII_IN_LOGS?: string },
        ctx: ctx as never,
        openStaged: opener,
        stagingStore: deps,
      });
    },
  };
}

function mediaSend(segments: unknown[], path = "/upload/gmail/v1/users/me/messages/send", method = "POST") {
  return { method, path, query: { uploadType: "media" }, contentType: "message/rfc822", composed: { segments } };
}

/** The header block of sent RFC 822 bytes: everything before the first blank line. */
function headerBlockOf(bytes: Uint8Array): string {
  const text = Buffer.from(bytes).toString("latin1");
  const end = text.indexOf("\r\n\r\n");
  return end < 0 ? text : text.slice(0, end);
}

describe("adversarial: composed media send end to end (issue #59)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("sends the exact assembled RFC 822 bytes to the media-upload endpoint", async () => {
    const w = composedWorld();
    const file = filePattern(1_048_576 + 333); // crosses a staging block boundary
    const ref = await w.stage(file);
    const head = mimeHead();
    const res = (await w.run(
      mediaSend([{ text: head }, { staged: ref, encoding: "base64-lines" }, { text: MIME_TAIL }]),
    )) as Record<string, unknown>;
    expect(res["success"]).toBe(true);
    expect(w.sent).toHaveLength(1);
    const s = w.sent[0]!;
    const url = new URL(s.url);
    expect(url.pathname).toBe("/upload/gmail/v1/users/me/messages/send");
    expect(url.searchParams.get("uploadType")).toBe("media");
    const expected = head + base64Lines(file) + MIME_TAIL;
    expect(Buffer.from(s.body).toString("latin1")).toBe(expected);
    const headers = s.init.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("message/rfc822");
    expect(headers["Content-Length"]).toBe(String(expected.length));
    expect(w.audits().at(-1)).toMatchObject({ operationId: "gmail.users.messages.send.media", decision: "allow" });
  });

  it("denies an off-allowlist recipient before any staged file is read", async () => {
    const w = composedWorld();
    const ref = await w.stage(filePattern(500));
    await expect(
      w.run(mediaSend([{ text: mimeHead({ to: "eve@evil.com" }) }, { staged: ref, encoding: "base64-lines" }, { text: MIME_TAIL }])),
    ).rejects.toThrow(/denied/);
    expect(w.sent).toHaveLength(0);
    expect(w.r2Reads()).toBe(0);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "external-send" });
  });

  it("refuses composed on the JSON messages.send operation (staged-not-supported)", async () => {
    const w = composedWorld();
    const ref = await w.stage(filePattern(500));
    await expect(
      w.run({
        method: "POST",
        path: "/gmail/v1/users/me/messages/send",
        composed: { segments: [{ text: mimeHead() }, { staged: ref, encoding: "base64-lines" }, { text: MIME_TAIL }] },
      }),
    ).rejects.toThrow(/staged/);
    expect(w.sent).toHaveLength(0);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "staged-not-supported" });
  });

  it("denies a message over Gmail's 35 MiB media limit before reading any file", async () => {
    const w = composedWorld();
    const ref = await w.stage(filePattern(7 * 1024 * 1024));
    const seg = { staged: ref, encoding: "base64-lines" };
    // Four copies of a 7 MiB file as base64 lines ≈ 37.4 MB.
    await expect(
      w.run(mediaSend([{ text: mimeHead() }, seg, { text: "\r\n" }, seg, { text: "\r\n" }, seg, { text: "\r\n" }, seg, { text: MIME_TAIL }])),
    ).rejects.toThrow(/36700160/);
    expect(w.sent).toHaveLength(0);
    expect(w.r2Reads()).toBe(0);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "message-too-large" });
  });

  it("repairs a mojibake Subject in the composed text on drafts.create.media", async () => {
    const w = composedWorld();
    const file = filePattern(300);
    const ref = await w.stage(file);
    const mangled = Buffer.from(Buffer.from("Report — Q3", "utf8").toString("latin1"), "utf8").toString("latin1");
    await w.run(
      mediaSend(
        [{ text: mimeHead({ subject: mangled }) }, { staged: ref, encoding: "base64-lines" }, { text: MIME_TAIL }],
        "/upload/gmail/v1/users/me/drafts",
      ),
    );
    expect(w.sent).toHaveLength(1);
    const header = headerBlockOf(w.sent[0]!.body);
    expect(header).toMatch(/^Subject: =\?UTF-8\?B\?/m);
    expect(header).not.toContain("Ã");
    // The attachment still follows, untouched.
    expect(Buffer.from(w.sent[0]!.body).toString("latin1")).toContain(base64Lines(file));
  });
});

describe("adversarial: header smuggling through staged bytes (issue #59)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  const EVIL = new TextEncoder().encode("\r\n\r\nBcc: evil@x.com\r\nTo: evil@x.com\r\n\r\nhi\r\n");

  it("a Bcc inside a base64 staged segment never reaches the header block", async () => {
    const w = composedWorld();
    const ref = await w.stage(EVIL, "text/plain", "note.txt");
    await w.run(mediaSend([{ text: mimeHead() }, { staged: ref, encoding: "base64-lines" }, { text: MIME_TAIL }]));
    expect(w.sent).toHaveLength(1);
    const wire = Buffer.from(w.sent[0]!.body).toString("latin1");
    expect(headerBlockOf(w.sent[0]!.body)).not.toMatch(/evil/i);
    // The staged bytes travel only as base64, never as their raw text.
    expect(wire).not.toContain("Bcc: evil@x.com");
  });

  it("plain base64 (no line breaks) cannot smuggle a header either", async () => {
    const w = composedWorld();
    const ref = await w.stage(EVIL, "text/plain", "note.txt");
    await w.run(mediaSend([{ text: mimeHead() }, { staged: ref, encoding: "base64" }, { text: "\r\n" + MIME_TAIL }]));
    expect(w.sent).toHaveLength(1);
    expect(Buffer.from(w.sent[0]!.body).toString("latin1")).not.toContain("Bcc: evil@x.com");
  });

  it("a staged segment placed inside the header block is denied before any file read", async () => {
    const w = composedWorld();
    const ref = await w.stage(EVIL, "text/plain", "note.txt");
    await expect(
      w.run(
        mediaSend([
          { text: "From: me\r\nTo: bob@example.com\r\nX-Note: " },
          { staged: ref, encoding: "base64" },
          { text: "\r\n\r\nbody\r\n" },
        ]),
      ),
    ).rejects.toThrow(/denied|header/);
    expect(w.sent).toHaveLength(0);
    expect(w.r2Reads()).toBe(0);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "attachment-before-header-end" });
  });

  it("a whole pre-built message as a sole identity segment cannot be sent", async () => {
    const w = composedWorld();
    const prebuilt = new TextEncoder().encode("To: bob@example.com\r\nBcc: evil@x.com\r\n\r\nhi\r\n");
    const ref = await w.stage(prebuilt, "message/rfc822", "m.eml");
    await expect(w.run(mediaSend([{ staged: ref, encoding: "identity" }]))).rejects.toThrow(/denied|header/);
    expect(w.sent).toHaveLength(0);
    expect(w.r2Reads()).toBe(0);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "attachment-before-header-end" });
  });

  it("the same pre-built message may become a draft (inert; gated at send time, red-team R-8)", async () => {
    const w = composedWorld();
    const prebuilt = new TextEncoder().encode("To: bob@example.com\r\nBcc: evil@x.com\r\n\r\nhi\r\n");
    const ref = await w.stage(prebuilt, "message/rfc822", "m.eml");
    await w.run(mediaSend([{ staged: ref, encoding: "identity" }], "/upload/gmail/v1/users/me/drafts"));
    expect(w.sent).toHaveLength(1);
    expect(Buffer.from(w.sent[0]!.body)).toEqual(Buffer.from(prebuilt));
  });
});
