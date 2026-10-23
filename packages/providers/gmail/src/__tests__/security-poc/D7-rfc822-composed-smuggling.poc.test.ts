// D7 — Gmail media-upload send: smuggling through a composed RFC 822 body (issue #59, D12, C2, red-team R-3/R-7/R-8).
//
// Attacker: sandbox code (LLM-authored or prompt-injected) that controls the
//   text segments, the staged file's bytes and, via register_file_handle,
//   the row's filename; its goal is a send to an off-allowlist recipient, a
//   send the inspector never judged, or an approval dialog it can reorder.
// Precondition: the REAL Gmail spec + surface review through the real
//   request handler; staged rows in FakeD1/FakeR2; `fetch` stubbed.
// Payloads: B1 an unterminated header block before the staged slot; B2
//   `identity` among text segments; B3 U+FFFC in text (literal and
//   JSON-escaped); B5 `composed` together with `body`/`bodyBase64`/
//   `multipart`; B6 `uploadType=resumable|multipart` (and absent); B7 an
//   off-allowlist To on the media op; B8 a row filename "x\r\nTo: evil@x"
//   and a bidi-override filename; B10 `composed` on the JSON messages.send
//   op; a mass send (26 recipients) on the media op.
// Control: the media inspector denies a staged slot before the header
//   block ends (`attachment-before-header-end`); the scaffold refuses
//   identity-among-text, U+FFFC in text, and a second body channel at
//   entry (no D1 read); the inspector requires `uploadType=media`; the
//   recipient allowlist applies to the composed header block exactly as to
//   the JSON `raw` send; row filenames reach only the view's metadata and
//   the dialog's attachments line, sanitised; the JSON op has no
//   `acceptsStaged`, so `composed` there is refused by rule; mass-send
//   still elicits on the media op.
//
// Pre-v2 reasoning: the media operations and the composed channel are new,
// so every probe here is a v2 control; removing the
// `attachment-before-header-end` rule (verified by mutation) lets B1's
// staged bytes sit where a header parser would read them.
//
// No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, staging, ToolError, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import type { InspectRequest } from "@local/shared";
import { gmailProvider } from "../../index";
import { inspectOutboundMessageMedia } from "../../inspectors/outbound";
// The staging fakes live in the scaffold's test fixtures; this file runs
// only under vitest.poc.config.ts and is excluded from the package typecheck.
import { FakeD1 } from "../../../../../scaffold/src/staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../../../../scaffold/src/staging/__tests__/__fixtures__/fake-r2";

const NOW = 1_700_000_000;
const CFG = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example" };
const MEDIA_SEND = "/upload/gmail/v1/users/me/messages/send";
const JSON_SEND = "/gmail/v1/users/me/messages/send";
const SENTINEL = "￼";

type Ref = { file_handle: string; token: string };

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  let prepares = 0;
  const origPrepare = d1.prepare.bind(d1);
  d1.prepare = (sql: string) => {
    prepares += 1;
    return origPrepare(sql);
  };
  const deps = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: "https://x.test",
    now: () => NOW,
  };
  const opener = staging.createStagedFileOpener(deps);
  const sent: Array<{ url: string; init: RequestInit; body: Uint8Array }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const rec: (typeof sent)[number] = { url: String(url), init: init ?? {}, body: new Uint8Array(0) };
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
  const audits = () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
  const elicitCalls: Array<{ message: string; requestedSchema: { properties: Record<string, { type: string }> } }> = [];
  const elicitInput = vi.fn(async (params: { message: string; requestedSchema: { properties: Record<string, { type: string }> } }) => {
    elicitCalls.push(params);
    // Accept with one value per requested field, of the requested type.
    const content = Object.fromEntries(
      Object.entries(params.requestedSchema.properties).map(([k, v]) => [k, v.type === "number" ? 1 : v.type === "boolean" ? true : "ok"]),
    );
    return { action: "accept", content };
  });
  const inspected: InspectRequest[] = [];
  // Wrap the real media inspector to record what it is shown.
  const sr = {
    ...gmailProvider.surfaceReview,
    "gmail.users.messages.send.media": {
      ...gmailProvider.surfaceReview["gmail.users.messages.send.media"]!,
      inspect: (req: InspectRequest, env?: Readonly<Record<string, unknown>>) => {
        inspected.push(req);
        return inspectOutboundMessageMedia(req, env);
      },
    },
  };
  const run = (ctx: UpstreamCtx, env: Record<string, string> = ENV) =>
    handleUpstreamRequest({
      ctx,
      spec: gmailProvider.spec,
      surfaceReview: sr,
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "poc",
      props: { refreshToken: "RT", userId: "u1" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as any,
      env: env as { ALLOW_PII_IN_LOGS?: string },
      audit: {},
      oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
      openStaged: opener,
      stagingStore: deps,
      ...(gmailProvider.elicitRenderers ? { elicitRenderers: gmailProvider.elicitRenderers } : {}),
    } as HandleArgs<Record<string, unknown>>);
  const stage = async (bytes: Uint8Array, contentType = "application/pdf", filename: string | null = "q.pdf"): Promise<Ref> => {
    const r = await staging.stageFromBlocks(deps, staging.blockSourceFromBytes(bytes), contentType, filename);
    if (!r.ok) throw new Error("stage failed");
    return { file_handle: r.file_handle, token: r.token };
  };
  return { d1, r2, run, stage, sent, audits, elicitCalls, inspected, prepares: () => prepares };
}

function head(opts: { to?: string; extra?: string[]; terminate?: boolean } = {}): string {
  const lines = [
    "From: me",
    `To: ${opts.to ?? "bob@allowed.example"}`,
    "Subject: Quarterly report",
    ...(opts.extra ?? []),
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b1"',
  ];
  if (opts.terminate === false) return lines.join("\r\n") + "\r\n";
  return (
    lines.join("\r\n") +
    "\r\n\r\n--b1\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nhello\r\n\r\n--b1\r\n" +
    'Content-Type: application/pdf; name="q.pdf"\r\nContent-Disposition: attachment; filename="q.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
  );
}
const TAIL = "--b1--\r\n";

const media = (segments: unknown[], extra: Partial<UpstreamCtx> = {}): UpstreamCtx =>
  ({
    method: "POST",
    path: MEDIA_SEND,
    query: { uploadType: "media" },
    contentType: "message/rfc822",
    composed: { segments },
    ...extra,
  }) as UpstreamCtx;

function assertNoSecrets(text: string, ref: Ref): void {
  expect(text).not.toContain(ref.token);
  expect(text).not.toContain(ref.token.slice(4, 24));
  expect(text).not.toContain(ref.file_handle);
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D7 — structure attacks on the composed RFC 822 body", () => {
  it("FIXED (#59): B1 a staged slot before the header block ends → attachment-before-header-end; no R2 read, no send", async () => {
    const w = world();
    const ref = await w.stage(new TextEncoder().encode("\r\nBcc: evil@attacker.example\r\n\r\nbody"));
    // (identity among text segments never reaches the inspector — B2 below.)
    for (const segments of [
      [{ text: head({ terminate: false }) }, { staged: ref, encoding: "base64" }, { text: "\r\n\r\nbody" }],
      [{ staged: ref, encoding: "identity" }], // a pre-built message: no header block the inspector can read
      [{ text: "To: bob@allowed.example\r\n" }, { staged: ref, encoding: "base64-lines" }, { text: "\r\n\r\n" }],
      [{ text: "To: bob@allowed.example\r\nSubject: x\r\n\r" }, { staged: ref, encoding: "base64" }, { text: "\n\r\n" }],
    ]) {
      const err = await w.run(media(segments)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect((err as Error).message).toMatch(/before the message's header block has ended/);
      expect(w.audits().at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "attachment-before-header-end" });
      assertNoSecrets((err as Error).message, ref);
    }
    expect(w.r2.getCalls).toBe(0);
    expect(w.sent).toHaveLength(0);
  });

  it("REFUTED: B2 identity among text segments → composed-identity-not-sole at entry; zero D1 reads", async () => {
    const w = world();
    const ref = await w.stage(new TextEncoder().encode("To: evil@attacker.example\r\n\r\n"));
    const before = w.prepares();
    const err = await w.run(media([{ text: head() }, { staged: ref, encoding: "identity" }, { text: TAIL }])).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/identity/);
    expect(w.prepares() - before).toBe(0);
    expect(w.inspected).toHaveLength(0);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "composed-identity-not-sole" });
  });

  it("REFUTED: B3 U+FFFC in text, literal or JSON-escaped, is refused at entry — a fake slot cannot make the inspector skip real text", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const escaped = JSON.parse('{"text":"To: bob@allowed.example\\r\\n\\r\\n\\uFFFCBcc: evil@attacker.example"}') as { text: string };
    for (const seg of [{ text: head() + SENTINEL }, escaped, { text: SENTINEL }]) {
      const err = await w.run(media([seg, { staged: ref, encoding: "base64" }, { text: TAIL }])).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect((err as Error).message).toMatch(/U\+FFFC/);
      expect(w.audits().at(-1)).toMatchObject({ reason: "composed-text-reserved-char" });
    }
    expect(w.inspected).toHaveLength(0);
    expect(w.sent).toHaveLength(0);
  });

  it("REFUTED: B5 composed + body / bodyBase64 / rawBody / multipart → multiple-body-channels at entry", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const segments = [{ text: head() }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }];
    const raw = Buffer.from("To: evil@attacker.example\r\n\r\nx").toString("base64url");
    for (const extra of [
      { body: { raw } },
      { bodyBase64: Buffer.from("To: evil@attacker.example\r\n\r\nx").toString("base64") },
      { rawBody: true, body: "To: evil@attacker.example\r\n\r\nx" },
      { multipart: [{ name: "f", value: "x" }] },
    ]) {
      const before = w.prepares();
      const err = await w.run(media(segments, extra as Partial<UpstreamCtx>)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect((err as Error).message).toMatch(/cannot be combined/);
      expect(w.prepares() - before).toBe(0);
      expect(w.audits().at(-1)).toMatchObject({ reason: "multiple-body-channels" });
    }
    expect(w.sent).toHaveLength(0);
  });

  it("REFUTED: B6 uploadType resumable / multipart / absent / with a stray parameter → denied by the media inspector before any R2 read", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const segments = [{ text: head() }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }];
    for (const [query, reason] of [
      [{ uploadType: "resumable" }, "upload-type-not-media"],
      [{ uploadType: "multipart" }, "upload-type-not-media"],
      [{}, "upload-type-not-media"],
      [{ uploadType: "media", upload_protocol: "resumable" }, "upload-type-not-media"],
      [{ uploadType: "media", alt: "media" }, "media-query-param"],
      [{ uploadType: "media", key: "attacker-key" }, "media-query-param"],
    ] as const) {
      const err = await w.run(media(segments, { query: query as NonNullable<UpstreamCtx["query"]> })).catch((e: unknown) => e);
      expect(err, JSON.stringify(query)).toBeInstanceOf(ToolError);
      expect(w.audits().at(-1), JSON.stringify(query)).toMatchObject({ decision: "deny", reason });
    }
    // A wrong content type is refused the same way.
    const err = await w.run(media(segments, { contentType: 'message/rfc822; boundary="x"' })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect(w.audits().at(-1)).toMatchObject({ reason: "media-content-type" });
    expect(w.r2.getCalls).toBe(0);
    expect(w.sent).toHaveLength(0);
  });
});

describe("D7 — recipient gating on the media op", () => {
  it("REFUTED: B7 an off-allowlist To (and Cc, Bcc, folded, display-name tricks) is denied before any R2 read", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    for (const h of [
      { to: "eve@attacker.example" },
      { extra: ["Cc: eve@attacker.example"] },
      { extra: ["Bcc: eve@attacker.example"] },
      { extra: ["Bcc: bob@allowed.example,\r\n eve@attacker.example"] },
      { to: '"bob@allowed.example" <eve@attacker.example>' },
      { to: "eve@attacker.example <bob@allowed.example>" },
    ]) {
      const err = await w.run(media([{ text: head(h) }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }])).catch((e: unknown) => e);
      expect(err, JSON.stringify(h)).toBeInstanceOf(ToolError);
      expect(w.audits().at(-1), JSON.stringify(h)).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "external-send" });
    }
    expect(w.r2.getCalls).toBe(0);
    expect(w.sent).toHaveLength(0);
    // Control: the allowlisted recipient is sent, byte-exact to the view.
    const r = (await w.run(media([{ text: head() }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }]))) as { success: boolean };
    expect(r.success).toBe(true);
    expect(w.sent).toHaveLength(1);
    expect(new URL(w.sent[0]!.url).searchParams.get("uploadType")).toBe("media");
    expect(Buffer.from(w.sent[0]!.body).toString("latin1").startsWith(head())).toBe(true);
  });

  it("REFUTED: B7' a recipient header hidden inside the staged bytes is never a recipient — base64 cannot carry it", async () => {
    const w = world();
    const ref = await w.stage(new TextEncoder().encode("\r\nTo: eve@attacker.example\r\nBcc: eve@attacker.example\r\n\r\n"));
    for (const encoding of ["base64", "base64-lines"] as const) {
      const r = (await w.run(media([{ text: head() }, { staged: ref, encoding }, { text: "\r\n" + TAIL }]))) as { success: boolean };
      expect(r.success).toBe(true);
    }
    for (const s of w.sent) {
      const text = Buffer.from(s.body).toString("latin1");
      expect(text).not.toContain("attacker.example");
      expect(text.slice(0, text.indexOf("\r\n\r\n"))).toBe(head().slice(0, head().indexOf("\r\n\r\n")));
    }
    expect(w.inspected.every((req) => (req.rawBody as string).includes(SENTINEL))).toBe(true);
  });

  it("REFUTED: B10 composed on the JSON messages.send op → staged-not-supported by rule; mass-send still elicits on the media op", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const err = await w
      .run({ method: "POST", path: JSON_SEND, contentType: "application/json", composed: { segments: [{ text: head() }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }] } })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/does not accept staged files/);
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "staged-not-supported", operationId: "gmail.users.messages.send" });
    expect(w.inspected).toHaveLength(0);
    // Mass send on the media op: 26 allowlisted recipients → elicit, accepted → sent.
    const to = Array.from({ length: 26 }, (_, i) => `user${i}@allowed.example`).join(", ");
    const r = (await w.run(media([{ text: head({ to }) }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }]))) as { success: boolean };
    expect(r.success).toBe(true);
    expect(w.elicitCalls).toHaveLength(1);
    expect(w.audits().some((a) => a.reason === "mass-send" && a.elicitationOutcome === "accepted")).toBe(true);
    expect(w.sent).toHaveLength(1);
  });
});

describe("D7 — B8 row filenames cannot shape the view, the dialog or the decision", () => {
  const names = ['x\r\nTo: eve@attacker.example', "q‮fdp.exe", "a​b‏.pdf", "\u0000\u0007bell.pdf"];

  it("REFUTED: the inspection view's rawBody is exactly the text segments; the filename reaches only sanitised metadata; decision unchanged", async () => {
    const w = world();
    for (const name of names) {
      const ref = await w.stage(new Uint8Array(10), "application/pdf", name);
      const r = (await w.run(media([{ text: head() }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }]))) as { success: boolean };
      expect(r.success, JSON.stringify(name)).toBe(true);
      const req = w.inspected.at(-1)!;
      expect(req.rawBody).toBe(head() + SENTINEL + TAIL);
      const meta = req.staged![0]!;
      expect(meta.filename ?? "").not.toMatch(/[\r\n\0\x07]/);
      expect(JSON.stringify(req)).not.toContain("attacker.example\r");
      expect(w.audits().at(-1)).toMatchObject({ decision: "allow", operationId: "gmail.users.messages.send.media" });
    }
    // Nothing of the filename reaches the wire: the body is the text + base64 only.
    for (const s of w.sent) {
      const text = Buffer.from(s.body).toString("utf8");
      expect(text).not.toContain("‮");
      expect(text).not.toContain("attacker.example");
    }
  });

  it("REFUTED: the mass-send dialog's attachments line is control- and bidi-free in both the handler's and the inspector's copies", async () => {
    const w = world();
    const to = Array.from({ length: 26 }, (_, i) => `user${i}@allowed.example`).join(", ");
    for (const name of names) {
      const ref = await w.stage(new Uint8Array(321), "application/pdf", name);
      const r = (await w.run(media([{ text: head({ to }) }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }]))) as { success: boolean };
      expect(r.success).toBe(true);
      const params = w.elicitCalls.at(-1)!;
      const dialog = JSON.stringify(params);
      expect(dialog).not.toMatch(/[‪-‮⁦-⁩​-‏]/);
      expect(dialog).not.toContain("\\r");
      expect(dialog).not.toContain("\\n\\nTo:");
      expect(dialog).not.toContain("\\u0000");
      expect(params.message).toContain("(321 bytes)");
      assertNoSecrets(dialog, ref);
    }
  });
});
