// D6 — Inspected view versus sent bytes for host-assembled bodies (issue #59, D5/D6, red-team R-7, review WP-B finding 1).
//
// Attacker: sandbox code that controls the text segments, the staged file's
//   bytes (it uploaded them), and — through register_file_handle or a D1
//   writer — the row's `filename` and `content_type`.
// Precondition: an inspected operation with `acceptsStaged`; a recording
//   inspector and a recording fetch.
// Payloads: staged bytes containing "\r\n\r\nBcc: evil@x\r\n" in every
//   encoding; a text segment starting with U+FEFF (the review's
//   view/wire divergence); a lone surrogate in text; a row content_type of
//   "multipart/mixed; boundary=zz" and one carrying CRLF as a staged-part
//   default; a row filename with CRLF and quotes.
// Control: the bytes sent equal the inspection view with each U+FFFC
//   replaced by the reference encoding of the staged file and nothing
//   else (byte-exact for base64, base64-lines, identity and multipart);
//   base64 output cannot carry CR/LF/`:`/`--`, so staged bytes never form
//   headers or boundaries; identity is sole-segment only; the view keeps a
//   leading BOM (ignoreBOM) so the wire and the view agree; lone surrogates
//   are refused rather than silently re-encoded; row-derived part defaults
//   are reduced to a media-type essence and control-free filenames.
//
// Pre-v2 reasoning: the channel is new. The BOM case is FIXED (#59): the
// first implementation's `new TextDecoder().decode()` dropped a leading
// U+FEFF from the view while the wire kept EF BB BF, so a Bcc after a
// BOM-led segment hid from the Gmail inspector (verified by mutation:
// removing `ignoreBOM` fails the BOM probe).
//
// FakeD1/FakeR2 only; `fetch` is stubbed. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { Buffer } from "node:buffer";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../../request-handler";
import { ToolError } from "../../elicit";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { blockSourceFromBytes, createStagedFileOpener, stageFromBlocks, type StagedRef } from "../../staging/staged-file";
import { insertClaimed } from "../../staging/repo";
import { sha256Bearer } from "../../staging/crypto";
import { BLOCK_BYTES, type StagingConfig } from "../../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { InspectRequest, SurfaceReview } from "@local/shared";

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
const SENTINEL = "￼";

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/upload/send": { post: op("sendMedia") },
    "/attach/{name}": { put: op("attach") },
    "/files": { post: op("files") },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

function pattern(n: number, seed = 13): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}

/** Reference encodings, independent of the scaffold's codec. */
const refBase64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const refLines = (b: Uint8Array) => {
  const s = refBase64(b);
  let out = "";
  for (let i = 0; i < s.length; i += 76) out += s.slice(i, i + 76) + "\r\n";
  return out;
};

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const D1 = d1 as unknown as D1Database;
  const deps = { STAGING_D1: D1, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, uploadOrigin: "https://x.test", now: () => NOW };
  const opener = createStagedFileOpener(deps);
  const inspected: InspectRequest[] = [];
  const SR: SurfaceReview = {
    sendMedia: {
      decision: "allow",
      acceptsStaged: true,
      inspect: (req) => {
        inspected.push(req);
        return { decision: "allow" };
      },
    },
    attach: {
      decision: "allow",
      acceptsStaged: true,
      inspect: (req) => {
        inspected.push(req);
        return { decision: "allow" };
      },
    },
    files: {
      decision: "allow",
      acceptsStaged: true,
      inspect: (req) => {
        inspected.push(req);
        return { decision: "allow" };
      },
    },
  };
  const sent: Array<{ body: Uint8Array; init: RequestInit }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
      const rec = { body: new Uint8Array(0), init: init ?? {} };
      sent.push(rec);
      const body = init?.body as ReadableStream<Uint8Array> | undefined;
      if (body instanceof ReadableStream) {
        const chunks: Uint8Array[] = [];
        const reader = body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        rec.body = Buffer.concat(chunks);
      }
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }),
  );
  vi.spyOn(console, "log").mockImplementation(() => {});
  const args = (ctx: UpstreamCtx, extra: Partial<HandleArgs<Record<string, unknown>>> = {}): HandleArgs<Record<string, unknown>> => ({
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "poc",
    props: { refreshToken: "RT", userId: "u1" },
    server: {} as never,
    env: {},
    audit: {},
    oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
    openStaged: opener,
    stagingStore: deps,
    ...extra,
  });
  const stage = async (bytes: Uint8Array, contentType = "application/pdf", filename: string | null = "q.pdf"): Promise<StagedRef> => {
    const r = await stageFromBlocks(deps, blockSourceFromBytes(bytes), contentType, filename);
    if (!r.ok) throw new Error("stage failed");
    return { file_handle: r.file_handle, token: r.token };
  };
  /** A D1 writer planting arbitrary row metadata over a real object. */
  const stageWithRow = async (bytes: Uint8Array, contentType: string, filename: string | null): Promise<StagedRef> => {
    const ref = await stage(bytes);
    const key = Buffer.from(await sha256Bearer(ref.token)).toString("hex");
    const row = d1.rows.get(key)!;
    d1.rows.delete(key);
    await insertClaimed(D1, {
      token_hash: Buffer.from(key, "hex"),
      file_handle: ref.file_handle,
      r2_key: row.r2_key!,
      iv: Buffer.from(row.iv_hex!, "hex"),
      content_type: contentType,
      byte_len: row.byte_len!,
      filename,
      created_at: NOW,
      claimed_at: NOW,
      expires_at: NOW + 3600,
      enc_version: 2,
    });
    return ref;
  };
  return { args, stage, stageWithRow, inspected, sent };
}

/** The wire bytes the view promises: text verbatim (UTF-8), each sentinel
 *  replaced by the reference encoding of the corresponding staged file. */
function expand(view: InspectRequest, files: Uint8Array[]): Uint8Array {
  const raw = view.rawBody as string;
  const parts: Uint8Array[] = [];
  let k = 0;
  let last = 0;
  for (let i = raw.indexOf(SENTINEL); i >= 0; i = raw.indexOf(SENTINEL, i + 1)) {
    parts.push(Buffer.from(raw.slice(last, i), "utf8"));
    const meta = view.staged![k]!;
    const file = files[k++]!;
    parts.push(
      Buffer.from(
        meta.encoding === "identity" ? Buffer.from(file).toString("latin1") : meta.encoding === "base64" ? refBase64(file) : refLines(file),
        "latin1",
      ),
    );
    last = i + 1;
  }
  parts.push(Buffer.from(raw.slice(last), "utf8"));
  return Buffer.concat(parts);
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const SMUGGLE = "\r\n\r\nBcc: evil@x\r\n";
const HEAD = "From: a@x\r\nTo: b@x\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Transfer-Encoding: base64\r\n\r\n";
const TAIL = "\r\n--b1--\r\n";

describe("D6 — byte-exact differential (B4/B9)", () => {
  for (const encoding of ["base64", "base64-lines"] as const) {
    it(`REFUTED: ${encoding}: sent bytes == view with each U+FFFC expanded by the reference encoder, nothing else; smuggled headers stay inert`, async () => {
      const w = world();
      const fileA = Buffer.concat([pattern(BLOCK_BYTES + 100), Buffer.from(SMUGGLE)]);
      const fileB = Buffer.concat([Buffer.from(SMUGGLE), pattern(57 * 3 + 1)]);
      const refA = await w.stage(fileA);
      const refB = await w.stage(fileB);
      await handleUpstreamRequest(
        w.args({
          method: "POST",
          path: "/upload/send",
          contentType: "message/rfc822",
          composed: {
            segments: [{ text: HEAD }, { staged: refA, encoding }, { text: "\r\n--b1\r\n\r\n" }, { staged: refB, encoding }, { text: TAIL }],
          },
        }),
      );
      const view = w.inspected[0]!;
      const wire = w.sent[0]!.body;
      expect(Buffer.from(wire).equals(Buffer.from(expand(view, [fileA, fileB])))).toBe(true);
      expect(Number((w.sent[0]!.init.headers as Record<string, string>)["Content-Length"])).toBe(wire.byteLength);
      expect(view.assembledByteLength).toBe(wire.byteLength);
      // The smuggled header never appears on the wire outside base64, and the
      // header block the upstream parses is exactly the text segment's.
      const text = Buffer.from(wire).toString("latin1");
      expect(text).not.toContain("Bcc: evil@x");
      expect(text.indexOf("\r\n\r\n")).toBe(HEAD.indexOf("\r\n\r\n"));
      expect((view.rawBody as string).split(SENTINEL)).toHaveLength(3);
    });
  }

  it("REFUTED: identity: a sole staged segment is sent verbatim; identity among text segments is refused (so staged bytes never join a text header block)", async () => {
    const w = world();
    const file = Buffer.from("%PDF" + SMUGGLE);
    const ref = await w.stage(file);
    await handleUpstreamRequest(
      w.args({ method: "PUT", path: "/attach/q.pdf", contentType: "application/pdf", composed: { segments: [{ staged: ref, encoding: "identity" }] } }),
    );
    expect(Buffer.from(w.sent[0]!.body).equals(file)).toBe(true);
    expect(w.inspected[0]!.rawBody).toBe(SENTINEL);
    expect(w.inspected[0]!.staged![0]!.encoding).toBe("identity");
    const err = await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/upload/send",
        composed: { segments: [{ text: HEAD }, { staged: ref, encoding: "identity" }, { text: TAIL }] },
      }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/identity/);
    expect(w.sent).toHaveLength(1);
  });

  it("REFUTED: multipart: the wire equals the hand-built reference behind the host boundary; the inspector sees metadata only", async () => {
    const w = world();
    const file = Buffer.concat([Buffer.from("--"), pattern(3000), Buffer.from(SMUGGLE)]);
    const ref = await w.stage(file, "image/png", "a.png");
    await handleUpstreamRequest(
      w.args({ method: "POST", path: "/files", multipart: [{ name: "Name", value: "x" }, { name: "file", staged: ref }] }),
    );
    const init = w.sent[0]!.init;
    const ct = (init.headers as Record<string, string>)["content-type"]!;
    const boundary = /^multipart\/form-data; boundary=(.+)$/.exec(ct)![1]!;
    expect(boundary).toMatch(/^----codemode-[0-9a-f]{48}$/);
    const reference = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="Name"\r\nContent-Type: text/plain\r\n\r\nx\r\n` +
          `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.png"\r\nContent-Type: image/png\r\n\r\n`,
      ),
      file,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    expect(Buffer.from(w.sent[0]!.body).equals(reference)).toBe(true);
    const view = w.inspected[0]!;
    expect(view.multipart).toEqual([
      { name: "Name", value: "x" },
      { name: "file", filename: "a.png", contentType: "image/png", staged: { byteLength: file.byteLength, contentType: "image/png", filename: "a.png" } },
    ]);
    expect(JSON.stringify(view)).not.toContain("Bcc");
    expect(view.assembledByteLength).toBe(reference.byteLength);
  });
});

describe("D6 — text-segment encoding edge cases", () => {
  it("FIXED (#59): a text segment beginning with U+FEFF keeps the BOM in the view, so the view's header block ends where the wire's does", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    // Review WP-B finding 1 payload: the BOM-led second segment used to lose
    // three bytes in the view, shifting the header terminator.
    const segments = [
      { text: "From: me@x\r\nTo: ok@allowed\r\n" },
      { text: "﻿\r\nBcc: victim@external\r\n\r\nbody\r\n" },
      { staged: ref, encoding: "base64" as const },
    ];
    await handleUpstreamRequest(w.args({ method: "POST", path: "/upload/send", contentType: "message/rfc822", composed: { segments } }));
    const view = w.inspected[0]!;
    const wire = w.sent[0]!.body;
    expect(Buffer.from(wire).equals(Buffer.from(expand(view, [pattern(10)])))).toBe(true);
    const raw = view.rawBody as string;
    expect(raw.startsWith("From: me@x\r\nTo: ok@allowed\r\n﻿")).toBe(true);
    // Both readers find the header block ending at the same byte offset: the
    // BOM is a non-empty line between the two CRLFs, so the block runs on.
    const viewEnd = Buffer.from(raw.slice(0, raw.indexOf("\r\n\r\n")), "utf8").byteLength;
    const wireEnd = Buffer.from(wire).indexOf("\r\n\r\n");
    expect(viewEnd).toBe(wireEnd);
    // The Bcc therefore sits INSIDE the header block for the wire's reader —
    // and now for the inspector too, which is what lets it be judged. The
    // pre-fix view ended its header block at 26 (BOM stripped) and showed the
    // Bcc as body text.
    expect(Buffer.from(wire).indexOf("Bcc:")).toBeLessThan(wireEnd);
    expect(raw.indexOf("Bcc:")).toBeLessThan(raw.indexOf("\r\n\r\n"));
    expect(raw.indexOf("\r\n\r\n")).not.toBe(26);
  });

  it("REFUTED: a BOM-only text segment and a segment that is a lone BOM between staged slots survive byte for byte", async () => {
    const w = world();
    const f = pattern(5);
    const ref = await w.stage(f);
    await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/upload/send",
        composed: { segments: [{ text: "﻿" }, { staged: ref, encoding: "base64" }, { text: "﻿" }, { staged: ref, encoding: "base64" }, { text: "﻿﻿" }] },
      }),
    );
    const view = w.inspected[0]!;
    const wire = w.sent[0]!.body;
    expect(Buffer.from(wire).equals(Buffer.from(expand(view, [f, f])))).toBe(true);
    expect(wire.byteLength).toBe(4 * 3 + 2 * refBase64(f).length);
  });

  it("REFUTED: a lone surrogate in text is refused as malformed, never sent as U+FFFD", async () => {
    const w = world();
    const ref = await w.stage(pattern(5));
    for (const text of ["To: a\uD83D\r\n\r\n", "\uDE00", "x\uD800", "\uDC00y"]) {
      const err = await handleUpstreamRequest(
        w.args({ method: "POST", path: "/upload/send", composed: { segments: [{ text }, { staged: ref, encoding: "base64" }] } }),
      ).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect((err as Error).message).toMatch(/lone surrogate/);
    }
    expect(w.sent).toHaveLength(0);
    expect(w.inspected).toHaveLength(0);
  });

  it("REFUTED: non-ASCII text is sent as UTF-8 exactly once and the view is the same string", async () => {
    const w = world();
    const ref = await w.stage(pattern(5));
    const text = "Subject: café — ünïcödé 🙂\r\n\r\n";
    await handleUpstreamRequest(
      w.args({ method: "POST", path: "/upload/send", composed: { segments: [{ text }, { staged: ref, encoding: "base64" }] } }),
    );
    expect((w.inspected[0]!.rawBody as string).startsWith(text)).toBe(true);
    expect(Buffer.from(w.sent[0]!.body).subarray(0, Buffer.byteLength(text)).equals(Buffer.from(text, "utf8"))).toBe(true);
  });
});

describe("D6 — row-derived multipart part defaults (R-7)", () => {
  it("FIXED (#59): a row content_type of 'multipart/mixed; boundary=zz' becomes the bare essence in the part header, never a nested boundary", async () => {
    const w = world();
    const file = pattern(100);
    const ref = await w.stageWithRow(file, "multipart/mixed; boundary=zz", "q.pdf");
    await handleUpstreamRequest(w.args({ method: "POST", path: "/files", multipart: [{ name: "file", staged: ref }] }));
    const text = Buffer.from(w.sent[0]!.body).toString("latin1");
    expect(text).toContain('; filename="q.pdf"\r\nContent-Type: multipart/mixed\r\n\r\n');
    expect(text).not.toContain("boundary=zz");
    expect(w.inspected[0]!.multipart![0]!.contentType).toBe("multipart/mixed");
  });

  it("FIXED (#59): a row content_type carrying CRLF (D1 writer) is replaced by application/octet-stream; the part header gains no line", async () => {
    const w = world();
    const ref = await w.stageWithRow(pattern(10), "application/pdf\r\nX-Injected: 1", "q.pdf");
    await handleUpstreamRequest(w.args({ method: "POST", path: "/files", multipart: [{ name: "file", staged: ref }] }));
    const text = Buffer.from(w.sent[0]!.body).toString("latin1");
    expect(text).toContain("Content-Type: application/octet-stream\r\n\r\n");
    expect(text).not.toContain("X-Injected");
    expect(JSON.stringify(w.inspected[0])).not.toContain("X-Injected");
  });

  it("FIXED (#59): a row filename with CRLF, quotes and a bidi override cannot add a header line or escape the quoted attribute", async () => {
    const w = world();
    const ref = await w.stageWithRow(pattern(10), "application/pdf", 'q"\r\nContent-Type: text/html\r\n‮fdp.exe');
    await handleUpstreamRequest(w.args({ method: "POST", path: "/files", multipart: [{ name: "file", staged: ref }] }));
    const text = Buffer.from(w.sent[0]!.body).toString("utf8");
    const start = text.lastIndexOf("--", text.indexOf('name="file"'));
    const partHead = text.slice(start, text.indexOf("\r\n\r\n", start));
    const lines = partHead.split("\r\n");
    // Delimiter, Content-Disposition, Content-Type — and no injected line.
    expect(lines).toHaveLength(3);
    expect(lines[1]).toBe('Content-Disposition: form-data; name="file"; filename="qContent-Type: text/html‮fdp.exe"');
    expect(lines[2]).toBe("Content-Type: application/pdf");
    // The inspector's copy of the filename carries no control characters (a
    // quote is metadata there; the wire line above shows it stripped).
    expect(w.inspected[0]!.multipart![0]!.filename).not.toMatch(/[\r\n\0]/);
  });

  it("REFUTED: a sandbox-supplied filename/contentType on a staged part still goes through the CR/LF/NUL check", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    for (const extra of [{ filename: "a\r\nb" }, { contentType: "text/plain\nX: 1" }, { filename: "a\0b" }]) {
      await expect(
        handleUpstreamRequest(w.args({ method: "POST", path: "/files", multipart: [{ name: "file", staged: ref, ...extra }] })),
      ).rejects.toThrow(/may not contain CR, LF or NUL/);
    }
    expect(w.sent).toHaveLength(0);
  });
});
