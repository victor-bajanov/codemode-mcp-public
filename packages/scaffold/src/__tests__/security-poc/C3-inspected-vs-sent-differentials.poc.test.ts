// Security-review POC C3 — differentials between what an inspector sees and
// what is sent upstream.
//
// (a) Raw JSON channel: `bodyBase64`/`rawBody` with a JSON content-type was
//     parsed with JSON.parse for the inspector but the ORIGINAL bytes were
//     sent. JSON.parse keeps the LAST duplicate key (and TextDecoder strips a
//     BOM); an upstream parser that keeps the first (or rejects) saw a
//     different document.
// (b) Multipart: part `name` / `filename` / `contentType` were interpolated
//     into the generated part headers with only `"` stripped, so CR/LF in
//     those fields injected extra header lines into the wire body while the
//     inspector was handed the structured `multipart` array.
//
// Status: (a) FIXED (F-7) — on inspected operations parseable raw JSON is sent
// as `JSON.stringify(parsed)` (`DerivedInspect.sendAs`), i.e. exactly what the
// inspector judged; (b) FIXED (F-11) — CR, LF or NUL in those part fields is
// refused, and so is any non-string part field (an array-valued
// `contentType` was stringified into the header, carrying its CRLF with it)
// (`marshalBody` throws; the handler denies at entry).
//
// The original payloads are kept as regression inputs.
import { describe, it, expect } from "vitest";
import { ToolError } from "../../elicit";
import {
  resolveEffective,
  deriveInspectRequest,
  marshalBody,
  INSPECT_JSON_MAX_BYTES,
  type UpstreamCtx,
} from "../../request-handler";

function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

describe("C3a raw JSON channel: inspector sees JSON.parse(bytes), upstream gets the same document (FIXED F-7)", () => {
  it("FIXED (F-7): duplicate keys: inspector sees the last value, the wire carries exactly that", () => {
    const wire = '{"raw":"QUxMT1dFRA","raw":"RVZJTA"}'; // ALLOWED then EVIL
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/gmail/v1/users/me/messages/send",
      bodyBase64: b64(wire),
      contentType: "application/json",
    };
    const eff = resolveEffective(ctx);
    expect(eff.kind).toBe("raw");
    const derived = deriveInspectRequest(ctx, eff, INSPECT_JSON_MAX_BYTES);
    // Inspector view: a single `raw` key with the LAST value.
    expect(derived.req.body).toEqual({ raw: "RVZJTA" });
    // Wire view: the handler marshals `derived.sendAs` on inspected ops — the
    // canonical re-serialisation of what the inspector judged, not the bytes.
    expect(derived.sendAs).toBeDefined();
    const { bodyToSend, contentType } = marshalBody(ctx, derived.sendAs!);
    expect(bodyToSend).toBe(JSON.stringify(derived.req.body));
    expect(bodyToSend).toBe('{"raw":"RVZJTA"}');
    expect(bodyToSend).not.toContain("QUxMT1dFRA");
    expect(contentType).toBe("application/json");
  });

  it("FIXED (F-7): a BOM-prefixed body goes out as the BOM-less document the inspector judged", () => {
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/gmail/v1/users/me/messages/send",
      bodyBase64: b64('\uFEFF{"raw":"RVZJTA"}'),
      contentType: "application/json",
    };
    const eff = resolveEffective(ctx);
    const derived = deriveInspectRequest(ctx, eff, INSPECT_JSON_MAX_BYTES);
    expect(derived.req.body).toEqual({ raw: "RVZJTA" });
    const { bodyToSend } = marshalBody(ctx, derived.sendAs!);
    expect(bodyToSend).toBe(JSON.stringify(derived.req.body));
  });

  it("the plain `body` channel has no such differential (same object is stringified)", () => {
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/x",
      body: { raw: "RVZJTA" },
    };
    const eff = resolveEffective(ctx);
    const derived = deriveInspectRequest(ctx, eff, INSPECT_JSON_MAX_BYTES);
    const { bodyToSend } = marshalBody(ctx, eff);
    expect(JSON.parse(bodyToSend as string)).toEqual(derived.req.body);
  });

  it("invalid JSON under a JSON content-type falls back to rawBody for the inspector (fail-closed path)", () => {
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/x",
      bodyBase64: b64('{"raw":"A"} trailing'),
      contentType: "application/json",
    };
    const eff = resolveEffective(ctx);
    const derived = deriveInspectRequest(ctx, eff, INSPECT_JSON_MAX_BYTES);
    expect(derived.req.body).toBeUndefined();
    expect(derived.req.rawBody).toBeInstanceOf(Uint8Array);
    // Nothing to canonicalise: the inspector judged these very bytes.
    expect(derived.sendAs).toBeUndefined();
  });
});

describe("C3b multipart part-header injection (FIXED F-11)", () => {
  it("FIXED (F-11): CRLF in a part filename can no longer inject headers into the wire body", () => {
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/files.xro/1.0/Files",
      multipart: [
        {
          name: "file",
          filename: 'ok.pdf\r\nContent-Disposition: form-data; name="file"; filename="evil.exe',
          contentType: "application/pdf",
          bodyBase64: b64("%PDF-1.4"),
        },
      ],
    };
    const eff = resolveEffective(ctx);
    expect(eff.kind).toBe("multipart");
    // Inspector view: a structured part whose filename is one (odd) string.
    const derived = deriveInspectRequest(ctx, eff, INSPECT_JSON_MAX_BYTES);
    expect(derived.req.multipart?.[0]?.filename).toContain("evil.exe");
    // Wire view: used to carry two Content-Disposition header lines inside the
    // same part; marshalling now refuses.
    expect(() => marshalBody(ctx, eff)).toThrow(ToolError);
    expect(() => marshalBody(ctx, eff)).toThrow(/`filename` may not contain CR, LF or NUL/);
  });

  it("FIXED (F-11): CRLF in a part contentType is refused too", () => {
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/files.xro/1.0/Files",
      multipart: [
        {
          name: "file",
          filename: "ok.pdf",
          contentType: "application/pdf\r\nX-Injected: 1",
          bodyBase64: b64("%PDF-1.4"),
        },
      ],
    };
    const eff = resolveEffective(ctx);
    expect(() => marshalBody(ctx, eff)).toThrow(ToolError);
    expect(() => marshalBody(ctx, eff)).toThrow(/`contentType` may not contain CR, LF or NUL/);
  });

  it("FIXED (F-11): a non-string contentType/name/filename cannot reach the wire either", () => {
    // An array is stringified by the header template literal, so a string-only
    // CR/LF check let `["application/pdf\r\nX-Injected: 1"]` through.
    const parts = [
      [{ name: "file", filename: "ok.pdf", contentType: ["application/pdf\r\nX-Injected: 1"], bodyBase64: b64("%PDF-1.4") }, /`contentType` must be a string when present/],
      [{ name: ["file\r\nX-Injected: 1"], filename: "ok.pdf", bodyBase64: b64("%PDF-1.4") }, /`name` must be a non-empty string/],
      [{ name: "file", filename: { toString: "x" }, bodyBase64: b64("%PDF-1.4") }, /`filename` must be a string when present/],
    ] as const;
    for (const [part, message] of parts) {
      const ctx = { method: "POST", path: "/files.xro/1.0/Files", multipart: [part] } as unknown as UpstreamCtx;
      const eff = resolveEffective(ctx);
      expect(() => marshalBody(ctx, eff)).toThrow(ToolError);
      expect(() => marshalBody(ctx, eff)).toThrow(message);
    }
  });
});
