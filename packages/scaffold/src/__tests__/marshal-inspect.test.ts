import { describe, it, expect } from "vitest";
import {
  bodyChannelCount,
  resolveEffective,
  marshalBody,
  deriveInspectRequest,
  isJsonContentType,
  INSPECT_JSON_MAX_BYTES,
} from "../request-handler";
import { ToolError } from "../elicit";

function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

describe("isJsonContentType", () => {
  it("recognizes JSON content-types", () => {
    expect(isJsonContentType("application/json")).toBe(true);
    expect(isJsonContentType("application/json; charset=utf-8")).toBe(true);
    expect(isJsonContentType("APPLICATION/JSON")).toBe(true);
    expect(isJsonContentType("application/fhir+json")).toBe(true);
  });

  // F-7: upstreams read these as JSON too, and fetch's Headers strips edge
  // whitespace, so each must be judged (and canonicalised) as JSON.
  it("recognises JSON variants and edge whitespace", () => {
    for (const ct of [" application/json", "\tapplication/json", "application/json \r\n", "text/json", "application/x-json", "text/x-json", "application/json ; charset=utf-8"]) {
      expect(isJsonContentType(ct), JSON.stringify(ct)).toBe(true);
    }
  });

  it("rejects non-JSON or missing content-types", () => {
    expect(isJsonContentType(undefined)).toBe(false);
    expect(isJsonContentType("application/jsonx")).toBe(false);
    expect(isJsonContentType("application/json-seq")).toBe(false);
    expect(isJsonContentType("message/rfc822")).toBe(false);
    expect(isJsonContentType("json")).toBe(false);
  });
});

describe("bodyChannelCount", () => {
  it("counts each distinct body channel", () => {
    expect(bodyChannelCount({ method: "POST", path: "/x" })).toBe(0);
    expect(bodyChannelCount({ method: "POST", path: "/x", body: { a: 1 } })).toBe(1);
    expect(bodyChannelCount({ method: "POST", path: "/x", bodyBase64: "AA==" })).toBe(1);
    expect(bodyChannelCount({ method: "POST", path: "/x", multipart: [{ name: "f" }] })).toBe(1);
    expect(
      bodyChannelCount({ method: "POST", path: "/x", body: { a: 1 }, bodyBase64: "AA==" }),
    ).toBe(2);
  });

  it("counts an empty-string bodyBase64 as a present channel", () => {
    expect(bodyChannelCount({ method: "POST", path: "/x", bodyBase64: "" })).toBe(1);
  });
});

describe("resolveEffective precedence", () => {
  it("multipart wins over everything", () => {
    const eff = resolveEffective({
      method: "POST",
      path: "/x",
      body: { a: 1 },
      bodyBase64: b64("z"),
      multipart: [{ name: "f", value: "v" }],
    });
    expect(eff.kind).toBe("multipart");
  });

  it("bodyBase64 wins over body and decodes to bytes", () => {
    const eff = resolveEffective({
      method: "POST",
      path: "/x",
      body: { a: 1 },
      bodyBase64: b64('{"raw":"hi"}'),
      contentType: "application/json",
    });
    expect(eff.kind).toBe("raw");
    if (eff.kind === "raw") {
      expect(new TextDecoder().decode(eff.bytes)).toBe('{"raw":"hi"}');
      expect(eff.contentType).toBe("application/json");
    }
  });

  it("plain body becomes json with default content-type", () => {
    const eff = resolveEffective({ method: "POST", path: "/x", body: { a: 1 } });
    expect(eff).toEqual({ kind: "json", body: { a: 1 }, contentType: "application/json" });
  });

  it("trims HTTP whitespace off the content-type, as fetch's Headers does (F-7)", () => {
    const eff = resolveEffective({ method: "POST", path: "/x", bodyBase64: b64("{}"), contentType: "\t application/json \r\n" });
    expect(eff.kind === "raw" && eff.contentType).toBe("application/json");
    const json = resolveEffective({ method: "POST", path: "/x", body: {}, contentType: " application/json" });
    expect(json.kind === "json" && json.contentType).toBe("application/json");
  });

  it("no body is 'none'", () => {
    expect(resolveEffective({ method: "GET", path: "/x" })).toEqual({ kind: "none" });
  });

  it("rawBody + string body becomes raw with TextEncoder-encoded bytes", () => {
    const eff = resolveEffective({
      method: "POST",
      path: "/x",
      rawBody: true,
      body: "plain text",
      contentType: "text/plain",
    });
    expect(eff.kind).toBe("raw");
    if (eff.kind === "raw") {
      expect(eff.bytes).toEqual(new TextEncoder().encode("plain text"));
      expect(eff.contentType).toBe("text/plain");
    }
  });

  it("rawBody + non-string body throws", () => {
    expect(() =>
      resolveEffective({ method: "POST", path: "/x", rawBody: true, body: { a: 1 } }),
    ).toThrow(/rawBody requires a string body/);
  });
});

describe("marshalBody preserves legacy wire behavior", () => {
  it("json → JSON.stringify + application/json", () => {
    const ctx = { method: "POST" as const, path: "/x", body: { a: 1 } };
    const eff = resolveEffective(ctx);
    const m = marshalBody(ctx, eff);
    expect(m.bodyToSend).toBe('{"a":1}');
    expect(m.contentType).toBe("application/json");
  });

  it("bodyBase64 → decoded bytes verbatim", () => {
    const ctx = { method: "POST" as const, path: "/x", bodyBase64: b64("PDF-BYTES"), contentType: "application/pdf" };
    const eff = resolveEffective(ctx);
    const m = marshalBody(ctx, eff);
    expect(new TextDecoder().decode(m.bodyToSend as Uint8Array)).toBe("PDF-BYTES");
    expect(m.contentType).toBe("application/pdf");
  });

  it("multipart → assembled body with boundary content-type", () => {
    const ctx = { method: "POST" as const, path: "/x", multipart: [{ name: "f", value: "v" }] };
    const eff = resolveEffective(ctx);
    const m = marshalBody(ctx, eff);
    expect(m.contentType).toMatch(/^multipart\/form-data; boundary=/);
    expect(m.bodyToSend).toBeInstanceOf(Uint8Array);
  });

  it("multipart → CR/LF/NUL in name, filename or contentType throws ToolError (F-11)", () => {
    for (const part of [
      { name: "f\r\nX-Injected: 1", value: "v" },
      { name: "f", filename: "a.pdf\nX: 1", value: "v" },
      { name: "f", filename: "a\0.pdf", value: "v" },
      { name: "f", contentType: "text/plain\r\n\r\n--b", value: "v" },
    ]) {
      const ctx = { method: "POST" as const, path: "/x", multipart: [part] };
      const eff = resolveEffective(ctx);
      expect(() => marshalBody(ctx, eff)).toThrow(ToolError);
      expect(() => marshalBody(ctx, eff)).toThrow(/may not contain CR, LF or NUL/);
    }
  });

  it("none → no body; honours an explicit caller content-type", () => {
    const ctxNoCt = { method: "GET" as const, path: "/x" };
    const effNoCt = resolveEffective(ctxNoCt);
    const mNoCt = marshalBody(ctxNoCt, effNoCt);
    expect(mNoCt.bodyToSend).toBeUndefined();
    expect(mNoCt.contentType).toBeUndefined();

    const ctxCt = { method: "GET" as const, path: "/x", contentType: "text/plain" };
    const effCt = resolveEffective(ctxCt);
    const mCt = marshalBody(ctxCt, effCt);
    expect(mCt.bodyToSend).toBeUndefined();
    expect(mCt.contentType).toBe("text/plain");
  });
});

describe("deriveInspectRequest", () => {
  it("json body passes through parsed", () => {
    const ctx = { method: "POST" as const, path: "/x", body: { raw: "x" }, query: { q: "1" } };
    const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
    expect(d.oversize).toBeUndefined();
    expect(d.req).toEqual({ query: { q: "1" }, body: { raw: "x" }, contentType: "application/json" });
  });

  it("bodyBase64 JSON is decoded AND parsed into body (the bypass channel)", () => {
    const ctx = {
      method: "POST" as const,
      path: "/x",
      bodyBase64: b64('{"raw":"ZXZpbA=="}'),
      contentType: "application/json",
    };
    const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
    expect(d.req.body).toEqual({ raw: "ZXZpbA==" });
    expect(d.req.rawBody).toBeUndefined();
  });

  it("non-JSON rawBody is exposed as rawBody bytes", () => {
    const ctx = { method: "POST" as const, path: "/x", bodyBase64: b64("To: a@b\r\n\r\nhi"), contentType: "message/rfc822" };
    const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
    expect(d.req.body).toBeUndefined();
    expect(d.req.contentType).toBe("message/rfc822");
    expect(new TextDecoder().decode(d.req.rawBody as Uint8Array)).toContain("To: a@b");
  });

  it("JSON-typed bytes that do not parse are flagged unparseable (F-7)", () => {
    const ctx = { method: "POST" as const, path: "/x", bodyBase64: b64('{"a":'), contentType: "text/json" };
    const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
    expect(d.unparseableJson).toBe(true);
    expect(d.sendAs).toBeUndefined();
  });

  it("multipart is exposed as structured parts", () => {
    const ctx = { method: "POST" as const, path: "/x", multipart: [{ name: "meta", value: "{}" }] };
    const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
    expect(d.req.multipart).toEqual([{ name: "meta", value: "{}" }]);
    expect(d.req.contentType).toBe("multipart/form-data");
  });

  it("oversize JSON is flagged, not parsed", () => {
    const big = "x".repeat(10);
    const ctx = { method: "POST" as const, path: "/x", bodyBase64: b64(`{"a":"${big}"}`), contentType: "application/json" };
    const d = deriveInspectRequest(ctx, resolveEffective(ctx), 4); // tiny cap
    expect(d.oversize).toBe(true);
    expect(d.req.body).toBeUndefined();
  });

  it("no body ('none' kind): req has only query when provided, no oversize flag", () => {
    const ctxNoQuery = { method: "GET" as const, path: "/x" };
    const dNoQuery = deriveInspectRequest(ctxNoQuery, resolveEffective(ctxNoQuery), INSPECT_JSON_MAX_BYTES);
    expect(dNoQuery.oversize).toBeUndefined();
    expect(dNoQuery.req).toEqual({});

    const ctxQuery = { method: "GET" as const, path: "/x", query: { q: "1" } };
    const dQuery = deriveInspectRequest(ctxQuery, resolveEffective(ctxQuery), INSPECT_JSON_MAX_BYTES);
    expect(dQuery.oversize).toBeUndefined();
    expect(dQuery.req).toEqual({ query: { q: "1" } });
  });

  describe("sendAs (F-7)", () => {
    it("is set only when raw JSON-typed bytes parse; it carries the parsed value", () => {
      const ctx = {
        method: "POST" as const,
        path: "/x",
        bodyBase64: b64('{"to":"a","to":"b"}'),
        contentType: "application/json",
      };
      const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
      expect(d.req.body).toEqual({ to: "b" });
      expect(d.sendAs).toEqual({ kind: "json", body: { to: "b" }, contentType: "application/json" });
      // Same object the inspector judges, so the send is exactly what was inspected.
      expect(d.sendAs?.kind === "json" && d.sendAs.body).toBe(d.req.body);
      const m = marshalBody(ctx, d.sendAs!);
      expect(m.bodyToSend).toBe('{"to":"b"}');
      expect(m.contentType).toBe("application/json");
    });

    it("is unset for invalid JSON, non-JSON raw bytes, oversize JSON, plain body, multipart and none", () => {
      const cases = [
        { method: "POST" as const, path: "/x", bodyBase64: b64("{not json"), contentType: "application/json" },
        { method: "POST" as const, path: "/x", bodyBase64: b64("To: a@b\r\n\r\nhi"), contentType: "message/rfc822" },
        { method: "POST" as const, path: "/x", body: { a: 1 } },
        { method: "POST" as const, path: "/x", multipart: [{ name: "f", value: "v" }] },
        { method: "GET" as const, path: "/x" },
      ];
      for (const ctx of cases) {
        const d = deriveInspectRequest(ctx, resolveEffective(ctx), INSPECT_JSON_MAX_BYTES);
        expect(d.sendAs).toBeUndefined();
      }
      const big = { method: "POST" as const, path: "/x", bodyBase64: b64('{"a":"xxxxxxxx"}'), contentType: "application/json" };
      expect(deriveInspectRequest(big, resolveEffective(big), 4).sendAs).toBeUndefined();
    });
  });
});
