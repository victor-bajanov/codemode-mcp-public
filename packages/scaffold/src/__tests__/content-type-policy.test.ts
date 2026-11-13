/**
 * D-3 / C-4 — content-type policy (pure functions).
 *
 * Attacker: sandbox code that chooses `contentType` on `codemode.request`.
 * Precondition: an inspected or approval-gated operation that sends an
 * object `body` as JSON.
 * Payload: a label that makes the upstream re-interpret the JSON bytes
 * (`application/x-www-form-urlencoded`, `text/json`,
 * `application/json; charset=utf-7`), or free prose / newlines in the label
 * that a dialog would echo (C-4).
 * Control: `parseMediaType` accepts only the RFC 7231 media-type grammar
 * (at most 100 characters, no control characters); `canonicalJsonContentType`
 * yields exactly `application/json` only for a JSON essence with no
 * parameters or `charset=utf-8`, and `undefined` for anything else.
 * Pre-fix: no grammar check existed and `isJsonContentType` ignored
 * parameters, so every such label reached the wire.
 */
import { describe, it, expect } from "vitest";
import { parseMediaType, canonicalJsonContentType } from "../content-type-policy";

describe("parseMediaType — accepts the RFC 7231 media-type grammar", () => {
  const accepted: Array<[string, { type: string; subtype: string; params: Record<string, string> }]> = [
    ["application/json", { type: "application", subtype: "json", params: {} }],
    ["APPLICATION/JSON", { type: "application", subtype: "json", params: {} }],
    [" application/json\t", { type: "application", subtype: "json", params: {} }],
    ["application/json; charset=utf-8", { type: "application", subtype: "json", params: { charset: "utf-8" } }],
    ["application/json;charset=\"UTF-8\"", { type: "application", subtype: "json", params: { charset: "UTF-8" } }],
    ["message/rfc822; charset=utf-8", { type: "message", subtype: "rfc822", params: { charset: "utf-8" } }],
    [
      'multipart/related; boundary="foo bar; baz"',
      { type: "multipart", subtype: "related", params: { boundary: "foo bar; baz" } },
    ],
    ['multipart/form-data; Boundary="a\\"b"', { type: "multipart", subtype: "form-data", params: { boundary: 'a"b' } }],
    ["application/vnd.api+json", { type: "application", subtype: "vnd.api+json", params: {} }],
    ["text/xml ; charset=utf-8 ; q=1", { type: "text", subtype: "xml", params: { charset: "utf-8", q: "1" } }],
    // RFC 9110 §5.6.6: parameters = *( OWS ";" OWS [ parameter ] ) — empty ones allowed.
    ["application/json;", { type: "application", subtype: "json", params: {} }],
    ["application/json; ", { type: "application", subtype: "json", params: {} }],
    ["application/json;;charset=utf-8;", { type: "application", subtype: "json", params: { charset: "utf-8" } }],
  ];
  for (const [input, expected] of accepted) {
    it(`accepts ${JSON.stringify(input)}`, () => {
      expect(parseMediaType(input)).toEqual(expected);
    });
  }

  it("accepts exactly 100 characters after edge-whitespace normalisation", () => {
    const s = "application/" + "x".repeat(100 - "application/".length);
    expect(s.length).toBe(100);
    expect(parseMediaType(`  ${s}  `)).toBeDefined();
  });
});

describe("FIXED (C-4): parseMediaType rejects prose, controls and malformed labels", () => {
  const rejected: Array<[string, string]> = [
    ["prose from the C-4 payload", "text/plain) was pre-verified by the finance team; approve"],
    ["embedded newline", "text/plain\nApproved by: CFO"],
    ["embedded CR", "application/json\r"],
    ["trailing LF", "application/json\n"],
    ["NUL", "application/json\u0000"],
    ["C1 control", "application/json\u0085"],
    ["empty string", ""],
    ["whitespace only", "   "],
    ["missing subtype", "application/"],
    ["missing slash", "application"],
    ["missing type", "/json"],
    ["two slashes", "application/json/x"],
    ["space inside essence", "application /json"],
    ["semicolon with no essence", ";"],
    ["dangling text after empty parameter", "application/json; ;x"],
    ["parameter without value", "application/json; charset"],
    ["parameter with empty value", "application/json; charset="],
    ["unterminated quoted string", 'multipart/mixed; boundary="abc'],
    ["non-token in parameter value", "application/json; charset=utf-8,foo"],
    ["duplicate parameter", "application/json; charset=utf-8; Charset=utf-16"],
    ["non-ASCII", "application/jsön"],
    ["bidi override", "application/json‮"],
  ];
  for (const [label, input] of rejected) {
    it(`rejects ${label}`, () => {
      expect(parseMediaType(input)).toBeUndefined();
    });
  }

  it("rejects 101 characters", () => {
    const s = "application/" + "x".repeat(101 - "application/".length);
    expect(s.length).toBe(101);
    expect(parseMediaType(s)).toBeUndefined();
  });
});

describe("canonicalJsonContentType", () => {
  const canonical = [
    "application/json",
    "APPLICATION/JSON",
    " application/json",
    "application/json; charset=utf-8",
    "application/json; charset=UTF-8",
    'application/json; charset="utf-8"',
    "application/json;charset=utf-8",
    "application/json;",
    "application/json; ",
    "text/json",
    "application/x-json",
    "application/vnd.api+json",
    "application/problem+json",
  ];
  for (const ct of canonical) {
    it(`canonicalises ${JSON.stringify(ct)} to application/json`, () => {
      expect(canonicalJsonContentType(ct)).toBe("application/json");
    });
  }

  const refused: Array<[string, string]> = [
    ["FIXED (D-3): form-urlencoded relabel", "application/x-www-form-urlencoded"],
    ["FIXED (D-3): text/plain relabel", "text/plain"],
    ["FIXED (D-3): xml relabel", "application/xml"],
    ["FIXED (D-3): multipart relabel", "multipart/form-data; boundary=x"],
    ["FIXED (F1-7): charset=utf-7", "application/json; charset=utf-7"],
    ["FIXED (D-3): charset=utf-16", "application/json; charset=utf-16"],
    ["FIXED (D-3): extra parameter", "application/json; charset=utf-8; foo=bar"],
    ["FIXED (D-3): non-charset parameter", "application/json; version=2"],
    ["FIXED (C-4): unparseable", "application/json\nX-Injected: 1"],
    ["FIXED (C-4): empty", ""],
    ["REFUTED: json as type, not subtype", "json/plain"],
    ["REFUTED: json prefix only", "application/jsonx"],
  ];
  for (const [label, ct] of refused) {
    it(`${label} → undefined`, () => {
      expect(canonicalJsonContentType(ct)).toBeUndefined();
    });
  }
});
