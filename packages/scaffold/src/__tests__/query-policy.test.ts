// packages/scaffold/src/__tests__/query-policy.test.ts
//
// D-2 — query parameter names were never checked. `buildUpstreamUrl` copied
// every key of the sandbox-supplied `query` onto the wire, so an allowed read
// could carry `$httpMethod=DELETE` (Google's query-form method override),
// `$httpHeaders`, a credential parameter (`access_token`, `key`) or any
// parameter the operation never declared, and the audit line recorded none of
// it.
//
// Attacker: sandbox code (prompt-injected model). Precondition: an `allow` (or
// approved) operation. Payload: extra query keys. Control: `checkQuery` —
// values must be primitives; a hard deny-list (`$`-prefixed, credential and
// method-override names, case-insensitive) wins even over a declaration; every
// other name must be declared by the matched operation (`in: "query"`, a
// `$ref` resolved against `components.parameters`) or be one of the provider's
// `standardQueryParams`. Pre-fix there was no check at all.

import { describe, it, expect } from "vitest";
import type { OpenApiOperation, OpenApiSpec } from "@local/spec-loaders-google-discovery";
import { auditQueryKeys, checkQuery, declaredQueryNames } from "../query-policy";

function op(parameters: unknown[]): OpenApiOperation {
  return {
    operationId: "thing.get",
    responses: { "200": { description: "ok" } },
    parameters: parameters as NonNullable<OpenApiOperation["parameters"]>,
  };
}

function spec(componentParameters?: Record<string, unknown>): OpenApiSpec {
  const components: Record<string, unknown> = { schemas: {} };
  if (componentParameters) components.parameters = componentParameters;
  return {
    openapi: "3.0.0",
    info: { title: "t", version: "1" },
    servers: [{ url: "https://api.example.com" }],
    paths: {},
    components: components as OpenApiSpec["components"],
  };
}

const GET = op([
  { name: "id", in: "path", required: true, schema: { type: "string" } },
  { name: "format", in: "query", schema: { type: "string" } },
  { name: "maxResults", in: "query", schema: { type: "integer" } },
  { name: "xero-tenant-id", in: "header", schema: { type: "string" } },
]);

describe("declaredQueryNames", () => {
  it("returns only in:query names, sorted", () => {
    expect(declaredQueryNames(GET, spec())).toEqual(["format", "maxResults"]);
  });

  it("resolves a $ref against spec.components.parameters", () => {
    const o = op([
      { $ref: "#/components/parameters/unitdp" },
      { $ref: "#/components/parameters/requiredHeader" },
    ]);
    const s = spec({
      unitdp: { name: "unitdp", in: "query", schema: { type: "integer" } },
      requiredHeader: { name: "xero-tenant-id", in: "header", schema: { type: "string" } },
    });
    expect(declaredQueryNames(o, s)).toEqual(["unitdp"]);
  });

  it("an unresolvable $ref declares nothing", () => {
    const o = op([
      { $ref: "#/components/parameters/missing" },
      { $ref: "#/components/parameters/__proto__" },
      { $ref: "#/components/schemas/unitdp" },
    ]);
    expect(declaredQueryNames(o, spec({ unitdp: { name: "unitdp", in: "query" } }))).toEqual([]);
    expect(declaredQueryNames(o, spec())).toEqual([]);
  });

  it("an operation with no parameters declares nothing", () => {
    expect(declaredQueryNames(op([]), spec())).toEqual([]);
    const bare: OpenApiOperation = { operationId: "x", responses: {} };
    expect(declaredQueryNames(bare, spec())).toEqual([]);
  });
});

describe("checkQuery", () => {
  it("REFUTED: no query or an empty query is allowed with no keys", () => {
    expect(checkQuery(GET, spec(), undefined, undefined)).toEqual({ ok: true, keys: [] });
    expect(checkQuery(GET, spec(), {}, [])).toEqual({ ok: true, keys: [] });
  });

  it("REFUTED: declared names pass and keys come back sorted", () => {
    expect(checkQuery(GET, spec(), { maxResults: 5, format: "full" }, [])).toEqual({
      ok: true,
      keys: ["format", "maxResults"],
    });
  });

  it("REFUTED: undefined values are ignored, even for undeclared or forbidden names", () => {
    expect(
      checkQuery(GET, spec(), { format: "full", nope: undefined, $httpMethod: undefined }, []),
    ).toEqual({ ok: true, keys: ["format"] });
  });

  it("FIXED (D-2): an undeclared name is refused with the accepted names listed", () => {
    const r = checkQuery(GET, spec(), { format: "full", notAParameterOfThisOperation: "1" }, []);
    expect(r).toMatchObject({ ok: false, reason: "undeclared-query-param" });
    if (r.ok) throw new Error("unreachable");
    expect(r.message).toBe(
      'Operation thing.get does not accept query parameter "notAParameterOfThisOperation"; it accepts: format, maxResults',
    );
    expect(r.keys).toEqual(["format", "notAParameterOfThisOperation"]);
  });

  it("FIXED (D-2): name comparison is case-sensitive", () => {
    const r = checkQuery(GET, spec(), { Format: "full" }, []);
    expect(r).toMatchObject({ ok: false, reason: "undeclared-query-param" });
  });

  it("FIXED (D-2): a header or path parameter does not declare a query name", () => {
    expect(checkQuery(GET, spec(), { id: "x" }, [])).toMatchObject({
      ok: false,
      reason: "undeclared-query-param",
    });
    expect(checkQuery(GET, spec(), { "xero-tenant-id": "x" }, [])).toMatchObject({
      ok: false,
      reason: "undeclared-query-param",
    });
  });

  it("FIXED (D-2): standardQueryParams are accepted on every operation", () => {
    const r = checkQuery(GET, spec(), { fields: "id", prettyPrint: false }, [
      "fields",
      "prettyPrint",
      "quotaUser",
      "upload_protocol",
    ]);
    expect(r).toEqual({ ok: true, keys: ["fields", "prettyPrint"] });
    expect(checkQuery(GET, spec(), { fields: "id" }, [])).toMatchObject({
      ok: false,
      reason: "undeclared-query-param",
    });
  });

  it("FIXED (D-2): $ref-declared names pass; unresolvable refs do not declare", () => {
    const o = op([
      { $ref: "#/components/parameters/unitdp" },
      { $ref: "#/components/parameters/summarizeErrors" },
    ]);
    const s = spec({ unitdp: { name: "unitdp", in: "query", schema: { type: "integer" } } });
    expect(checkQuery(o, s, { unitdp: 4 }, [])).toEqual({ ok: true, keys: ["unitdp"] });
    expect(checkQuery(o, s, { summarizeErrors: true }, [])).toMatchObject({
      ok: false,
      reason: "undeclared-query-param",
    });
  });

  it.each([
    ["$httpMethod", "DELETE"],
    ["$httpHeaders", "X-Foo: bar"],
    ["$anything", "1"],
    ["access_token", "ya29.x"],
    ["oauth_token", "x"],
    ["key", "AIza"],
    ["api_key", "x"],
    ["apikey", "x"],
    ["token", "x"],
    ["bearer", "x"],
    ["authorization", "x"],
    ["_method", "DELETE"],
    ["method", "DELETE"],
    ["httpmethod", "DELETE"],
    ["x-http-method-override", "DELETE"],
    ["Access_Token", "x"],
    ["KEY", "x"],
    ["X-HTTP-Method-Override", "DELETE"],
    ["HttpMethod", "DELETE"],
  ])("FIXED (D-2): forbidden name %s is refused", (name, value) => {
    const r = checkQuery(GET, spec(), { [name]: value }, []);
    expect(r).toMatchObject({ ok: false, reason: "forbidden-query-param", keys: [name] });
  });

  it("FIXED (D-2): the deny-list wins even over a declaration or a standard param", () => {
    const o = op([
      { name: "key", in: "query", schema: { type: "string" } },
      { name: "$httpMethod", in: "query", schema: { type: "string" } },
      { name: "method", in: "query", schema: { type: "string" } },
    ]);
    for (const name of ["key", "$httpMethod", "method"]) {
      expect(checkQuery(o, spec(), { [name]: "x" }, [name])).toMatchObject({
        ok: false,
        reason: "forbidden-query-param",
      });
    }
    // Forbidden names are never advertised as accepted.
    const r = checkQuery(o, spec(), { nope: "1" }, ["access_token"]);
    if (r.ok) throw new Error("unreachable");
    expect(r.message).toBe(
      'Operation thing.get does not accept query parameter "nope"; it accepts no query parameters',
    );
  });

  it("FIXED (D-2): a forbidden name is reported ahead of an undeclared one", () => {
    const r = checkQuery(GET, spec(), { aaa: "1", $httpMethod: "DELETE" }, []);
    expect(r).toMatchObject({ ok: false, reason: "forbidden-query-param" });
  });

  it.each([
    ["object", { a: 1 }],
    ["array", ["a", "b"]],
    ["null", null],
    ["bigint", 1n],
    ["function", () => 1],
    ["symbol", Symbol("s")],
  ])("FIXED (D-2): a non-primitive value (%s) is refused as malformed", (_label, value) => {
    const r = checkQuery(GET, spec(), { format: value }, []);
    expect(r).toMatchObject({
      ok: false,
      category: "malformed",
      reason: "query-value-not-primitive",
      keys: ["format"],
    });
  });

  describe("comma-separated list parameters (type array, explode: false)", () => {
  const LISTS = op([
    { name: "IDs", in: "query", style: "form", explode: false, schema: { type: "array", items: { type: "string" } } },
    { name: "Statuses", in: "query", explode: false, schema: { type: "array", items: { type: "string" } } },
    { $ref: "#/components/parameters/Refs" },
    // explode defaults to true for form style: repeated keys, which this
    // server cannot send, so arrays stay refused.
    { name: "ObjectIds", in: "query", schema: { type: "array", items: { type: "string" } } },
    { name: "Spaced", in: "query", style: "spaceDelimited", explode: false, schema: { type: "array" } },
    { name: "single", in: "query", schema: { type: "string" } },
  ]);
  const S = spec({ Refs: { name: "References", in: "query", explode: false, schema: { type: "array" } } });

  it("accepts an array of primitives for a declared form/explode:false array (inline, default style, or $ref)", () => {
    expect(checkQuery(LISTS, S, { IDs: ["a", "b"], Statuses: ["DRAFT"], References: [1, true, "x"] }, [])).toEqual({
      ok: true,
      keys: ["IDs", "References", "Statuses"],
    });
  });

  it.each([
    ["nested array", [["a"], "b"]],
    ["object element", [{ a: 1 }]],
    ["null element", [null]],
    ["undefined element", [undefined]],
  ])("refuses a list whose elements are not primitive (%s)", (_label, value) => {
    const r = checkQuery(LISTS, S, { IDs: value }, []);
    expect(r).toMatchObject({ ok: false, category: "malformed", reason: "query-value-not-primitive", keys: ["IDs"] });
    if (r.ok) throw new Error("unreachable");
    expect(r.message).toBe(
      'Operation thing.get: query parameter "IDs" is a comma-separated list; its elements must be strings, numbers or booleans',
    );
  });

  it.each([["ObjectIds"], ["Spaced"], ["single"]])(
    "still refuses an array for %s (not a form/explode:false array) and says how to pass it",
    (name) => {
      const r = checkQuery(LISTS, S, { [name]: ["a", "b"] }, []);
      expect(r).toMatchObject({ ok: false, reason: "query-value-not-primitive" });
      if (r.ok) throw new Error("unreachable");
      expect(r.message).toBe(
        `Operation thing.get: query parameter "${name}" must be a string, number or boolean; ` +
          "this operation does not declare it as a comma-separated list, so pass one value per request",
      );
    },
  );

  it("an array for an undeclared or standard name is refused", () => {
    expect(checkQuery(LISTS, S, { fields: ["a"] }, ["fields"])).toMatchObject({ ok: false, reason: "query-value-not-primitive" });
    expect(checkQuery(LISTS, S, { nope: ["a"] }, [])).toMatchObject({ ok: false, reason: "query-value-not-primitive" });
  });
});

  it("FIXED (D-2): messages carry names only, never values", () => {
    const secret = "SECRET-VALUE-123";
    for (const q of [{ $httpMethod: secret }, { nope: secret }, { format: { secret } }]) {
      const r = checkQuery(GET, spec(), q as Record<string, unknown>, []);
      if (r.ok) throw new Error("unreachable");
      expect(r.message).not.toContain(secret);
    }
  });

  it("REFUTED: inherited Object.prototype names are not treated as declared", () => {
    expect(checkQuery(GET, spec(), { toString: "x" }, [])).toMatchObject({
      ok: false,
      reason: "undeclared-query-param",
    });
    expect(checkQuery(GET, spec(), { constructor: "x" }, [])).toMatchObject({
      ok: false,
      reason: "undeclared-query-param",
    });
  });
});

describe("auditQueryKeys (bounded audit view of the key set)", () => {
  it("is empty for no keys", () => {
    expect(auditQueryKeys([])).toEqual({});
  });

  it("keeps a short set whole and reports the count", () => {
    expect(auditQueryKeys(["a", "b"])).toEqual({ queryKeys: ["a", "b"], queryKeyCount: 2 });
  });

  it("caps at 32 names, each at 64 code points with a visible ellipsis; the count stays true", () => {
    const keys = Array.from({ length: 40 }, (_, i) => `n${String(i).padStart(2, "0")}`);
    keys.push("😀".repeat(70));
    const out = auditQueryKeys(keys);
    expect(out.queryKeyCount).toBe(41);
    expect(out.queryKeys).toHaveLength(32);
    expect(out.queryKeys![31]).toBe("n31");
    expect(auditQueryKeys(["😀".repeat(70)]).queryKeys).toEqual(["😀".repeat(63) + "…"]);
    expect(auditQueryKeys(["a".repeat(64)]).queryKeys).toEqual(["a".repeat(64)]);
  });
});
