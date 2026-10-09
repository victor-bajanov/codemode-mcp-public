import { describe, it, expect } from "vitest";
import {
  findShadowConflicts,
  hasUnsafePathSegment,
  isUnsafePathSegment,
  matchOperation,
  resolveOperation,
} from "../path-matcher";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";

const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "test", version: "0" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/users/{userId}/messages": {
      get: { operationId: "gmail.users.messages.list", responses: { "200": { description: "ok" } } },
      post: { operationId: "gmail.users.messages.send", responses: { "200": { description: "ok" } } },
    },
    "/users/{userId}/messages/{id}": {
      get: { operationId: "gmail.users.messages.get", responses: { "200": { description: "ok" } } },
      delete: { operationId: "gmail.users.messages.delete", responses: { "200": { description: "ok" } } },
    },
    "/users/{userId}/settings/delegates": {
      post: { operationId: "gmail.users.settings.delegates.create", responses: { "200": { description: "ok" } } },
    },
  },
  components: { schemas: {} },
};

describe("resolveOperation", () => {
  it("resolves a simple GET with one path param", () => {
    const op = resolveOperation(SPEC, "GET", "/users/me/messages");
    expect(op?.operationId).toBe("gmail.users.messages.list");
  });

  it("resolves POST on the same template separately from GET", () => {
    const op = resolveOperation(SPEC, "POST", "/users/me/messages");
    expect(op?.operationId).toBe("gmail.users.messages.send");
  });

  it("resolves multi-param paths", () => {
    const op = resolveOperation(SPEC, "GET", "/users/me/messages/abc123");
    expect(op?.operationId).toBe("gmail.users.messages.get");
  });

  it("returns null for unknown path", () => {
    expect(resolveOperation(SPEC, "GET", "/unknown")).toBeNull();
  });

  it("returns null for known path with unknown method", () => {
    expect(resolveOperation(SPEC, "PATCH", "/users/me/messages")).toBeNull();
  });

  it("rejects path with extra segments — adversarial", () => {
    expect(resolveOperation(SPEC, "GET", "/users/me/messages/abc/extra")).toBeNull();
  });

  it("rejects empty path segments — adversarial", () => {
    expect(resolveOperation(SPEC, "GET", "/users//messages")).toBeNull();
  });

  it("does not match across templates with identical literal segments — adversarial", () => {
    expect(resolveOperation(SPEC, "POST", "/users/me/settings/delegates")?.operationId).toBe(
      "gmail.users.settings.delegates.create",
    );
    // An encoded "/" no longer rides through a param slot: it decodes to a
    // segment separator, so the whole path is refused (F-6).
    expect(resolveOperation(SPEC, "POST", "/users/settings%2Fdelegates/messages")).toBeNull();
  });

  it("treats trailing slash as a different path — adversarial", () => {
    expect(resolveOperation(SPEC, "GET", "/users/me/messages/")).toBeNull();
  });

  it("is case-sensitive on method", () => {
    expect(resolveOperation(SPEC, "get", "/users/me/messages")).toBeNull();
  });
});

describe("isUnsafePathSegment / hasUnsafePathSegment (F-1, F-6)", () => {
  const UNSAFE = [
    "..", ".", "%2e%2E", ".%2e", "%2e.", "...", "%2e%2e%2e",
    "a\\b", "a?b", "a#b", "?", "#",
    "%2F", "a%2fb", "%5c", "a%5Cb",
    "a%00b", "a\tb", "a\nb", "a\rb", "a\x7fb", "%7F", "%09",
    "%", "%zz", "a%2", "%E0%A4%A",
    // Lone UTF-16 surrogates: encodeURIComponent would throw URIError.
    "a\uD800b", "\uDC00", "x\uDBFF",
  ];
  for (const seg of UNSAFE) {
    it(`refuses ${JSON.stringify(seg)}`, () => {
      expect(isUnsafePathSegment(seg)).toBe(true);
      expect(hasUnsafePathSegment(`/users/${seg}/messages`)).toBe(true);
      expect(resolveOperation(SPEC, "GET", `/users/me/messages/${seg}`)).toBeNull();
      expect(matchOperation(SPEC, "GET", `/users/${seg}/messages`)).toBeNull();
    });
  }

  it("accepts ordinary and legitimately encoded segments", () => {
    for (const seg of ["me", "abc123", "user%40example.com", "user@example.com", "my%20file.pdf", "my file.pdf", "a+b", "a.b", ".hidden", "100%25", "%C3%A9t%C3%A9", "été", "\uD83D\uDE00"]) {
      expect(isUnsafePathSegment(seg), seg).toBe(false);
    }
    expect(hasUnsafePathSegment("/users/me/messages/abc")).toBe(false);
  });

  // Regression: an encoded `?` or `#` is re-encoded in the wire path, so it can
  // never start a query or fragment. Refusing it locked out Calendar ids such
  // as `en.australian#holiday@group.v.calendar.google.com` and file names such
  // as `Receipt #123.pdf`.
  it("accepts encoded ? and # inside a value and re-encodes them on the wire", () => {
    for (const seg of ["%3f", "%3F", "%23", "a%23b", "Receipt%20%23123.pdf", "what%3F.pdf"]) {
      expect(isUnsafePathSegment(seg), seg).toBe(false);
    }
    const cal = matchOperation(SPEC, "GET", "/users/en.australian%23holiday%40group.v.calendar.google.com/messages");
    expect(cal!.params.userId).toBe("en.australian#holiday@group.v.calendar.google.com");
    expect(cal!.wirePath).toBe("/users/en.australian%23holiday%40group.v.calendar.google.com/messages");
    const file = matchOperation(SPEC, "GET", `/users/me/messages/${encodeURIComponent("Receipt #1?.pdf")}`);
    expect(file!.wirePath).toBe("/users/me/messages/Receipt%20%231%3F.pdf");
    // The wire path resolves to the same operation (the handler's re-resolve check).
    expect(matchOperation(SPEC, "GET", file!.wirePath)!.op).toBe(file!.op);
  });
});

describe("matchOperation", () => {
  it("returns the template, decoded params and an encoded wire path", () => {
    const m = matchOperation(SPEC, "GET", "/users/user%40example.com/messages/my%20file+v2");
    expect(m).not.toBeNull();
    expect(m!.op.operationId).toBe("gmail.users.messages.get");
    expect(m!.template).toBe("/users/{userId}/messages/{id}");
    expect(m!.params).toEqual({ userId: "user@example.com", id: "my file+v2" });
    expect(m!.wirePath).toBe("/users/user%40example.com/messages/my%20file%2Bv2");
  });

  it("encodes raw (unencoded) values the same way as their encoded spelling", () => {
    const raw = matchOperation(SPEC, "GET", "/users/user@example.com/messages/my file.pdf");
    const enc = matchOperation(SPEC, "GET", "/users/user%40example.com/messages/my%20file.pdf");
    expect(raw!.wirePath).toBe("/users/user%40example.com/messages/my%20file.pdf");
    expect(enc!.wirePath).toBe(raw!.wirePath);
  });

  it("percent-encodes non-ASCII as UTF-8 and keeps a literal % as %25", () => {
    const m = matchOperation(SPEC, "GET", "/users/me/messages/%C3%A9t%C3%A9-100%25");
    expect(m!.params.id).toBe("été-100%");
    expect(m!.wirePath).toBe("/users/me/messages/%C3%A9t%C3%A9-100%25");
  });

  it("keeps literal segments verbatim", () => {
    const m = matchOperation(SPEC, "POST", "/users/me/settings/delegates");
    expect(m!.wirePath).toBe("/users/me/settings/delegates");
    expect(m!.params).toEqual({ userId: "me" });
  });

  it("returns null for non-string method or path", () => {
    expect(matchOperation(SPEC, 42 as unknown as string, "/users/me/messages")).toBeNull();
    expect(matchOperation(SPEC, "GET", { toString: () => "/users/me/messages" } as unknown as string)).toBeNull();
    expect(resolveOperation(SPEC, undefined as unknown as string, "/users/me/messages")).toBeNull();
  });

  it("resolveOperation agrees with matchOperation", () => {
    const m = matchOperation(SPEC, "DELETE", "/users/me/messages/abc");
    expect(resolveOperation(SPEC, "DELETE", "/users/me/messages/abc")).toBe(m!.op);
  });
});

describe("findShadowConflicts", () => {
  const SHADOW_SPEC: OpenApiSpec = {
    openapi: "3.0.0",
    info: { title: "t", version: "0" },
    servers: [{ url: "https://api.example.com" }],
    paths: {
      "/reports/{id}": { get: { operationId: "getReport", responses: {} } },
      "/reports/Summary": { get: { operationId: "getSummary", responses: {} } },
      "/items/{id}": { delete: { operationId: "deleteItem", responses: {} } },
      "/items/archive": { delete: { operationId: "deleteArchive", responses: {} } },
      "/other/{id}": { post: { operationId: "postOther", responses: {} } },
    },
    components: { schemas: {} },
  } as unknown as OpenApiSpec;

  it("ignores overlaps with the same treatment and reports ones that differ", () => {
    const conflicts = findShadowConflicts(SHADOW_SPEC, {
      getReport: { decision: "allow" },
      getSummary: { decision: "allow" },
      deleteItem: { decision: "allow" },
      deleteArchive: { decision: "elicit" },
      postOther: { decision: "deny" },
    });
    expect(conflicts).toEqual([
      {
        method: "DELETE",
        first: { template: "/items/{id}", operationId: "deleteItem" },
        second: { template: "/items/archive", operationId: "deleteArchive" },
      },
    ]);
  });

  it("treats a different inspector as different treatment", () => {
    const conflicts = findShadowConflicts(SHADOW_SPEC, {
      getReport: { decision: "allow" },
      getSummary: { decision: "allow", inspect: () => ({ decision: "deny" }) },
    });
    expect(conflicts.map((c) => c.second.operationId)).toContain("getSummary");
  });
});
