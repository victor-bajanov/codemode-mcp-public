import { describe, it, expect } from "vitest";
import { resolveOperation } from "../path-matcher";
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
    expect(resolveOperation(SPEC, "POST", "/users/settings%2Fdelegates/messages")).not.toBe(null);
  });

  it("treats trailing slash as a different path — adversarial", () => {
    expect(resolveOperation(SPEC, "GET", "/users/me/messages/")).toBeNull();
  });

  it("is case-sensitive on method", () => {
    expect(resolveOperation(SPEC, "get", "/users/me/messages")).toBeNull();
  });
});
