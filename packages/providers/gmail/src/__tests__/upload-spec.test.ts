// The three hand-written Gmail media-upload operations (issue #59, D12) are
// merged into the provider spec from gmail-upload.spec.json. Pins the exact
// paths, methods, scopes, the required `uploadType=media` query parameter and
// the `message/rfc822` request body, so the scaffold resolves a composed
// media send to the right operation and the client learns the shape via
// `search`.

import { describe, it, expect } from "vitest";
import { gmailProvider } from "../index";

interface Op {
  operationId?: string;
  parameters?: Array<{ name: string; in: string; required?: boolean; schema?: { type?: string; enum?: string[] } }>;
  requestBody?: { required?: boolean; content?: Record<string, unknown> };
  "x-google-scopes"?: string[];
}

const paths = (gmailProvider.spec as unknown as { paths: Record<string, Record<string, Op>> }).paths;

const CASES = [
  {
    id: "gmail.users.messages.send.media",
    path: "/upload/gmail/v1/users/{userId}/messages/send",
    method: "post",
    scope: "https://www.googleapis.com/auth/gmail.send",
    pathParams: ["userId"],
  },
  {
    id: "gmail.users.drafts.create.media",
    path: "/upload/gmail/v1/users/{userId}/drafts",
    method: "post",
    scope: "https://www.googleapis.com/auth/gmail.compose",
    pathParams: ["userId"],
  },
  {
    id: "gmail.users.drafts.update.media",
    path: "/upload/gmail/v1/users/{userId}/drafts/{id}",
    method: "put",
    scope: "https://www.googleapis.com/auth/gmail.compose",
    pathParams: ["userId", "id"],
  },
] as const;

describe("Gmail media-upload operations in the merged spec", () => {
  for (const c of CASES) {
    describe(c.id, () => {
      const op = paths[c.path]?.[c.method];

      it(`is registered at ${c.method.toUpperCase()} ${c.path}`, () => {
        expect(op?.operationId).toBe(c.id);
      });

      it(`carries the ${c.scope.split("/").pop()} scope (and the full mail scope the provider grants)`, () => {
        expect(op?.["x-google-scopes"]).toContain(c.scope);
        expect(op?.["x-google-scopes"]).toContain("https://mail.google.com/");
      });

      it("requires uploadType as a query enum of exactly [\"media\"]", () => {
        const p = op?.parameters?.find((x) => x.name === "uploadType");
        expect(p).toMatchObject({ in: "query", required: true, schema: { type: "string", enum: ["media"] } });
      });

      it("declares its path parameters", () => {
        const names = (op?.parameters ?? []).filter((x) => x.in === "path").map((x) => x.name).sort();
        expect(names).toEqual([...c.pathParams].sort());
      });

      it("takes a required message/rfc822 request body and nothing else", () => {
        expect(op?.requestBody?.required).toBe(true);
        expect(Object.keys(op?.requestBody?.content ?? {})).toEqual(["message/rfc822"]);
      });
    });
  }

  it("leaves the JSON operations on their original paths", () => {
    expect(paths["/gmail/v1/users/{userId}/messages/send"]?.["post"]?.operationId).toBe("gmail.users.messages.send");
    expect(paths["/gmail/v1/users/{userId}/drafts"]?.["post"]?.operationId).toBe("gmail.users.drafts.create");
    expect(paths["/gmail/v1/users/{userId}/drafts/{id}"]?.["put"]?.operationId).toBe("gmail.users.drafts.update");
  });

  it("registers no other /upload/ path (import/insert media stay out of scope)", () => {
    const uploads = Object.keys(paths).filter((p) => p.startsWith("/upload/")).sort();
    expect(uploads).toEqual(CASES.map((c) => c.path).sort());
  });
});
