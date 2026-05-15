import { describe, it, expect } from "vitest";
import { discoveryToOpenApi, type DiscoveryDoc } from "../index";

describe("discoveryToOpenApi", () => {
  const sampleDoc: DiscoveryDoc = {
    baseUrl: "https://gmail.googleapis.com/gmail/v1/",
    rootUrl: "https://gmail.googleapis.com/",
    servicePath: "gmail/v1/",
    schemas: {
      Message: { type: "object", properties: { id: { type: "string" } } },
    },
    resources: {
      users: {
        resources: {
          messages: {
            methods: {
              list: {
                id: "gmail.users.messages.list",
                path: "users/{userId}/messages",
                httpMethod: "GET",
                description: "Lists messages",
                parameters: {
                  userId: {
                    type: "string",
                    location: "path",
                    required: true,
                    description: "The user's email",
                  },
                  maxResults: {
                    type: "integer",
                    location: "query",
                    description: "Maximum results",
                  },
                },
                scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
              },
              get: {
                id: "gmail.users.messages.get",
                path: "users/{userId}/messages/{id}",
                httpMethod: "GET",
                parameters: {
                  userId: { type: "string", location: "path", required: true },
                  id: { type: "string", location: "path", required: true },
                },
                response: { $ref: "Message" },
              },
            },
          },
        },
      },
    },
  };

  it("emits openapi 3.0.0", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(out.openapi).toBe("3.0.0");
  });

  it("populates the server URL from the discovery baseUrl", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(out.servers[0]?.url).toBe("https://gmail.googleapis.com/gmail/v1");
  });

  it("emits one path entry per method, with the leading slash", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(Object.keys(out.paths)).toContain("/users/{userId}/messages");
    expect(Object.keys(out.paths)).toContain("/users/{userId}/messages/{id}");
  });

  it("uses the discovery method id as operationId", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(out.paths["/users/{userId}/messages"]?.get?.operationId).toBe(
      "gmail.users.messages.list",
    );
  });

  it("translates path and query parameters", () => {
    const out = discoveryToOpenApi(sampleDoc);
    const params = out.paths["/users/{userId}/messages"]?.get?.parameters;
    expect(params).toContainEqual(
      expect.objectContaining({ name: "userId", in: "path", required: true }),
    );
    expect(params).toContainEqual(
      expect.objectContaining({ name: "maxResults", in: "query" }),
    );
  });

  it("preserves OAuth scopes as x-google-scopes", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(
      out.paths["/users/{userId}/messages"]?.get?.["x-google-scopes"],
    ).toEqual(["https://www.googleapis.com/auth/gmail.readonly"]);
  });

  it("preserves schemas in components", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(out.components.schemas).toHaveProperty("Message");
  });

  it("handles nested resources (users.messages.attachments.get)", () => {
    const nested: DiscoveryDoc = {
      ...sampleDoc,
      resources: {
        users: {
          resources: {
            messages: {
              resources: {
                attachments: {
                  methods: {
                    get: {
                      id: "gmail.users.messages.attachments.get",
                      path: "users/{userId}/messages/{messageId}/attachments/{id}",
                      httpMethod: "GET",
                      parameters: {
                        userId: { type: "string", location: "path", required: true },
                        messageId: { type: "string", location: "path", required: true },
                        id: { type: "string", location: "path", required: true },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    };
    const out = discoveryToOpenApi(nested);
    expect(out.paths["/users/{userId}/messages/{messageId}/attachments/{id}"]).toBeDefined();
  });
});
