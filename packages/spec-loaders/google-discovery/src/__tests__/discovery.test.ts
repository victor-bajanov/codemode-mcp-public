import { describe, it, expect } from "vitest";
import { discoveryToOpenApi, mergeOpenApiSpecs, type DiscoveryDoc } from "../index";

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

  it("populates the server URL with the host origin only", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(out.servers[0]?.url).toBe("https://gmail.googleapis.com");
  });

  it("folds the baseUrl service path into host-root-relative path keys", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(Object.keys(out.paths)).toContain("/gmail/v1/users/{userId}/messages");
    expect(Object.keys(out.paths)).toContain("/gmail/v1/users/{userId}/messages/{id}");
  });

  it("uses the discovery method id as operationId", () => {
    const out = discoveryToOpenApi(sampleDoc);
    expect(out.paths["/gmail/v1/users/{userId}/messages"]?.get?.operationId).toBe(
      "gmail.users.messages.list",
    );
  });

  it("translates path and query parameters", () => {
    const out = discoveryToOpenApi(sampleDoc);
    const params = out.paths["/gmail/v1/users/{userId}/messages"]?.get?.parameters;
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
      out.paths["/gmail/v1/users/{userId}/messages"]?.get?.["x-google-scopes"],
    ).toEqual(["https://www.googleapis.com/auth/gmail.readonly"]);
  });

  it("derives info.title/version from the discovery doc when present", () => {
    const out = discoveryToOpenApi({ ...sampleDoc, title: "Gmail API", version: "v1" });
    expect(out.info.title).toBe("Gmail API");
    expect(out.info.version).toBe("v1");
  });

  it("keeps a Calendar-style service path (different host) host-root-relative", () => {
    const calDoc: DiscoveryDoc = {
      baseUrl: "https://www.googleapis.com/calendar/v3/",
      schemas: { Event: { type: "object" } },
      resources: {
        events: {
          methods: {
            list: {
              id: "calendar.events.list",
              path: "calendars/{calendarId}/events",
              httpMethod: "GET",
            },
          },
        },
      },
    };
    const out = discoveryToOpenApi(calDoc);
    expect(out.servers[0]?.url).toBe("https://www.googleapis.com");
    expect(Object.keys(out.paths)).toContain("/calendar/v3/calendars/{calendarId}/events");
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
    expect(
      out.paths["/gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}"],
    ).toBeDefined();
  });
});

describe("mergeOpenApiSpecs", () => {
  const gmail = discoveryToOpenApi({
    baseUrl: "https://gmail.googleapis.com/",
    title: "Gmail API",
    schemas: { Message: { type: "object" } },
    resources: {
      users: {
        methods: {
          getProfile: { id: "gmail.users.getProfile", path: "gmail/v1/users/{userId}/profile", httpMethod: "GET" },
        },
      },
    },
  });
  const calendar = discoveryToOpenApi({
    baseUrl: "https://www.googleapis.com/calendar/v3/",
    title: "Calendar API",
    schemas: { Event: { type: "object" } },
    resources: {
      events: {
        methods: {
          list: { id: "calendar.events.list", path: "calendars/{calendarId}/events", httpMethod: "GET" },
        },
      },
    },
  });

  it("unions paths and schemas across specs", () => {
    const out = mergeOpenApiSpecs([gmail, calendar], {
      title: "Google",
      serverUrl: "https://www.googleapis.com",
    });
    expect(Object.keys(out.paths)).toContain("/gmail/v1/users/{userId}/profile");
    expect(Object.keys(out.paths)).toContain("/calendar/v3/calendars/{calendarId}/events");
    expect(out.components.schemas).toHaveProperty("Message");
    expect(out.components.schemas).toHaveProperty("Event");
    expect(out.info.title).toBe("Google");
    expect(out.servers[0]?.url).toBe("https://www.googleapis.com");
  });

  it("throws on a duplicate schema name (guards discovery drift)", () => {
    const collides = discoveryToOpenApi({
      baseUrl: "https://www.googleapis.com/other/v1/",
      schemas: { Message: { type: "object", properties: { different: { type: "string" } } } },
      resources: {},
    });
    expect(() => mergeOpenApiSpecs([gmail, collides])).toThrow(/duplicate schema name "Message"/);
  });

  it("throws on a duplicate path key", () => {
    expect(() => mergeOpenApiSpecs([gmail, gmail])).toThrow(/duplicate path/);
  });
});
