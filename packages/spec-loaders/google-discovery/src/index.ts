export interface DiscoveryDoc {
  baseUrl: string;
  rootUrl?: string;
  servicePath?: string;
  schemas: Record<string, unknown>;
  resources?: Record<string, DiscoveryResource>;
  methods?: Record<string, DiscoveryMethod>;
}

export interface DiscoveryResource {
  methods?: Record<string, DiscoveryMethod>;
  resources?: Record<string, DiscoveryResource>;
}

export interface DiscoveryMethod {
  id: string;
  path: string;
  httpMethod: string;
  description?: string;
  parameters?: Record<string, DiscoveryParam>;
  parameterOrder?: string[];
  request?: { $ref: string };
  response?: { $ref: string };
  scopes?: string[];
}

export interface DiscoveryParam {
  type: string;
  description?: string;
  required?: boolean;
  location: "query" | "path";
}

export interface OpenApiSpec {
  openapi: "3.0.0";
  info: { title: string; version: string };
  servers: Array<{ url: string }>;
  paths: Record<string, Record<string, OpenApiOperation>>;
  components: { schemas: Record<string, unknown> };
}

export interface OpenApiOperation {
  operationId: string;
  summary?: string;
  description?: string;
  parameters?: Array<{
    name: string;
    in: "path" | "query";
    required?: boolean;
    schema: { type: string };
    description?: string;
  }>;
  requestBody?: {
    required?: boolean;
    content: Record<string, { schema: unknown }>;
  };
  responses: Record<string, { description: string; content?: Record<string, { schema: unknown }> }>;
  "x-google-scopes"?: string[];
}

function* walkMethods(
  resource: DiscoveryResource,
): Generator<DiscoveryMethod, void, unknown> {
  for (const m of Object.values(resource.methods ?? {})) yield m;
  for (const r of Object.values(resource.resources ?? {})) yield* walkMethods(r);
}

export function discoveryToOpenApi(doc: DiscoveryDoc): OpenApiSpec {
  const baseUrl = doc.baseUrl.replace(/\/$/, "");
  const paths: OpenApiSpec["paths"] = {};

  const allMethods: DiscoveryMethod[] = [];
  if (doc.methods) allMethods.push(...Object.values(doc.methods));
  for (const r of Object.values(doc.resources ?? {})) allMethods.push(...walkMethods(r));

  for (const m of allMethods) {
    const path = "/" + m.path.replace(/^\//, "");
    const method = m.httpMethod.toLowerCase();
    const op: OpenApiOperation = {
      operationId: m.id,
      ...(m.description ? { description: m.description } : {}),
      parameters: Object.entries(m.parameters ?? {}).map(([name, p]) => ({
        name,
        in: p.location,
        ...(p.required ? { required: true } : {}),
        schema: { type: p.type },
        ...(p.description ? { description: p.description } : {}),
      })),
      responses: {
        "200": {
          description: "OK",
          ...(m.response
            ? {
                content: {
                  "application/json": {
                    schema: { $ref: `#/components/schemas/${m.response.$ref}` },
                  },
                },
              }
            : {}),
        },
      },
      ...(m.scopes ? { "x-google-scopes": m.scopes } : {}),
    };
    if (m.request) {
      op.requestBody = {
        required: true,
        content: {
          "application/json": {
            schema: { $ref: `#/components/schemas/${m.request.$ref}` },
          },
        },
      };
    }
    if (!paths[path]) paths[path] = {};
    paths[path][method] = op;
  }

  return {
    openapi: "3.0.0",
    info: { title: "Gmail (normalised from Discovery)", version: "v1" },
    servers: [{ url: baseUrl }],
    paths,
    components: { schemas: doc.schemas as Record<string, unknown> },
  };
}
