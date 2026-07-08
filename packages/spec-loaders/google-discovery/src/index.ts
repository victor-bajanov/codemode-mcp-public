export interface DiscoveryDoc {
  baseUrl: string;
  rootUrl?: string;
  servicePath?: string;
  title?: string;
  version?: string;
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
  info: { title: string; version: string; description?: string };
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
  // Host-root-relative paths + host-only server, so multiple Google APIs can be
  // merged under one apiBaseUrl (the shared www.googleapis.com origin) without
  // tripping the request-handler's origin-invariance guard. The service-path
  // portion of baseUrl (e.g. "/calendar/v3") is folded into each path.
  //  - Gmail:    baseUrl https://gmail.googleapis.com/ → origin only, paths
  //              already carry "gmail/v1/..." → "/gmail/v1/...".
  //  - Calendar: baseUrl https://www.googleapis.com/calendar/v3/ → prefix
  //              "/calendar/v3", method path "calendars/{calendarId}" →
  //              "/calendar/v3/calendars/{calendarId}".
  const baseUrlObj = new URL(doc.baseUrl);
  const origin = baseUrlObj.origin;
  const servicePrefix = baseUrlObj.pathname.replace(/\/+$/, "");
  const paths: OpenApiSpec["paths"] = {};

  const allMethods: DiscoveryMethod[] = [];
  if (doc.methods) allMethods.push(...Object.values(doc.methods));
  for (const r of Object.values(doc.resources ?? {})) allMethods.push(...walkMethods(r));

  for (const m of allMethods) {
    const path = servicePrefix + "/" + m.path.replace(/^\//, "");
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
    info: {
      title: doc.title ?? "Google API (normalised from Discovery)",
      version: doc.version ?? "v1",
    },
    servers: [{ url: origin }],
    paths,
    components: { schemas: doc.schemas as Record<string, unknown> },
  };
}

/**
 * Merge multiple normalised OpenAPI specs into one bundled spec. Used to expose
 * several Google APIs (Gmail + Calendar) through a single provider definition.
 *
 * - `paths` are unioned. Path keys are host-root-relative and namespaced per API
 *   (`/gmail/v1/...` vs `/calendar/v3/...`), so collisions are not expected; a
 *   colliding path key throws.
 * - `components.schemas` are unioned. A duplicate schema name throws, so future
 *   discovery-doc drift cannot silently shadow a schema referenced by `$ref`.
 *
 * The merged `servers`/`info` are taken from `overrides` (the provider's
 * apiBaseUrl is the runtime source of truth; servers here are cosmetic).
 */
export function mergeOpenApiSpecs(
  specs: OpenApiSpec[],
  overrides?: { title?: string; version?: string; description?: string; serverUrl?: string },
): OpenApiSpec {
  if (specs.length === 0) throw new Error("mergeOpenApiSpecs: no specs provided");

  const paths: OpenApiSpec["paths"] = {};
  const schemas: Record<string, unknown> = {};

  for (const spec of specs) {
    for (const [pathKey, methods] of Object.entries(spec.paths)) {
      if (paths[pathKey]) {
        throw new Error(`mergeOpenApiSpecs: duplicate path "${pathKey}"`);
      }
      paths[pathKey] = methods;
    }
    for (const [name, schema] of Object.entries(spec.components.schemas)) {
      if (name in schemas) {
        throw new Error(`mergeOpenApiSpecs: duplicate schema name "${name}"`);
      }
      schemas[name] = schema;
    }
  }

  const description = overrides?.description ?? specs[0]!.info.description;

  return {
    openapi: "3.0.0",
    info: {
      title: overrides?.title ?? specs[0]!.info.title,
      version: overrides?.version ?? specs[0]!.info.version,
      ...(description ? { description } : {}),
    },
    servers: [{ url: overrides?.serverUrl ?? specs[0]!.servers[0]!.url }],
    paths,
    components: { schemas },
  };
}
