import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";

export interface UnifyOptions {
  title: string;
  version: string;
  serverUrl: string;
}

export interface InputDoc {
  paths: Record<string, unknown>;
  /** `parameters` is inlined into operations by `inlineParameterRefs` before
   *  `unify`; only `schemas` is carried into the merged spec. */
  components?: {
    schemas?: Record<string, unknown>;
    parameters?: Record<string, unknown>;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

export function unify(docs: InputDoc[], opts: UnifyOptions): OpenApiSpec {
  const paths: Record<string, unknown> = {};
  const schemas: Record<string, unknown> = {};

  for (const d of docs) {
    for (const [p, methods] of Object.entries(d.paths ?? {})) {
      if (paths[p] !== undefined) {
        throw new Error(`xero-merge unify: path collision on ${p}`);
      }
      paths[p] = methods;
    }
    for (const [name, schema] of Object.entries(d.components?.schemas ?? {})) {
      if (schemas[name] !== undefined) {
        throw new Error(`xero-merge unify: schema collision on ${name}`);
      }
      schemas[name] = schema;
    }
  }

  return {
    openapi: "3.0.0",
    info: { title: opts.title, version: opts.version },
    servers: [{ url: opts.serverUrl }],
    paths: paths as OpenApiSpec["paths"],
    components: { schemas },
  };
}
