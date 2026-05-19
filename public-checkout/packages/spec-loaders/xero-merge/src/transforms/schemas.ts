// packages/spec-loaders/xero-merge/src/transforms/schemas.ts

export interface PartialOpenApi {
  paths: Record<string, unknown>;
  components?: {
    schemas?: Record<string, unknown>;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

const SCHEMA_REF_RE = /^#\/components\/schemas\/([A-Za-z0-9_\-.]+)$/;

function rewriteRefsDeep(value: unknown, rename: (oldName: string) => string): unknown {
  if (Array.isArray(value)) {
    return value.map((v) => rewriteRefsDeep(v, rename));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === "$ref" && typeof v === "string") {
        const m = SCHEMA_REF_RE.exec(v);
        if (m) {
          out[k] = `#/components/schemas/${rename(m[1]!)}`;
        } else {
          out[k] = v;
        }
      } else {
        out[k] = rewriteRefsDeep(v, rename);
      }
    }
    return out;
  }
  return value;
}

export function prefixSchemas<T extends PartialOpenApi>(doc: T, prefix: string): T {
  const oldSchemas = doc.components?.schemas ?? {};
  const rename = (name: string): string =>
    name.startsWith(prefix) ? name : `${prefix}${name}`;

  const newSchemas: Record<string, unknown> = {};
  for (const [name, schema] of Object.entries(oldSchemas)) {
    newSchemas[rename(name)] = rewriteRefsDeep(schema, rename);
  }

  const newPaths = rewriteRefsDeep(doc.paths, rename) as Record<string, unknown>;

  return {
    ...doc,
    paths: newPaths,
    components: {
      ...(doc.components ?? {}),
      schemas: newSchemas,
    },
  } as T;
}
