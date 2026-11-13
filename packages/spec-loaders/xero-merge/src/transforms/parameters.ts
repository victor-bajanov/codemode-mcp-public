// packages/spec-loaders/xero-merge/src/transforms/parameters.ts
//
// Replace every parameter `$ref: "#/components/parameters/<name>"` (operation
// level and path-item level) with a copy of the referenced object from the
// doc's own `components.parameters`. `unify` emits `components.schemas` only,
// so without this the merged spec carries dangling refs and the scaffold's
// query policy (D-2) cannot see the names they declare. An unknown ref is a
// build error.

export interface ParameterDoc {
  paths: Record<string, unknown>;
  components?: {
    parameters?: Record<string, unknown>;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

const PARAM_REF_RE = /^#\/components\/parameters\/(.+)$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

export function inlineParameterRefs<T extends ParameterDoc>(doc: T): T {
  const table = doc.components?.parameters ?? {};

  const resolve = (param: unknown, where: string): unknown => {
    if (!isRecord(param) || param.$ref === undefined) return param;
    const ref = param.$ref;
    const m = typeof ref === "string" ? PARAM_REF_RE.exec(ref) : null;
    if (!m || !Object.prototype.hasOwnProperty.call(table, m[1]!)) {
      throw new Error(`xero-merge inlineParameterRefs: unresolvable parameter ref ${String(ref)} at ${where}`);
    }
    return structuredClone(table[m[1]!]);
  };

  const inlineList = (list: unknown, where: string): unknown =>
    Array.isArray(list) ? list.map((p) => resolve(p, where)) : list;

  const paths: Record<string, unknown> = {};
  for (const [p, item] of Object.entries(doc.paths)) {
    if (!isRecord(item)) {
      paths[p] = item;
      continue;
    }
    const outItem: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(item)) {
      if (k === "parameters") {
        outItem[k] = inlineList(v, p);
      } else if (isRecord(v) && "parameters" in v) {
        outItem[k] = { ...v, parameters: inlineList(v.parameters, `${k.toUpperCase()} ${p}`) };
      } else {
        outItem[k] = v;
      }
    }
    paths[p] = outItem;
  }

  return { ...doc, paths } as T;
}
