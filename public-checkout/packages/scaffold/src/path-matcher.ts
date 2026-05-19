import type { OpenApiSpec, OpenApiOperation } from "@local/spec-loaders-google-discovery";

interface CompiledPath {
  template: string;
  segments: ReadonlyArray<{ literal: string } | { param: string }>;
  methods: Map<string, OpenApiOperation>;
}

const TEMPLATE_SEGMENT = /^\{(.+)\}$/;

function compile(spec: OpenApiSpec): CompiledPath[] {
  const out: CompiledPath[] = [];
  for (const [tmpl, methods] of Object.entries(spec.paths)) {
    const segments = tmpl
      .split("/")
      .filter((s) => s.length > 0)
      .map((s) => {
        const m = TEMPLATE_SEGMENT.exec(s);
        return m ? { param: m[1]! } : { literal: s };
      });
    const methodMap = new Map<string, OpenApiOperation>();
    for (const [method, op] of Object.entries(methods)) {
      methodMap.set(method.toUpperCase(), op);
    }
    out.push({ template: tmpl, segments, methods: methodMap });
  }
  return out;
}

let cache: WeakMap<OpenApiSpec, CompiledPath[]> | null = null;

function compiledOf(spec: OpenApiSpec): CompiledPath[] {
  cache ??= new WeakMap();
  let c = cache.get(spec);
  if (!c) {
    c = compile(spec);
    cache.set(spec, c);
  }
  return c;
}

export function resolveOperation(
  spec: OpenApiSpec,
  method: string,
  path: string,
): OpenApiOperation | null {
  if (method !== method.toUpperCase()) return null;     // case-sensitive
  if (path === "" || path[0] !== "/") return null;
  const segments = path.slice(1).split("/");
  if (segments.some((s) => s === "")) return null;       // reject empty segments / trailing slash
  for (const cp of compiledOf(spec)) {
    if (cp.segments.length !== segments.length) continue;
    let match = true;
    for (let i = 0; i < cp.segments.length; i++) {
      const want = cp.segments[i]!;
      const got = segments[i]!;
      if ("literal" in want) {
        if (want.literal !== got) { match = false; break; }
      }
      // param: matches any non-empty segment
    }
    if (!match) continue;
    const op = cp.methods.get(method);
    if (op) return op;
  }
  return null;
}
