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

export interface OperationMatch {
  op: OpenApiOperation;
  /** Spec template the path matched, e.g. "/gmail/v1/users/{userId}/labels/{id}". */
  template: string;
  /** Decoded parameter values keyed by template param name. */
  params: Record<string, string>;
  /** Outbound path derived from the template: literals verbatim, each param
   *  as encodeURIComponent(decoded value). Never contains `?`, `#`, `\`,
   *  dot-segments or control characters. */
  wirePath: string;
}

// C0 controls and DEL. The WHATWG URL parser strips tab/CR/LF outright and
// percent-encodes the rest, so either way the wire path would differ from the
// path the operation was matched on.
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;
const DOT_ONLY = /^\.+$/;
// Raw characters the URL parser reinterprets: `\` becomes `/` on special
// schemes, `?` and `#` start the query and fragment.
const RAW_REWRITTEN = /[\\?#]/;
// Decoded values only need refusing where re-encoding does not neutralise
// them: an encoded `/` would add a segment once an upstream decodes it, and an
// encoded `\` may be folded into `/` by an upstream that normalises it. A
// decoded `?` or `#` is re-encoded as `%3F`/`%23` in the wire path and can
// never start a query or fragment, so values such as Calendar ids
// (`en.australian#holiday@group.v.calendar.google.com`) and file names
// (`Receipt #123.pdf`) stay reachable.
const DECODED_UNSAFE = /[/\\]/;
// A lone UTF-16 surrogate makes `encodeURIComponent` throw `URIError` while
// the wire path is derived; refuse it here so the request fails as an
// ordinary unmatched path instead of a raw error.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** True when a raw path segment could be rewritten by the WHATWG URL parser
 *  or smuggle query/fragment syntax: contains `\`, `?`, `#` or a C0
 *  control/DEL or a lone UTF-16 surrogate; is `.`/`..`; fails
 *  decodeURIComponent; or decodes to
 *  something containing `/`, `\`, a C0 control/DEL, or consisting only of
 *  dots. An encoded `?` or `#` (`%3F`, `%23`) is accepted: it is re-encoded
 *  in the wire path. */
export function isUnsafePathSegment(segment: string): boolean {
  if (segment === "." || segment === "..") return true;
  if (RAW_REWRITTEN.test(segment) || CONTROL_CHARS.test(segment)) return true;
  if (LONE_SURROGATE.test(segment)) return true;
  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    return true; // malformed `%` sequence: fail closed (send a literal `%` as `%25`)
  }
  return DECODED_UNSAFE.test(decoded) || CONTROL_CHARS.test(decoded) || DOT_ONLY.test(decoded);
}

/** Splits `path.slice(1)` on "/" and returns true if any segment is unsafe. */
export function hasUnsafePathSegment(path: string): boolean {
  return path.slice(1).split("/").some(isUnsafePathSegment);
}

/**
 * Match `method` + raw `path` against the spec's templates (first match wins)
 * and derive the outbound path from the matched template, so the operation
 * reviewed is, by construction, the operation sent. Returns `null` for a
 * non-string method/path, a lower-case method, a path without a leading slash,
 * an empty segment (incl. trailing slash), any unsafe segment
 * (`isUnsafePathSegment`), or no matching template.
 */
export function matchOperation(
  spec: OpenApiSpec,
  method: string,
  path: string,
): OperationMatch | null {
  if (typeof method !== "string" || typeof path !== "string") return null;
  if (method !== method.toUpperCase()) return null;     // case-sensitive
  if (path === "" || path[0] !== "/") return null;
  const segments = path.slice(1).split("/");
  if (segments.some((s) => s === "")) return null;       // reject empty segments / trailing slash
  if (segments.some(isUnsafePathSegment)) return null;
  for (const cp of compiledOf(spec)) {
    if (cp.segments.length !== segments.length) continue;
    let match = true;
    for (let i = 0; i < cp.segments.length; i++) {
      const want = cp.segments[i]!;
      const got = segments[i]!;
      if ("literal" in want) {
        if (want.literal !== got) { match = false; break; }
      }
      // param: matches any non-empty (safe) segment
    }
    if (!match) continue;
    const op = cp.methods.get(method);
    if (!op) continue;
    const params: Record<string, string> = {};
    const wire: string[] = [];
    for (let i = 0; i < cp.segments.length; i++) {
      const want = cp.segments[i]!;
      if ("literal" in want) {
        wire.push(want.literal);
      } else {
        // Safe segments always decode (checked above).
        const value = decodeURIComponent(segments[i]!);
        params[want.param] = value;
        wire.push(encodeURIComponent(value));
      }
    }
    return { op, template: cp.template, params, wirePath: "/" + wire.join("/") };
  }
  return null;
}

export function resolveOperation(
  spec: OpenApiSpec,
  method: string,
  path: string,
): OpenApiOperation | null {
  return matchOperation(spec, method, path)?.op ?? null;
}

/** A pair of same-method templates that can match the same concrete path
 *  but carry different surface-review treatment. */
export interface ShadowConflict {
  method: string;
  first: { template: string; operationId: string };
  second: { template: string; operationId: string };
}

/**
 * Same-method template pairs that overlap (equal segment count, and at every
 * position equal literals or at least one parameter) while their surface
 * review entries differ in `decision` or `inspect`. `matchOperation` is
 * first-template-wins, and the re-resolve check uses the same matcher, so it
 * cannot see a literal route shadowed by an earlier parameter template that
 * an upstream router would prefer. Today every overlap in the bundled specs
 * is allow-to-allow; providers assert this stays empty so a spec or review
 * change cannot turn a shadow into an operation confusion unnoticed.
 */
export function findShadowConflicts(
  spec: OpenApiSpec,
  surfaceReview: Readonly<Record<string, { decision: string; inspect?: unknown } | undefined>>,
): ShadowConflict[] {
  const ops: Array<{ template: string; segments: CompiledPath["segments"]; method: string; operationId: string }> = [];
  for (const cp of compiledOf(spec)) {
    for (const [method, op] of cp.methods) {
      ops.push({ template: cp.template, segments: cp.segments, method, operationId: op.operationId });
    }
  }
  const out: ShadowConflict[] = [];
  for (let i = 0; i < ops.length; i++) {
    for (let j = i + 1; j < ops.length; j++) {
      const a = ops[i]!;
      const b = ops[j]!;
      if (a.method !== b.method || a.segments.length !== b.segments.length) continue;
      const overlaps = a.segments.every((s, k) => {
        const t = b.segments[k]!;
        return "param" in s || "param" in t || s.literal === t.literal;
      });
      if (!overlaps) continue;
      const ra = surfaceReview[a.operationId];
      const rb = surfaceReview[b.operationId];
      if (ra?.decision === rb?.decision && ra?.inspect === rb?.inspect) continue;
      out.push({
        method: a.method,
        first: { template: a.template, operationId: a.operationId },
        second: { template: b.template, operationId: b.operationId },
      });
    }
  }
  return out;
}
