/**
 * Fencing of provider-flagged untrusted response fields (F2-8).
 *
 * A provider names a vendor extension (Optical: `x-optical-untrusted`) that
 * its spec sets to `true` on response-schema nodes whose text is written by
 * third parties. `collectUntrustedPointers` finds those nodes per response
 * status; `fenceUntrusted` wraps each string they reach as
 * `⟦untrusted⟧…⟦/untrusted⟧` before the value is returned to the model.
 * Provider-agnostic: a provider without the extension pays nothing.
 */
import type { OpenApiOperation, OpenApiSpec } from "@local/spec-loaders-google-discovery";

/** Property-name segments from the response root; `"*"` means "each array element". */
export type Pointer = readonly string[];

export const UNTRUSTED_OPEN = "⟦untrusted⟧";
export const UNTRUSTED_CLOSE = "⟦/untrusted⟧";

/** Wildcard segment: each array element, or each own key of an object
 *  (`additionalProperties`). */
const ITEMS = "*";
const JSON_MEDIA = "application/json";
const LOCAL_SCHEMA_REF = "#/components/schemas/";
// U+27E6/U+27E7 (the fence brackets) and the look-alikes U+301A/U+301B.
const FENCE_BRACKETS = /[⟦⟧〚〛]/g;

type Components = Pick<OpenApiSpec, "components">;

interface CacheEntry {
  extensionKey: string;
  spec: Components | undefined;
  pointers: Map<string, Pointer[]>;
}
const cache = new WeakMap<OpenApiOperation, CacheEntry>();

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function resolveRef(ref: string, spec: Components | undefined): unknown {
  if (!ref.startsWith(LOCAL_SCHEMA_REF) || !spec) return undefined;
  const name = ref.slice(LOCAL_SCHEMA_REF.length);
  const schemas = spec.components?.schemas;
  if (!isRecord(schemas) || !Object.prototype.hasOwnProperty.call(schemas, name)) return undefined;
  return schemas[name];
}

function walkSchema(
  node: unknown,
  path: string[],
  extensionKey: string,
  spec: Components | undefined,
  refStack: Set<string>,
  out: Map<string, Pointer>,
): void {
  if (!isRecord(node)) return;
  if (typeof node.$ref === "string") {
    const ref = node.$ref;
    if (refStack.has(ref)) return;
    refStack.add(ref);
    walkSchema(resolveRef(ref, spec), path, extensionKey, spec, refStack, out);
    refStack.delete(ref);
    // A `$ref` sibling in OpenAPI 3.0 is ignored; keep reading flags on the
    // node anyway (fail towards fencing).
  }
  if (node[extensionKey] === true) {
    out.set(JSON.stringify(path), [...path]);
  }
  if (isRecord(node.properties)) {
    for (const [name, child] of Object.entries(node.properties)) {
      walkSchema(child, [...path, name], extensionKey, spec, refStack, out);
    }
  }
  if (node.items !== undefined) {
    walkSchema(node.items, [...path, ITEMS], extensionKey, spec, refStack, out);
  }
  if (isRecord(node.additionalProperties)) {
    walkSchema(node.additionalProperties, [...path, ITEMS], extensionKey, spec, refStack, out);
  }
  for (const key of ["allOf", "oneOf", "anyOf"] as const) {
    const branches = node[key];
    if (Array.isArray(branches)) {
      for (const b of branches) walkSchema(b, path, extensionKey, spec, refStack, out);
    }
  }
}

/**
 * Pointers to every node flagged `<extensionKey>: true` in each response's
 * `application/json` schema, keyed by response status (`"200"`, `"default"`).
 * Every declared status has an entry; it is empty when nothing is flagged.
 * Walks `properties`, `items` and schema-form `additionalProperties` (both
 * as the wildcard segment), `allOf`/`oneOf`/`anyOf` (union) and local
 * `#/components/schemas/` refs. `patternProperties` and `prefixItems` are not
 * walked. Expects an un-dereferenced spec: `$ref`s are resolved against
 * `spec` by schema name only (no JSON-pointer `~0`/`~1` unescaping), and the
 * only cycle guard is the stack of `$ref`s being expanded, so an
 * object-identity cycle in a pre-dereferenced spec is not supported.
 * Cached per `op` object.
 */
export function collectUntrustedPointers(
  op: OpenApiOperation,
  extensionKey: string,
  spec?: Components,
): Map<string, Pointer[]> {
  const hit = cache.get(op);
  if (hit && hit.extensionKey === extensionKey && hit.spec === spec) return hit.pointers;

  const pointers = new Map<string, Pointer[]>();
  const responses = isRecord(op.responses) ? op.responses : {};
  for (const [status, res] of Object.entries(responses)) {
    // Every declared status gets an entry (possibly empty), so a status the
    // spec declares without flags is told apart from an undeclared one.
    const found = new Map<string, Pointer>();
    const media = isRecord(res) && isRecord(res.content) ? res.content[JSON_MEDIA] : undefined;
    if (isRecord(media)) walkSchema(media.schema, [], extensionKey, spec, new Set(), found);
    pointers.set(status, [...found.values()]);
  }
  cache.set(op, { extensionKey, spec, pointers });
  return pointers;
}

/** Pointers for an HTTP status: the exact status, else its `NXX` range,
 *  else `default`. A status the operation does not declare at all fails
 *  closed to the union of every declared status's pointers (an upstream
 *  answering off-spec may still be echoing flagged text). */
export function untrustedPointersForStatus(pointers: Map<string, Pointer[]>, status: number): Pointer[] {
  const range = `${Math.floor(status / 100)}XX`;
  const declared =
    pointers.get(String(status)) ?? pointers.get(range) ?? pointers.get(range.toLowerCase()) ?? pointers.get("default");
  if (declared) return declared;
  const union = new Map<string, Pointer>();
  for (const list of pointers.values()) {
    for (const p of list) union.set(JSON.stringify(p), p);
  }
  return [...union.values()];
}

function fenceString(s: string): string {
  return `${UNTRUSTED_OPEN}${s.replace(FENCE_BRACKETS, "�")}${UNTRUSTED_CLOSE}`;
}

interface Trie {
  fence: boolean;
  children: Map<string, Trie>;
}

// Tries for the pointer lists `collectUntrustedPointers` caches per operation,
// so a flagged operation builds its trie once rather than per response.
const trieCache = new WeakMap<readonly Pointer[], Trie>();

function buildTrie(pointers: readonly Pointer[]): Trie {
  const hit = trieCache.get(pointers);
  if (hit) return hit;
  const root: Trie = { fence: false, children: new Map() };
  for (const p of pointers) {
    let node = root;
    for (const seg of p) {
      let next = node.children.get(seg);
      if (!next) {
        next = { fence: false, children: new Map() };
        node.children.set(seg, next);
      }
      node = next;
    }
    node.fence = true;
  }
  trieCache.set(pointers, root);
  return root;
}

function childNodes(nodes: readonly Trie[], key: string | undefined): Trie[] {
  const out: Trie[] = [];
  for (const n of nodes) {
    const named = key === undefined ? undefined : n.children.get(key);
    const wild = n.children.get(ITEMS);
    if (named) out.push(named);
    if (wild && wild !== named) out.push(wild);
  }
  return out;
}

// `nodes` are every trie node reaching this value (a named and a wildcard
// pointer can both reach it). `flagged` is inherited by everything below a
// flagged node, so each string is visited once and fenced at most once.
function apply(value: unknown, nodes: readonly Trie[], inherited: boolean): unknown {
  const flagged = inherited || nodes.some((n) => n.fence);
  if (typeof value === "string") return flagged ? fenceString(value) : value;
  if (Array.isArray(value)) {
    const next = childNodes(nodes, undefined);
    if (!flagged && next.length === 0) return value;
    let copy: unknown[] | undefined;
    for (let i = 0; i < value.length; i++) {
      const v = apply(value[i], next, flagged);
      if (v !== value[i]) {
        copy ??= value.slice();
        copy[i] = v;
      }
    }
    return copy ?? value;
  }
  if (isRecord(value)) {
    if (!flagged && !nodes.some((n) => n.children.size > 0)) return value;
    let copy: Record<string, unknown> | undefined;
    for (const key of Object.keys(value)) {
      const next = childNodes(nodes, key);
      if (!flagged && next.length === 0) continue;
      const v = apply(value[key], next, flagged);
      if (v !== value[key]) {
        copy ??= { ...value };
        // defineProperty keeps a literal `__proto__` key an own data property.
        Object.defineProperty(copy, key, { value: v, writable: true, enumerable: true, configurable: true });
      }
    }
    return copy ?? value;
  }
  return value;
}

/**
 * A copy of `value` in which every string reached by a pointer, and every
 * string anywhere under a flagged array or object, is fenced. The wildcard
 * segment reaches each array element and each own key of an object. Object
 * keys under a flagged node are neither fenced nor escaped, only values
 * (Optical flags no maps today). Untouched subtrees are
 * shared; `value` itself is never mutated. Returns `value` unchanged when
 * nothing is reached.
 */
export function fenceUntrusted(value: unknown, pointers: readonly Pointer[]): unknown {
  if (pointers.length === 0) return value;
  return apply(value, [buildTrie(pointers)], false);
}
