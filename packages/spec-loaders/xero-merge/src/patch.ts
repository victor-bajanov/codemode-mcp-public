// fast-json-patch ships as a CJS-only package (Object.assign-based exports),
// which Node.js ESM cannot statically destructure.  We use createRequire so
// both tsx (build CLI) and vitest (tests) resolve it correctly.
import { createRequire } from "node:module";
import type { Operation, PatchResult } from "fast-json-patch";

const _require = createRequire(import.meta.url);
const { applyPatch } = _require("fast-json-patch") as {
  applyPatch: <T>(doc: T, patch: ReadonlyArray<Operation>, validate?: boolean, mutate?: boolean) => PatchResult<T>;
};

export type Patch = Operation[];

/** Apply each patch in order to a deep clone of `doc`; returns the patched copy. */
export function applyPatches<T>(doc: T, patches: Patch[]): T {
  let current: T = JSON.parse(JSON.stringify(doc));
  for (const p of patches) {
    const result = applyPatch(current, p, true, false);
    current = result.newDocument as T;
  }
  return current;
}
