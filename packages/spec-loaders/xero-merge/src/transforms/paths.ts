// packages/spec-loaders/xero-merge/src/transforms/paths.ts

export interface PartialOpenApi {
  paths: Record<string, Record<string, unknown>>;
  [key: string]: unknown;
}

/** Rebase every path under `prefix`. Prefix is normalised so the join produces exactly one leading slash. */
export function rewritePaths<T extends PartialOpenApi>(doc: T, prefix: string): T {
  const trimmed = "/" + prefix.replace(/^\/+/, "").replace(/\/+$/, "");
  const newPaths: PartialOpenApi["paths"] = {};
  for (const [p, methods] of Object.entries(doc.paths ?? {})) {
    const path = "/" + p.replace(/^\/+/, "");
    newPaths[trimmed + path] = methods;
  }
  return { ...doc, paths: newPaths };
}
