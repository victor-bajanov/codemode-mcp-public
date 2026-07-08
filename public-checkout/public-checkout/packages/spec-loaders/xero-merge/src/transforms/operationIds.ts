// packages/spec-loaders/xero-merge/src/transforms/operationIds.ts

export interface PartialOpenApi {
  paths: Record<string, Record<string, { operationId?: string; [k: string]: unknown }>>;
  [key: string]: unknown;
}

export function prefixOperationIds<T extends PartialOpenApi>(doc: T, prefix: string): T {
  const newPaths: PartialOpenApi["paths"] = {};
  for (const [p, methods] of Object.entries(doc.paths ?? {})) {
    const newMethods: Record<string, { operationId?: string; [k: string]: unknown }> = {};
    for (const [method, op] of Object.entries(methods)) {
      if (op && typeof op === "object" && typeof op.operationId === "string") {
        const id = op.operationId;
        newMethods[method] = id.startsWith(prefix + ".")
          ? op
          : { ...op, operationId: `${prefix}.${id}` };
      } else {
        newMethods[method] = op;
      }
    }
    newPaths[p] = newMethods;
  }
  return { ...doc, paths: newPaths };
}
