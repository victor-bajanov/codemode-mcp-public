import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";

type LooseSpec = {
  paths: Record<string, Record<string, unknown>>;
};

/** HTTP method verbs recognised by OpenAPI 3.x. Non-method path-item keys
 *  (parameters, summary, description, $ref, servers) are skipped. */
const HTTP_METHODS = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);

export function validateMerged(spec: LooseSpec): OpenApiSpec {
  const seen = new Map<string, string>();
  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (!HTTP_METHODS.has(method.toLowerCase())) continue;
      const id = (op as { operationId?: string }).operationId;
      if (typeof id !== "string" || id.length === 0) {
        throw new Error(`validateMerged: missing operationId at ${method.toUpperCase()} ${path}`);
      }
      const prior = seen.get(id);
      if (prior) {
        throw new Error(`validateMerged: duplicate operationId ${id} (also at ${prior})`);
      }
      seen.set(id, `${method.toUpperCase()} ${path}`);
    }
  }
  return spec as unknown as OpenApiSpec;
}
