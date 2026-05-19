import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import { parseSpecYaml } from "./parse";
import { rewritePaths } from "./transforms/paths";
import { prefixOperationIds } from "./transforms/operationIds";
import { prefixSchemas } from "./transforms/schemas";
import { unify } from "./unify";
import { applyPatches, type Patch } from "./patch";
import { validateMerged } from "./validate";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface MergeOptions {
  /** Override for the specs directory (defaults to `<package>/specs`). */
  specsDir?: string;
  /** Override for the patches directory (defaults to `<package>/src/patches`). */
  patchesDir?: string;
}

export interface MergeResult {
  spec: OpenApiSpec;
  /** Sorted operationIds for diff aid. */
  operationIds: string[];
}

const SUBSPECS = [
  { file: "xero_accounting.yaml", pathPrefix: "/api.xro/2.0", idPrefix: "xero.accounting", schemaPrefix: "Accounting" },
  { file: "xero_files.yaml", pathPrefix: "/files.xro/1.0", idPrefix: "xero.files", schemaPrefix: "Files" },
  { file: "xero_payroll_au.yaml", pathPrefix: "/payroll.xro/1.0", idPrefix: "xero.payroll.au", schemaPrefix: "PayrollAU" },
];

export function mergeXeroSpecs(opts: MergeOptions = {}): MergeResult {
  const specsDir = opts.specsDir ?? join(__dirname, "..", "specs");
  const patchesDir = opts.patchesDir ?? join(__dirname, "patches");

  const transformed = SUBSPECS.map((s) => {
    const raw = readFileSync(join(specsDir, s.file), "utf8");
    const parsed = parseSpecYaml(raw) as {
      paths: Record<string, Record<string, unknown>>;
      components?: { schemas?: Record<string, unknown> };
      [k: string]: unknown;
    };
    const pathsDoc = rewritePaths(parsed, s.pathPrefix);
    const idsDoc = prefixOperationIds(
      pathsDoc as unknown as Parameters<typeof prefixOperationIds>[0],
      s.idPrefix,
    );
    const doc = prefixSchemas(
      idsDoc as unknown as Parameters<typeof prefixSchemas>[0],
      s.schemaPrefix,
    );
    return doc;
  });

  let merged = unify(transformed, {
    title: "Xero (merged: accounting + files + payroll-au)",
    version: "1.0.0",
    serverUrl: "https://api.xero.com",
  });

  // Apply RFC-6902 patches in lexicographic filename order (deterministic).
  const patches: Patch[] = [];
  if (existsSync(patchesDir)) {
    const files = readdirSync(patchesDir).filter((f) => f.endsWith(".json")).sort();
    for (const f of files) {
      const text = readFileSync(join(patchesDir, f), "utf8");
      patches.push(JSON.parse(text) as Patch);
    }
  }
  merged = applyPatches(merged, patches);

  validateMerged(merged);

  const operationIds = Object.values(merged.paths)
    .flatMap((m) => Object.values(m as Record<string, { operationId?: string }>))
    .map((op) => op.operationId)
    .filter((id): id is string => typeof id === "string")
    .sort();

  return { spec: merged, operationIds };
}
