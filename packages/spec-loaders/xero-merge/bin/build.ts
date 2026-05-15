// packages/spec-loaders/xero-merge/bin/build.ts
//
// CLI: build the merged Xero spec and emit it to `dist/` AND to
// `packages/providers/xero/src/` so the bundled JSON is committed alongside
// surface-review.ts and inspectors. Spec, surface review, and inspectors all
// version together through the same PR.

import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mergeXeroSpecs } from "../src/merge";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = join(__dirname, "..", "dist");
const providerDir = join(__dirname, "..", "..", "..", "providers", "xero", "src");

function emit(targetDir: string, spec: unknown, ids: string[]): void {
  mkdirSync(targetDir, { recursive: true });
  writeFileSync(join(targetDir, "spec.json"), JSON.stringify(spec, null, 2) + "\n");
  writeFileSync(join(targetDir, "operationId-list.txt"), ids.join("\n") + "\n");
}

const { spec, operationIds } = mergeXeroSpecs();
emit(distDir, spec, operationIds);

// Skip provider copy if providers/xero/src/ does not exist (e.g. when this script
// is run before Phase 4 has created the package). Phase 4's Task 22 creates the dir.
try {
  emit(providerDir, spec, operationIds);
  console.log(`xero-merge: wrote ${operationIds.length} operationIds to ${distDir} and ${providerDir}`);
} catch (e) {
  console.log(`xero-merge: wrote ${operationIds.length} operationIds to ${distDir} only (${(e as Error).message})`);
}
