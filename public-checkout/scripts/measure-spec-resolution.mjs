#!/usr/bin/env node
// Measure provider spec sizes before and after resolveRefs (mirrors @cloudflare/codemode/dist/mcp.js
// line 135). Lets us evaluate options A/D from docs/todo.md (prune to surface review; strip
// descriptions/examples) without committing to a build step.
//
// Reproducible: `node scripts/measure-spec-resolution.mjs`

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");
const RPC_LIMIT = 32 * 1024 * 1024; // 32 MiB Cloudflare Workers RPC arg/return cap

// Verbatim copy of resolveRefs from @cloudflare/codemode@0.3.4/dist/mcp.js:135.
function resolveRefs(obj, root, seen = new Set()) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map((item) => resolveRefs(item, root, seen));
  const record = obj;
  if ("$ref" in record && typeof record.$ref === "string") {
    const ref = record.$ref;
    if (seen.has(ref)) return { $circular: ref };
    if (!ref.startsWith("#/")) return record;
    seen.add(ref);
    const parts = ref.slice(2).split("/").map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    let resolved = root;
    for (const part of parts) resolved = resolved?.[part];
    const result = resolveRefs(resolved, root, seen);
    seen.delete(ref);
    return result;
  }
  const result = {};
  for (const [key, value] of Object.entries(record)) result[key] = resolveRefs(value, root, seen);
  return result;
}

function bytesOf(obj) {
  return Buffer.byteLength(JSON.stringify(obj), "utf8");
}

function fmt(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

const HTTP_METHODS = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);

// Filter spec.paths to only operations whose operationId is in `allowedOpIds`,
// then orphan-prune components.schemas to only those reachable from the kept paths.
function pruneSpecToOps(spec, allowedOpIds) {
  const newPaths = {};
  let keptOps = 0;
  let droppedOps = 0;
  for (const [path, methods] of Object.entries(spec.paths || {})) {
    const newMethods = {};
    let keptAny = false;
    for (const [methodKey, op] of Object.entries(methods)) {
      if (!HTTP_METHODS.has(methodKey)) {
        newMethods[methodKey] = op;
        continue;
      }
      if (op && typeof op.operationId === "string" && allowedOpIds.has(op.operationId)) {
        newMethods[methodKey] = op;
        keptAny = true;
        keptOps++;
      } else {
        droppedOps++;
      }
    }
    if (keptAny) newPaths[path] = newMethods;
  }

  // Walk kept paths, transitively collecting every #/ ref that's reachable.
  const reachable = new Set();
  const walk = (obj) => {
    if (obj === null || obj === undefined || typeof obj !== "object") return;
    if (Array.isArray(obj)) {
      for (const item of obj) walk(item);
      return;
    }
    if ("$ref" in obj && typeof obj.$ref === "string" && obj.$ref.startsWith("#/")) {
      if (reachable.has(obj.$ref)) return;
      reachable.add(obj.$ref);
      const parts = obj.$ref.slice(2).split("/").map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
      let resolved = spec;
      for (const part of parts) resolved = resolved?.[part];
      walk(resolved);
      return;
    }
    for (const value of Object.values(obj)) walk(value);
  };
  walk(newPaths);

  const newComponents = { ...(spec.components || {}) };
  let keptSchemas = 0;
  let droppedSchemas = 0;
  if (newComponents.schemas) {
    const newSchemas = {};
    for (const [name] of Object.entries(newComponents.schemas)) {
      if (reachable.has(`#/components/schemas/${name}`)) {
        newSchemas[name] = newComponents.schemas[name];
        keptSchemas++;
      } else {
        droppedSchemas++;
      }
    }
    newComponents.schemas = newSchemas;
  }

  return {
    pruned: { ...spec, paths: newPaths, components: newComponents },
    stats: { keptOps, droppedOps, keptSchemas, droppedSchemas },
  };
}

// Strip fields that don't affect runtime correctness but bloat resolved size:
// description, example, examples, x-* vendor extensions.
function stripNonEssential(obj) {
  if (obj === null || obj === undefined || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(stripNonEssential);
  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (key === "description" || key === "example" || key === "examples") continue;
    if (key.startsWith("x-")) continue;
    out[key] = stripNonEssential(value);
  }
  return out;
}

// Mirror the Xero surface review's allow-set: every GET on accounting/files/payroll.au, plus
// the 10 Tier-1 inspector entries, the 6 Tier-2 elicit ops, and the 4 Tier-3 deny ops.
function xeroSurfaceOpIds(spec) {
  const out = new Set();
  for (const methods of Object.values(spec.paths)) {
    const get = methods.get;
    if (!get || typeof get.operationId !== "string") continue;
    const id = get.operationId;
    if (id.startsWith("xero.accounting.") || id.startsWith("xero.files.") || id.startsWith("xero.payroll.au.")) {
      out.add(id);
    }
  }
  const tier1 = [
    "xero.accounting.createInvoices",
    "xero.accounting.updateOrCreateInvoices",
    "xero.accounting.updateInvoice",
    "xero.accounting.createContacts",
    "xero.accounting.updateOrCreateContacts",
    "xero.accounting.createBankTransactions",
    "xero.accounting.updateBankTransaction",
    "xero.accounting.createInvoiceAttachmentByFileName",
    "xero.accounting.updateInvoiceAttachmentByFileName",
    "xero.files.uploadFile",
    "xero.files.createFolder",
  ];
  const tier2 = [
    "xero.accounting.emailInvoice",
    "xero.accounting.createBatchPayment",
    "xero.payroll.au.createEmployee",
    "xero.payroll.au.updateEmployee",
    "xero.payroll.au.createPayRun",
    "xero.payroll.au.updatePayRun",
  ];
  const tier3 = [
    "xero.accounting.deleteTrackingCategory",
    "xero.accounting.updateTaxRate",
    "xero.accounting.deleteAccount",
    "xero.accounting.createPaymentService",
  ];
  [...tier1, ...tier2, ...tier3].forEach((id) => out.add(id));
  return out;
}

function row(label, onDisk, resolved) {
  const fits = resolved < RPC_LIMIT ? "✅" : "❌";
  return `| ${label.padEnd(42)} | ${fmt(onDisk).padStart(10)} | ${fmt(resolved).padStart(10)} | ${fits.padEnd(11)} |`;
}

const xeroSpec = JSON.parse(readFileSync(join(repoRoot, "packages/providers/xero/src/spec.json"), "utf8"));
const gmailSpec = JSON.parse(readFileSync(join(repoRoot, "packages/providers/gmail/src/spec.json"), "utf8"));

console.log(`RPC limit: ${fmt(RPC_LIMIT)}`);
console.log("");

const results = [];

// ---- Gmail (control) ----
{
  const onDisk = bytesOf(gmailSpec);
  const resolved = bytesOf(resolveRefs(gmailSpec, gmailSpec));
  results.push(["Gmail (control, full)", onDisk, resolved]);
}

// ---- Xero full ----
const xeroFullOnDisk = bytesOf(xeroSpec);
const xeroFullResolved = bytesOf(resolveRefs(xeroSpec, xeroSpec));
results.push(["Xero full", xeroFullOnDisk, xeroFullResolved]);

// ---- Xero pruned to surface ----
const allowedIds = xeroSurfaceOpIds(xeroSpec);
const { pruned: xeroPruned, stats: pruneStats } = pruneSpecToOps(xeroSpec, allowedIds);
const xeroPrunedOnDisk = bytesOf(xeroPruned);
const xeroPrunedResolved = bytesOf(resolveRefs(xeroPruned, xeroPruned));
results.push(["Xero pruned to surface review", xeroPrunedOnDisk, xeroPrunedResolved]);

// ---- Xero full + stripped descriptions/examples ----
const xeroStripped = stripNonEssential(xeroSpec);
const xeroStrippedOnDisk = bytesOf(xeroStripped);
const xeroStrippedResolved = bytesOf(resolveRefs(xeroStripped, xeroStripped));
results.push(["Xero full + descriptions stripped", xeroStrippedOnDisk, xeroStrippedResolved]);

// ---- Xero pruned + stripped (combined) ----
const xeroPrunedStripped = stripNonEssential(xeroPruned);
const xeroPrunedStrippedOnDisk = bytesOf(xeroPrunedStripped);
const xeroPrunedStrippedResolved = bytesOf(resolveRefs(xeroPrunedStripped, xeroPrunedStripped));
results.push(["Xero pruned + descriptions stripped", xeroPrunedStrippedOnDisk, xeroPrunedStrippedResolved]);

console.log(`Surface review allows ${allowedIds.size} operationIds.`);
console.log(`Pruning: kept ${pruneStats.keptOps} ops + ${pruneStats.keptSchemas} schemas; dropped ${pruneStats.droppedOps} ops + ${pruneStats.droppedSchemas} schemas.`);
console.log("");

console.log("| Variant                                    | On-disk    | Resolved   | < 32 MiB?   |");
console.log("|--------------------------------------------|------------|------------|-------------|");
for (const [label, onDisk, resolved] of results) {
  console.log(row(label, onDisk, resolved));
}

const xeroFitsAfterPrune = xeroPrunedResolved < RPC_LIMIT;
const xeroFitsAfterStrip = xeroStrippedResolved < RPC_LIMIT;
const xeroFitsCombined = xeroPrunedStrippedResolved < RPC_LIMIT;

console.log("");
console.log("Headlines:");
console.log(`  Xero full resolved:           ${fmt(xeroFullResolved)}  (~${(xeroFullResolved / xeroFullOnDisk).toFixed(0)}x on-disk)`);
console.log(`  Xero pruned resolved:         ${fmt(xeroPrunedResolved)}  ${xeroFitsAfterPrune ? `(under 32 MiB by ${fmt(RPC_LIMIT - xeroPrunedResolved)})` : `(STILL OVER by ${fmt(xeroPrunedResolved - RPC_LIMIT)})`}`);
console.log(`  Xero stripped-only resolved:  ${fmt(xeroStrippedResolved)}  ${xeroFitsAfterStrip ? `(under 32 MiB by ${fmt(RPC_LIMIT - xeroStrippedResolved)})` : `(STILL OVER by ${fmt(xeroStrippedResolved - RPC_LIMIT)})`}`);
console.log(`  Xero pruned + stripped:       ${fmt(xeroPrunedStrippedResolved)}  ${xeroFitsCombined ? `(under 32 MiB by ${fmt(RPC_LIMIT - xeroPrunedStrippedResolved)})` : `(STILL OVER by ${fmt(xeroPrunedStrippedResolved - RPC_LIMIT)})`}`);
