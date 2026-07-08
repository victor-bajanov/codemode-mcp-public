#!/usr/bin/env tsx
/* fetch-and-normalise: pulls a Discovery doc, converts to OpenAPI, writes to disk */
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { discoveryToOpenApi, type DiscoveryDoc } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main(): Promise<void> {
  const url =
    process.argv[2] ??
    "https://gmail.googleapis.com/$discovery/rest?version=v1";
  const out = process.argv[3] ?? "../../../providers/gmail/src/spec.json";

  console.log(`Fetching: ${url}`);
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
  }
  const doc = (await res.json()) as DiscoveryDoc;

  console.log(`Normalising...`);
  const spec = discoveryToOpenApi(doc);

  const outAbs = resolve(__dirname, out);
  await mkdir(dirname(outAbs), { recursive: true });
  await writeFile(outAbs, JSON.stringify(spec, null, 2), "utf8");

  console.log(`Wrote: ${outAbs}`);
  console.log(
    `Stats: ${Object.keys(spec.paths).length} paths, ${
      Object.keys(spec.components.schemas).length
    } schemas`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
