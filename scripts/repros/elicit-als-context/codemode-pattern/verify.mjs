#!/usr/bin/env node
// Spawns `wrangler dev`, connects an MCP client that advertises elicitation
// capability, calls `delete_thing` (the destructive op routed through the
// scaffold-mini dispatcher), and prints what happened.
//
// Three independent toggles:
//   WRAP=1                 -> apply the agentContext.run wrap (ALS fix)
//   VALIDATOR=cfworker     -> swap the SDK's default AjvJsonSchemaValidator
//                             for CfWorkerJsonSchemaValidator
//   TRIGGER_VALIDATION=1   -> mock client returns {action:"accept", content:...}
//                             so the SDK runs response-schema validation
//                             (otherwise returns {action:"decline"} and
//                             validation is skipped per SDK precondition
//                             `result.action === 'accept' && result.content`)
//
// Toggle matrix and expected outcomes:
//   WRAP=0                                              -> ALS bug
//   WRAP=1, TRIGGER_VALIDATION=0                        -> happy decline path
//   WRAP=1, TRIGGER_VALIDATION=1                        -> AJV bug
//   WRAP=1, TRIGGER_VALIDATION=1, VALIDATOR=cfworker    -> happy accept path
//
// Exit code is 0 if the observed behavior matches the toggles, 1 otherwise.

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const WRAP = process.env.WRAP === "1";
const TRIGGER_VALIDATION = process.env.TRIGGER_VALIDATION === "1";
const VALIDATOR = process.env.VALIDATOR ?? "";
const READY_TIMEOUT_MS = 60_000;
const CALL_TIMEOUT_MS = 30_000;

function startWrangler() {
  // Pass toggles via --var so the deployed Worker sees them.
  const args = [
    "dev", "--port", "0",
    "--var", `WRAP:${WRAP ? "1" : ""}`,
    "--var", `VALIDATOR:${VALIDATOR}`,
  ];
  const child = spawn("npx", ["--yes", "wrangler", ...args], {
    cwd: process.cwd(),
    env: { ...process.env, FORCE_COLOR: "0" },
  });
  return child;
}

function waitForReady(child) {
  return new Promise((resolve, reject) => {
    const buf = { stdout: "", stderr: "" };
    const timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for wrangler 'Ready on'.\nstdout:\n${buf.stdout}\nstderr:\n${buf.stderr}`));
    }, READY_TIMEOUT_MS);

    const onData = (stream) => (chunk) => {
      const s = chunk.toString();
      buf[stream] += s;
      process.stderr.write(`[wrangler:${stream}] ${s}`);
      const m = buf[stream].match(/Ready on\s+(https?:\/\/[^\s]+)/i);
      if (m) {
        clearTimeout(timer);
        resolve({ url: m[1], buf });
      }
    };
    child.stdout.on("data", onData("stdout"));
    child.stderr.on("data", onData("stderr"));
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`wrangler exited with code ${code} before ready.\nstdout:\n${buf.stdout}\nstderr:\n${buf.stderr}`));
    });
  });
}

async function main() {
  const child = startWrangler();

  // Continue to capture wrangler logs even after we get "Ready on".
  const wrangleLogs = { stdout: "", stderr: "" };
  child.stdout.on("data", (c) => {
    wrangleLogs.stdout += c.toString();
  });
  child.stderr.on("data", (c) => {
    wrangleLogs.stderr += c.toString();
  });

  let baseUrl;
  try {
    const ready = await waitForReady(child);
    baseUrl = ready.url.replace(/\/$/, "");
    console.error(`[verify] wrangler ready at ${baseUrl}`);
  } catch (err) {
    console.error(`[verify] wrangler did not become ready: ${err.message}`);
    try { child.kill("SIGTERM"); } catch {}
    process.exit(2);
  }

  // Brief settle so the inner handler is mounted.
  await sleep(500);

  let observed = "unknown";
  let observedDetail = "";
  let toolResultText = "";

  try {
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
    const client = new Client(
      { name: "elicit-als-codemode-pattern-verifier", version: "0.0.1" },
      { capabilities: { elicitation: {} } },
    );

    // Mock elicit handler. Behavior depends on TRIGGER_VALIDATION:
    //   off -> {action: "decline"}                  (no content; SDK skips validation)
    //   on  -> {action: "accept", content: {...}}   (SDK compiles validator -> AJV throws under Workers)
    // The schema in elicit-gate.ts is: confirm: enum["yes","no"]. Content value
    // is irrelevant for triggering AJV codegen — even a mismatched value
    // makes it past the validator-compile phase to the validator-run phase.
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      console.error(`[verify] elicit request received: ${JSON.stringify(req.params)}`);
      if (TRIGGER_VALIDATION) {
        return { action: "accept", content: { confirm: "yes" } };
      }
      return { action: "decline" };
    });

    await client.connect(transport);
    console.error(`[verify] MCP client connected`);

    const callPromise = client.callTool(
      { name: "delete_thing", arguments: { input: { id: "thing-1" } } },
      undefined,
      { timeout: CALL_TIMEOUT_MS },
    );

    const result = await callPromise;
    toolResultText = JSON.stringify(result);
    console.error(`[verify] tool result: ${toolResultText}`);

    const text = result?.content?.[0]?.text ?? "";
    if (typeof text === "string" && text.startsWith("ERROR ")) {
      observed = "tool-error";
      observedDetail = text;
    } else if (typeof text === "string" && text.startsWith("OK ")) {
      observed = "tool-success";
      observedDetail = text;
    } else {
      observed = "tool-unknown";
      observedDetail = toolResultText;
    }

    try { await client.close(); } catch {}
  } catch (err) {
    observed = "client-error";
    observedDetail = err?.message ?? String(err);
    console.error(`[verify] MCP client error: ${observedDetail}`);
  } finally {
    try { child.kill("SIGTERM"); } catch {}
    // Give wrangler a moment to flush logs.
    await sleep(500);
  }

  // Summary
  const stderrTail = wrangleLogs.stderr.slice(-4000);
  const stdoutTail = wrangleLogs.stdout.slice(-4000);

  console.log("\n=== VERIFY SUMMARY ===");
  console.log(`WRAP=${WRAP ? "1" : ""}`);
  console.log(`TRIGGER_VALIDATION=${TRIGGER_VALIDATION ? "1" : ""}`);
  console.log(`VALIDATOR=${VALIDATOR}`);
  console.log(`observed=${observed}`);
  console.log(`detail=${observedDetail}`);
  console.log(`\n--- wrangler stdout (tail) ---\n${stdoutTail}`);
  console.log(`\n--- wrangler stderr (tail) ---\n${stderrTail}`);

  // Failure markers
  const sawAlsError =
    observedDetail.includes("Agent was not found in send") ||
    stderrTail.includes("Agent was not found in send") ||
    stdoutTail.includes("Agent was not found in send");
  const sawAjvError =
    observedDetail.includes("Code generation from strings disallowed") ||
    stderrTail.includes("Code generation from strings disallowed") ||
    stdoutTail.includes("Code generation from strings disallowed");

  // Pass criteria depend on the toggle combination.
  let pass = false;
  let expectation = "";
  if (!WRAP) {
    expectation = "ALS error";
    pass = sawAlsError;
  } else if (!TRIGGER_VALIDATION) {
    expectation = "tool-success (decline)";
    pass = observed === "tool-success" && !sawAlsError && !sawAjvError;
  } else if (VALIDATOR !== "cfworker") {
    expectation = "AJV codegen error";
    pass = sawAjvError && !sawAlsError;
  } else {
    expectation = "tool-success (accept)";
    pass = observed === "tool-success" && !sawAlsError && !sawAjvError;
  }

  console.log(
    pass
      ? `\nPASS: observed expected behavior (${expectation}).`
      : `\nFAIL: expected ${expectation}; see detail above.`,
  );

  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error(`[verify] fatal: ${err?.stack ?? err}`);
  process.exit(2);
});
