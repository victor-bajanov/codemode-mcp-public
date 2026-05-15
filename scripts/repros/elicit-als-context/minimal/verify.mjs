#!/usr/bin/env node
// Spawns `wrangler dev`, connects an MCP client that advertises
// elicitation capability, calls `repro_elicit`, and prints what happened.
//
// Behavior:
//   WRAP=    -> expects ELICIT-ERROR ... "Agent was not found in send"
//   WRAP=1   -> expects a successful elicit round-trip
//
// Exit code is 0 if the observed behavior matches WRAP, 1 otherwise.

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const WRAP = process.env.WRAP === "1";
const READY_TIMEOUT_MS = 60_000;
const CALL_TIMEOUT_MS = 30_000;

function startWrangler() {
  // Pass WRAP via --var so the deployed Worker sees it.
  const args = ["dev", "--port", "0", "--var", `WRAP:${WRAP ? "1" : ""}`];
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
      { name: "elicit-als-repro-verifier", version: "0.0.1" },
      { capabilities: { elicitation: {} } },
    );

    // Stub elicit handler — autoresponds with "decline" (no content) so the
    // server-side response validator (which uses ajv -> `new Function(...)`,
    // disallowed in the Workers runtime) is skipped. The round-trip itself —
    // server.elicitInput(...) -> client -> back to server -> tool returns —
    // is what proves the ALS-context bug is fixed.
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      console.error(`[verify] elicit request received: ${JSON.stringify(req.params)}`);
      return { action: "decline" };
    });

    await client.connect(transport);
    console.error(`[verify] MCP client connected`);

    const callPromise = client.callTool(
      { name: "repro_elicit", arguments: { message: "repro" } },
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
  console.log(`observed=${observed}`);
  console.log(`detail=${observedDetail}`);
  console.log(`\n--- wrangler stdout (tail) ---\n${stdoutTail}`);
  console.log(`\n--- wrangler stderr (tail) ---\n${stderrTail}`);

  // Pass criteria
  const sawAlsError =
    observedDetail.includes("Agent was not found in send") ||
    stderrTail.includes("Agent was not found in send") ||
    stdoutTail.includes("Agent was not found in send");

  let pass = false;
  if (WRAP) {
    pass = observed === "tool-success" && !sawAlsError;
    console.log(
      pass
        ? `\nPASS: WRAP=1 produced a successful elicit round-trip.`
        : `\nFAIL: WRAP=1 expected tool-success without ALS error.`,
    );
  } else {
    pass = sawAlsError;
    console.log(
      pass
        ? `\nPASS: WRAP unset reproduced "Agent was not found in send".`
        : `\nFAIL: WRAP unset did not reproduce the expected ALS error.`,
    );
  }

  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error(`[verify] fatal: ${err?.stack ?? err}`);
  process.exit(2);
});
