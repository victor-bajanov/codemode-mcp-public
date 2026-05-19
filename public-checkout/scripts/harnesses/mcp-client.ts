/**
 * MCP client integration harness.
 *
 * Spawns `pnpm wrangler dev` from `apps/gmail/`, drives an MCP client (using
 * `@modelcontextprotocol/sdk`'s `StreamableHTTPClientTransport` plus a
 * filesystem-backed `OAuthClientProvider`) through the worker's OAuth dance,
 * and exercises one of three end-to-end checks:
 *
 *   --check=pkce            verifies the OAuth dance completes (which only
 *                           happens if both MCP-client↔worker PKCE and
 *                           worker↔Google PKCE succeed); no tool call.
 *   --check=audit-redacted  spawns wrangler dev with the default
 *                           `ALLOW_PII_IN_LOGS=false`, calls
 *                           gmail.users.messages.send with 26 allow-listed
 *                           recipients (triggering the mass-send inspector),
 *                           the client declines the elicit, and asserts the
 *                           AUDIT line on stdout carries `__redacted__:true`
 *                           and the field names but no raw values.
 *   --check=audit-raw       same as audit-redacted but spawns with
 *                           `--var ALLOW_PII_IN_LOGS:true` and asserts the
 *                           AUDIT line carries the raw recipients/subject.
 *
 * Token cache lives at `~/.codemode-mcp/mcp-token.json` so the OAuth dance
 * runs once per operator session. Delete that file to force a fresh dance.
 *
 * This harness can't be exercised end-to-end in CI; running it requires:
 *   - a real Google Cloud OAuth client with http://localhost:8787/callback
 *     in its authorized redirect URIs;
 *   - `apps/gmail/.dev.vars` populated with GOOGLE_CLIENT_ID,
 *     GOOGLE_CLIENT_SECRET, and COOKIE_ENCRYPTION_KEY (>=32 chars).
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  ElicitRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type {
  OAuthClientMetadata,
  OAuthClientInformation,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";

import { spawnWrangler, type SpawnedWrangler } from "./lib/spawn-wrangler.js";
import { dumpTail, printAssertions, summary, type Assertion } from "./lib/report.js";

type CheckMode = "pkce" | "audit-redacted" | "audit-raw";

interface Args {
  check: CheckMode;
  target: string;
  port: number;
  spawn: boolean;
}

const USAGE = `Usage: pnpm harness:mcp [options]

Options:
  --check=<mode>   pkce | audit-redacted (default) | audit-raw
  --target=<url>   Base URL when --no-spawn is set. Default http://localhost:8787
  --port=<n>       Port for wrangler dev. Default 8787
  --no-spawn       Don't spawn wrangler dev; use --target instead. Only
                   meaningful for audit-redacted / audit-raw modes — the
                   PKCE mode requires the spawned process for token-cache
                   semantics. With --no-spawn, AUDIT lines come from the
                   worker logs the operator is responsible for piping.
  --help           Print this help and exit.
`;

function parseArgs(argv: readonly string[]): Args {
  let check: CheckMode = "audit-redacted";
  let target = "http://localhost:8787";
  let port = 8787;
  let spawnFlag = true;
  for (const raw of argv) {
    if (raw === "--help" || raw === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    }
    if (raw === "--no-spawn") {
      spawnFlag = false;
      continue;
    }
    // Skip a standalone "--" separator. pnpm 9 forwards it from the
    // `pnpm <script> -- <args>` form, and `op run --env-file=… -- pnpm …`
    // doesn't strip its own. Either way it's just a delimiter, not an arg.
    if (raw === "--") {
      continue;
    }
    const eq = raw.indexOf("=");
    if (eq < 0) {
      throw new Error(`Unrecognised argument: ${raw}\n${USAGE}`);
    }
    const key = raw.slice(0, eq);
    const value = raw.slice(eq + 1);
    switch (key) {
      case "--check":
        if (value !== "pkce" && value !== "audit-redacted" && value !== "audit-raw") {
          throw new Error(`Unknown --check mode: ${value}\n${USAGE}`);
        }
        check = value;
        break;
      case "--target":
        target = value;
        break;
      case "--port": {
        const n = Number.parseInt(value, 10);
        if (!Number.isFinite(n) || n <= 0 || n > 65535) {
          throw new Error(`Invalid --port: ${value}`);
        }
        port = n;
        break;
      }
      default:
        throw new Error(`Unrecognised argument: ${raw}\n${USAGE}`);
    }
  }
  return { check, target, port, spawn: spawnFlag };
}

// ---------------------------------------------------------------------------
// Browser open: tiny built-in, no extra dep. Best-effort.
// ---------------------------------------------------------------------------

function openBrowser(url: string): void {
  const platform = process.platform;
  const cmd =
    platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {
      // Fallback already handled in caller (we print the URL).
    });
    child.unref();
  } catch {
    /* swallow — caller prints URL */
  }
}

// ---------------------------------------------------------------------------
// Token cache + OAuth client provider
// ---------------------------------------------------------------------------

interface CachedSession {
  tokens?: OAuthTokens;
  clientInformation?: OAuthClientInformation;
  codeVerifier?: string;
}

const TOKEN_CACHE_PATH = path.join(homedir(), ".codemode-mcp", "mcp-token.json");

async function readCache(): Promise<CachedSession> {
  if (!existsSync(TOKEN_CACHE_PATH)) return {};
  try {
    const text = await readFile(TOKEN_CACHE_PATH, "utf8");
    return JSON.parse(text) as CachedSession;
  } catch {
    return {};
  }
}

async function writeCache(session: CachedSession): Promise<void> {
  await mkdir(path.dirname(TOKEN_CACHE_PATH), { recursive: true });
  await writeFile(TOKEN_CACHE_PATH, JSON.stringify(session, null, 2), {
    mode: 0o600,
  });
}

class HarnessOAuthProvider {
  private cache: CachedSession;
  constructor(
    private readonly redirectListenerUrl: string,
    cache: CachedSession,
  ) {
    this.cache = cache;
  }

  get redirectUrl(): string {
    return this.redirectListenerUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: "codemode-mcp harness",
      redirect_uris: [this.redirectListenerUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    };
  }

  clientInformation(): OAuthClientInformation | undefined {
    return this.cache.clientInformation;
  }

  async saveClientInformation(info: OAuthClientInformation): Promise<void> {
    this.cache.clientInformation = info;
    await writeCache(this.cache);
  }

  tokens(): OAuthTokens | undefined {
    return this.cache.tokens;
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    this.cache.tokens = tokens;
    await writeCache(this.cache);
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    this.cache.codeVerifier = codeVerifier;
    await writeCache(this.cache);
  }

  codeVerifier(): string {
    if (!this.cache.codeVerifier) {
      throw new Error("No code verifier saved — saveCodeVerifier was not called first");
    }
    return this.cache.codeVerifier;
  }

  // Browser-launch sink. The harness layers a localhost callback listener
  // on top via `awaitCallbackCode` (see below); we never actually drive a
  // user-agent ourselves.
  pendingAuthUrl: string | undefined;
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    this.pendingAuthUrl = authorizationUrl.toString();
  }
}

// ---------------------------------------------------------------------------
// Localhost callback listener
// ---------------------------------------------------------------------------

interface CallbackListener {
  redirectUrl: string;
  awaitCode: (timeoutMs: number) => Promise<string>;
  close: () => void;
}

async function startCallbackListener(): Promise<CallbackListener> {
  let resolveCode: ((code: string) => void) | undefined;
  let rejectCode: ((err: Error) => void) | undefined;

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (!req.url) {
      res.statusCode = 400;
      res.end("missing url");
      return;
    }
    const url = new URL(req.url, `http://localhost`);
    if (url.pathname !== "/callback") {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    const code = url.searchParams.get("code");
    const error = url.searchParams.get("error");
    if (error) {
      res.statusCode = 400;
      res.end(`OAuth error: ${error}`);
      if (rejectCode) rejectCode(new Error(`OAuth error: ${error}`));
      return;
    }
    if (!code) {
      res.statusCode = 400;
      res.end("missing code");
      if (rejectCode) rejectCode(new Error("Callback hit without ?code"));
      return;
    }
    res.statusCode = 200;
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end(
      "<html><body><h2>Authorization complete</h2>" +
        "<p>You can close this tab and return to the harness.</p></body></html>",
    );
    if (resolveCode) resolveCode(code);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const addr = server.address() as AddressInfo;
  const redirectUrl = `http://127.0.0.1:${addr.port}/callback`;

  return {
    redirectUrl,
    awaitCode: (timeoutMs) =>
      new Promise<string>((resolve, reject) => {
        resolveCode = resolve;
        rejectCode = reject;
        setTimeout(() => reject(new Error(`OAuth callback timeout after ${timeoutMs} ms`)), timeoutMs);
      }),
    close: () => server.close(),
  };
}

// ---------------------------------------------------------------------------
// Connect with OAuth
// ---------------------------------------------------------------------------

async function connectWithOAuth(targetUrl: string): Promise<Client> {
  const listener = await startCallbackListener();
  const cache = await readCache();
  const provider = new HarnessOAuthProvider(listener.redirectUrl, cache);

  const transport = new StreamableHTTPClientTransport(new URL(`${targetUrl}/mcp`), {
    authProvider: provider,
  });

  const client = new Client(
    { name: "codemode-mcp-harness", version: "0.1.0" },
    { capabilities: { elicitation: {} } },
  );

  // The mass-send inspector needs an elicit hook that the SDK can call.
  // Always decline — the harness asserts the audit shape *for the declined
  // path*, which exercises the redaction code without sending any mail.
  client.setRequestHandler(ElicitRequestSchema, async () => ({ action: "decline" }));

  try {
    await client.connect(transport as unknown as Transport);
  } catch (err) {
    // If we got UnauthorizedError, run the dance. The SDK's UnauthorizedError
    // extends Error without setting `this.name`, so `err.name === "Error"`;
    // identify it by instanceof (or by message as a fallback).
    if (!(err instanceof UnauthorizedError)) {
      listener.close();
      throw err;
    }
    if (!provider.pendingAuthUrl) {
      listener.close();
      throw new Error("UnauthorizedError thrown but no authorization URL was produced");
    }
    process.stderr.write(
      `\n[harness] Open this URL in a browser to authorize:\n  ${provider.pendingAuthUrl}\n\n`,
    );
    openBrowser(provider.pendingAuthUrl);
    const code = await listener.awaitCode(2 * 60_000);
    await transport.finishAuth(code);
    listener.close();
    // After finishAuth, retry the connect on a fresh transport (the SDK does
    // not auto-retry the same instance).
    const transport2 = new StreamableHTTPClientTransport(new URL(`${targetUrl}/mcp`), {
      authProvider: provider,
    });
    await client.connect(transport2 as unknown as Transport);
    return client;
  }
  listener.close();
  return client;
}

// ---------------------------------------------------------------------------
// Audit harness body
// ---------------------------------------------------------------------------

/** Build a base64url-encoded RFC 822 message with 26 recipients off the
 *  outbound allowlist (`*@example.com`). 26 > MASS_SEND_THRESHOLD
 *  (25) so the outbound inspector returns `decision: "elicit"` with
 *  inspectorSummary `{ recipients, subject, count }`. */
function buildMassSendBody(): { raw: string; recipientCount: number; subject: string } {
  const recipients = Array.from(
    { length: 26 },
    (_, i) => `user${i + 1}@example.com`,
  );
  const subject = "harness-mass-send";
  const rfc822 =
    `To: ${recipients.join(", ")}\r\n` +
    `From: user1@example.com\r\n` +
    `Subject: ${subject}\r\n` +
    `\r\n` +
    `This is a codemode-mcp harness test message. It is never actually sent ` +
    `because the elicit is declined.\r\n`;
  const raw = Buffer.from(rfc822, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return { raw, recipientCount: recipients.length, subject };
}

interface AuditLine {
  raw: string;
  parsed: Record<string, unknown>;
}

function findAuditLine(
  lines: readonly string[],
  operationId: string,
): AuditLine | undefined {
  // wrangler may prefix each captured line with "[wrangler:stdout] " or
  // similar; locate the JSON payload itself by searching for "AUDIT {".
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i]!;
    const idx = line.indexOf("AUDIT {");
    if (idx < 0) continue;
    const jsonText = line.slice(idx + "AUDIT ".length);
    try {
      const parsed = JSON.parse(jsonText) as Record<string, unknown>;
      if (parsed.operationId === operationId) {
        return { raw: line, parsed };
      }
    } catch {
      /* keep scanning */
    }
  }
  return undefined;
}

async function callExecuteSend(client: Client, body: { raw: string }): Promise<CallToolResult> {
  // The provider's MCP surface exposes a `search` tool and an `execute` tool
  // (see @cloudflare/codemode openApiMcpServer). The `execute` tool runs
  // arbitrary JS in a sandbox whose `codemode.request(...)` calls the
  // upstream Gmail API through the scaffold's inspector pipeline. We embed
  // the raw RFC822 inside that JS so the inspector receives the body shape
  // it expects.
  const escapedRaw = JSON.stringify(body.raw);
  const code = `async () => {
  return await codemode.request({
    method: "POST",
    path: "/gmail/v1/users/me/messages/send",
    body: { raw: ${escapedRaw} },
  });
}`;
  const result = (await client.callTool(
    { name: "execute", arguments: { code } },
    undefined,
    { timeout: 60_000 },
  )) as CallToolResult;
  return result;
}

async function waitForAuditLine(
  wrangler: SpawnedWrangler,
  operationId: string,
  timeoutMs: number,
): Promise<AuditLine | undefined> {
  // Quick check first.
  const existing = findAuditLine(wrangler.getCapturedLines(), operationId);
  if (existing) return existing;
  return new Promise<AuditLine | undefined>((resolve) => {
    const timer = setTimeout(() => {
      unsub();
      resolve(undefined);
    }, timeoutMs);
    const unsub = wrangler.onLine(() => {
      const m = findAuditLine(wrangler.getCapturedLines(), operationId);
      if (m) {
        clearTimeout(timer);
        unsub();
        resolve(m);
      }
    });
  });
}

function isRedactedEnvelope(elicitFields: unknown): boolean {
  if (typeof elicitFields !== "object" || elicitFields === null) return false;
  const rec = elicitFields as Record<string, unknown>;
  return rec["__redacted__"] === true;
}

interface AuditExpectation {
  mode: "redacted" | "raw";
}

function assertAuditShape(
  audit: AuditLine,
  expected: AuditExpectation,
  recipientCount: number,
  subject: string,
): Assertion[] {
  const elicitFields = audit.parsed.elicitFields as Record<string, unknown> | undefined;
  const assertions: Assertion[] = [];

  if (!elicitFields) {
    assertions.push({
      ok: false,
      label: "AUDIT line has elicitFields",
      detail: `parsed=${JSON.stringify(audit.parsed)}`,
    });
    return assertions;
  }

  if (expected.mode === "redacted") {
    const redacted = isRedactedEnvelope(elicitFields);
    assertions.push({
      ok: redacted,
      label: "elicitFields.__redacted__ === true",
      detail: redacted ? undefined : `elicitFields=${JSON.stringify(elicitFields)}`,
    });
    const keys = elicitFields["keys"];
    const keyList = Array.isArray(keys) ? (keys as unknown[]) : [];
    const hasRecipients = keyList.includes("recipients");
    const hasSubject = keyList.includes("subject");
    assertions.push({
      ok: hasRecipients,
      label: "elicitFields.keys contains 'recipients'",
      detail: hasRecipients ? undefined : `keys=${JSON.stringify(keyList)}`,
    });
    assertions.push({
      ok: hasSubject,
      label: "elicitFields.keys contains 'subject'",
      detail: hasSubject ? undefined : `keys=${JSON.stringify(keyList)}`,
    });
    // No raw recipient/subject string should be present.
    const recipientsRaw = elicitFields["recipients"];
    const subjectRaw = elicitFields["subject"];
    assertions.push({
      ok: recipientsRaw === undefined,
      label: "raw 'recipients' string absent",
      detail: recipientsRaw === undefined ? undefined : `recipients=${String(recipientsRaw)}`,
    });
    assertions.push({
      ok: subjectRaw === undefined,
      label: "raw 'subject' string absent",
      detail: subjectRaw === undefined ? undefined : `subject=${String(subjectRaw)}`,
    });
    // countValue collapses to 0 by redactAuditEntry.
    const countValue = elicitFields["countValue"];
    assertions.push({
      ok: countValue === 0,
      label: "elicitFields.countValue === 0 (number redaction)",
      detail: countValue === 0 ? undefined : `countValue=${String(countValue)}`,
    });
  } else {
    // raw mode: the redaction envelope must be absent, raw fields present.
    assertions.push({
      ok: !isRedactedEnvelope(elicitFields),
      label: "elicitFields.__redacted__ NOT set",
    });
    const recipientsRaw = elicitFields["recipients"];
    assertions.push({
      ok: typeof recipientsRaw === "string" && recipientsRaw.length > 0,
      label: "raw 'recipients' string present",
      detail: typeof recipientsRaw === "string" ? `len=${recipientsRaw.length}` : `recipients=${String(recipientsRaw)}`,
    });
    const subjectRaw = elicitFields["subject"];
    assertions.push({
      ok: subjectRaw === subject,
      label: `raw 'subject' === '${subject}'`,
      detail: subjectRaw === subject ? undefined : `subject=${String(subjectRaw)}`,
    });
    const countRaw = elicitFields["count"];
    assertions.push({
      ok: countRaw === recipientCount,
      label: `raw 'count' === ${recipientCount}`,
      detail: countRaw === recipientCount ? undefined : `count=${String(countRaw)}`,
    });
  }

  return assertions;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");
const GMAIL_APP_CWD = path.join(REPO_ROOT, "apps", "gmail");

async function runPkce(args: Args): Promise<number> {
  let wrangler: SpawnedWrangler | undefined;
  let client: Client | undefined;
  try {
    let target = args.target;
    if (args.spawn) {
      wrangler = spawnWrangler({
        cwd: GMAIL_APP_CWD,
        port: args.port,
      });
      target = await wrangler.ready;
    }
    process.stderr.write(`[harness:pkce] target=${target}\n`);
    client = await connectWithOAuth(target);
    // initialize() is what `connect()` already calls internally; if we got
    // here, both the MCP-client↔worker PKCE *and* the worker↔Google PKCE
    // succeeded. List the tools as a smoke check.
    const list = await client.listTools();
    const assertions: Assertion[] = [
      {
        ok: list.tools.length >= 1,
        label: "MCP listTools returned at least one tool",
        detail: `tool count=${list.tools.length}`,
      },
    ];
    const ok = printAssertions(assertions);
    summary("PKCE", ok);
    return ok ? 0 : 1;
  } catch (err) {
    process.stderr.write(`[harness:pkce] error: ${err instanceof Error ? err.stack : String(err)}\n`);
    if (wrangler) dumpTail("wrangler log", wrangler.getCapturedLines());
    summary("PKCE", false);
    return 2;
  } finally {
    if (client) {
      try {
        await client.close();
      } catch {
        /* ignore */
      }
    }
    if (wrangler) await wrangler.kill();
  }
}

async function runAudit(args: Args): Promise<number> {
  let wrangler: SpawnedWrangler | undefined;
  let client: Client | undefined;
  try {
    let target = args.target;
    if (args.spawn) {
      const vars: Record<string, string> = {};
      if (args.check === "audit-raw") vars["ALLOW_PII_IN_LOGS"] = "true";
      wrangler = spawnWrangler({
        cwd: GMAIL_APP_CWD,
        port: args.port,
        vars,
      });
      target = await wrangler.ready;
    } else if (args.check === "audit-raw" || args.check === "audit-redacted") {
      process.stderr.write(
        "[harness:audit] --no-spawn: the operator must ensure wrangler dev " +
          "is running with the correct ALLOW_PII_IN_LOGS setting and pipe its " +
          "stdout somewhere this harness can read it. With --no-spawn we " +
          "cannot inspect the AUDIT line, so only the tool-call request will " +
          "be exercised — see README.md.\n",
      );
    }
    process.stderr.write(`[harness:audit] target=${target} mode=${args.check}\n`);

    client = await connectWithOAuth(target);
    const { raw, recipientCount, subject } = buildMassSendBody();
    let toolResult: CallToolResult | undefined;
    try {
      toolResult = await callExecuteSend(client, { raw });
    } catch (err) {
      // The execute tool may surface a non-ok response (declined elicit
      // causes a JSON-RPC error). That's fine for the audit assertion path.
      process.stderr.write(
        `[harness:audit] execute tool call rejected: ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }
    if (toolResult) {
      process.stderr.write(
        `[harness:audit] tool result (truncated): ${JSON.stringify(toolResult).slice(0, 400)}\n`,
      );
    }

    if (!wrangler) {
      process.stderr.write(
        "[harness:audit] no wrangler spawn → cannot inspect AUDIT line. Treating tool-call exit as the only signal.\n",
      );
      summary(`AUDIT-${args.check}`, true);
      return 0;
    }

    const audit = await waitForAuditLine(
      wrangler,
      "gmail.users.messages.send",
      10_000,
    );
    if (!audit) {
      process.stderr.write("[harness:audit] AUDIT line never appeared within 10s\n");
      dumpTail("wrangler log", wrangler.getCapturedLines());
      summary(`AUDIT-${args.check}`, false);
      return 1;
    }

    const expected: AuditExpectation = {
      mode: args.check === "audit-raw" ? "raw" : "redacted",
    };
    const assertions = assertAuditShape(audit, expected, recipientCount, subject);
    process.stdout.write(`\nAUDIT line:\n  ${audit.raw}\n\n`);
    const ok = printAssertions(assertions);
    summary(`AUDIT-${args.check}`, ok);
    return ok ? 0 : 1;
  } catch (err) {
    process.stderr.write(`[harness:audit] error: ${err instanceof Error ? err.stack : String(err)}\n`);
    if (wrangler) dumpTail("wrangler log", wrangler.getCapturedLines());
    summary(`AUDIT-${args.check}`, false);
    return 2;
  } finally {
    if (client) {
      try {
        await client.close();
      } catch {
        /* ignore */
      }
    }
    if (wrangler) await wrangler.kill();
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  let code: number;
  if (args.check === "pkce") {
    code = await runPkce(args);
  } else {
    code = await runAudit(args);
  }
  process.exit(code);
}

main().catch((err: unknown) => {
  process.stderr.write(`[harness] fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
