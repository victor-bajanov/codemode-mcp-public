# codemode-mcp

Cloudflare Worker MCP servers that expose third-party SaaS APIs (Gmail,
Xero, …) to MCP clients (Claude.ai, Claude Code, etc) using Cloudflare's
**Code Mode** pattern: each provider ships a `search` / `execute` pair and
the client writes JavaScript that runs in a sandboxed sub-Worker, instead
of issuing one MCP tool call per API operation.

Cloudflare's [`agents`](https://github.com/cloudflare/agents) and
[`@cloudflare/codemode`](https://www.npmjs.com/package/@cloudflare/codemode)
libraries supply the runtime primitives — Durable-Object-backed MCP agent,
sandboxed `worker_loader`, `openApiMcpServer` over an OpenAPI spec. This
repo wraps them into a turn-key, single-operator **provider scaffold**:

- **`setupProvider(providerDefinition)`** assembles a deployable Worker
  from a provider definition. OAuth endpoints (`/authorize`, `/token`,
  `/register`, `/mcp` via `@cloudflare/workers-oauth-provider`), the MCP
  agent Durable Object, audit logging, and elicitation glue are all wired
  for you. New providers are typically ~50–100 lines.
- **Per-operation surface review** — each provider declares an explicit
  allow-list of OpenAPI operations with reviewer notes alongside the code,
  so security-relevant changes show up in code review rather than slipping
  in via a spec bump.
- **Spec loaders** for the quirks of major SaaS APIs (Google Discovery →
  OpenAPI, multi-spec merging for Xero).
- **OpenTofu module** for the per-app infra — one KV namespace plus a
  Cloudflare Access policy gating the MCP endpoint to a single operator.
  One `tofu apply` per provider.
- **Reference Gmail and Xero deployments** with vetted surface reviews to
  copy from.

The whole stack is designed for personal/operator-of-one use: OAuth tokens
live in a per-app KV namespace and the MCP endpoint is fronted by
Cloudflare Access — no multi-tenant accounting, no shared user store.

If you've never used Cloudflare before, read
[`docs/cloudflare-getting-started.md`](./docs/cloudflare-getting-started.md)
first — that covers the platform concepts, account setup, and CLI tooling
this repo assumes.

## Repository layout

```
apps/
  gmail/                  deployable Worker — Gmail
  xero/                   deployable Worker — Xero (Demo Company)
packages/
  scaffold/               provider-agnostic Worker scaffold (OAuth, MCP agent,
                          request-handler, audit, elicitation)
  providers/gmail/        Gmail provider definition + surface review + spec
  providers/xero/         Xero provider definition + surface review + spec
  shared/                 cross-package types (surface review, elicit)
  spec-loaders/           OpenAPI spec ingestion (Google Discovery, Xero merge)
infra/                    OpenTofu — KV namespace + Cloudflare Access policy
                          (one module instance per deployed app)
scripts/                  diagnostics, repros, measurement helpers
docs/                     specs, plans, runbooks, this guide
```

Each `apps/*` is a thin entrypoint:

```ts
// apps/gmail/src/index.ts
import { setupProvider } from "@local/scaffold";
import { gmailProvider } from "@local/providers-gmail";

export const { McpAgent: GmailMCP, default: OAuthHandler } = setupProvider(gmailProvider);
export default OAuthHandler;
```

`setupProvider` returns the Durable Object class (the MCP agent) and an
`OAuthProvider` handler wired to `/authorize`, `/token`, `/register`, `/mcp`.

## Prerequisites

- **Node 20+** and **pnpm 9** (the repo pins `pnpm@9.12.0` via `packageManager`).
- **Wrangler 4** — installed per-app via `devDependencies`; invoke with
  `npx wrangler` or via the package scripts.
- **OpenTofu 1.6+** (only if you use `infra/` to provision Cloudflare
  resources). `brew install opentofu`.
- **1Password CLI** (`op`), optional — the OpenTofu setup reads secrets from
  1Password via `op run --env-file=.env`. You can substitute literal env vars
  if you don't use 1Password.
- A **Cloudflare account** with the workers.dev subdomain reserved and
  Zero Trust enabled. See the
  [getting-started guide](./docs/cloudflare-getting-started.md) if you don't
  have these yet.
- A **Google Cloud OAuth client** (for Gmail) and/or a **Xero OAuth app**
  (for Xero). See the per-app sections below.

## Install

```
pnpm install
```

This installs all workspaces.

## Deploy: end-to-end walkthrough

The flow is the same for every app:

1. **Provision Cloudflare resources** (KV namespace + Access policy on
   `/authorize`).
2. **Register the OAuth app** with the upstream provider (Google / Xero).
3. **Configure the Worker** (paste the KV id; set Worker secrets).
4. **`wrangler deploy`**.
5. **Connect from your MCP client**.

The next sections walk through this for each app.

### Provision Cloudflare resources (OpenTofu)

The `infra/` OpenTofu stack provisions, per app:

- `cloudflare_workers_kv_namespace` — for `OAUTH_KV`.
- `cloudflare_zero_trust_access_application` on `/authorize` —
  self-hosted Access app.
- `cloudflare_zero_trust_access_policy` — allow-list by email through an
  allowed identity provider.

```
cd infra
cp .env.example .env
```

Edit `.env`:

- If you use 1Password, leave the `op://...` references and adjust paths to
  match your vault layout.
- If you don't, replace each `op://...` value with the literal credential
  and remove the `op run` prefix from the commands below.
- Set `TF_VAR_cloudflare_workers_subdomain`,
  `TF_VAR_allowed_emails` (JSON list), and
  `TF_VAR_access_allowed_idp_ids` (JSON list of Cloudflare Access IdP UUIDs
  — find them at Zero Trust → Settings → Authentication; the UUID is in the
  URL when you edit an IdP).

Apply:

```
op run --env-file=.env -- tofu init
op run --env-file=.env -- tofu plan
op run --env-file=.env -- tofu apply
```

Note the outputs — you need `*_oauth_kv_id` for the next step.

### App: `gmail`

1. **Paste the KV id** into `apps/gmail/wrangler.jsonc` at
   `kv_namespaces[0].id`. (The committed value points at the existing
   namespace; replace it with yours.)

2. **Create a Google Cloud OAuth client**:
   - Console → APIs & Services → Credentials → Create OAuth client ID
     (Web application).
   - Authorized redirect URI:
     `https://gmail.<your-subdomain>.workers.dev/callback`
   - Enable the Gmail API on the same project.
   - OAuth consent screen: add yourself as a Test user (External, Testing
     mode is fine for a single-operator deployment).
   - Scopes used by the provider live in
     `packages/providers/gmail/src/index.ts → gmailProvider.oauth.scopes`.

3. **Set Worker secrets**:

   ```
   cd apps/gmail
   npx wrangler secret put GOOGLE_CLIENT_ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET
   npx wrangler secret put COOKIE_ENCRYPTION_KEY   # any 32+ byte random string
   ```

4. **Deploy**:

   ```
   pnpm --filter @apps/gmail typecheck
   pnpm --filter @apps/gmail deploy
   # or from repo root: pnpm deploy:gmail
   ```

5. **Connect from Claude.ai**:
   - Claude.ai → Settings → Connectors → Add custom MCP.
   - URL: `https://gmail.<your-subdomain>.workers.dev/mcp`.
   - The first `/authorize` redirect hits Cloudflare Access (must match an
     allowed email through an allowed IdP), then Google consent.

### App: `xero`

See [`apps/xero/README.md`](./apps/xero/README.md)
for the per-app specifics (Xero OAuth registration, single-tenant grant
requirement, spec re-merge procedure).

Short version:

1. Paste the Xero KV id into `apps/xero/wrangler.jsonc`.
2. Register a Xero OAuth app at developer.xero.com with redirect URI
   `https://xero.<your-subdomain>.workers.dev/callback`.
3. Secrets: `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `COOKIE_ENCRYPTION_KEY`.
4. `pnpm --filter @apps/xero deploy`.

### Deploying a dev variant

Each provider Worker has a paired `-dev` deployment (`gmail-dev`, `xero-dev`)
that points at a different upstream tenant and a different Cloudflare Access
application, so you can connect Claude.ai to a dev MCP connector without
disturbing the prod connector. The same `src/index.ts` deploys to both
environments; isolation is achieved entirely via Wrangler's `env.dev` override
and a parallel OpenTofu module.

One-time setup (per provider):

1. **Provision the dev KV + Access policy.** From repo root:

   ```
   op run --env-file=.env -- tofu -chdir=infra apply
   ```

   This adds the `gmail-dev` / `xero-dev` resources alongside prod; existing
   prod state is unchanged.

2. **Paste the dev KV id.** Run:

   ```
   tofu -chdir=infra output -raw gmail_dev_oauth_kv_id
   # and
   tofu -chdir=infra output -raw xero_dev_oauth_kv_id
   ```

   Paste each value into the corresponding
   `apps/<provider>/wrangler.jsonc` at `env.dev.kv_namespaces[0].id`,
   replacing the `PASTE_FROM_tofu_output_*` placeholder.

3. **Register a separate OAuth app** at Google / Xero with redirect URI
   `https://<provider>-dev.<your-subdomain>.workers.dev/callback`. This must
   be a different client from the prod one — Google rejects mismatched
   redirect URIs, and you want a distinct consent screen anyway.

4. **Set the dev Worker secrets** (note the `--env dev` flag on every
   `wrangler secret put` — omitting it puts the secret on the prod Worker):

   ```
   cd apps/gmail
   npx wrangler --env dev secret put GOOGLE_CLIENT_ID
   npx wrangler --env dev secret put GOOGLE_CLIENT_SECRET
   npx wrangler --env dev secret put COOKIE_ENCRYPTION_KEY
   ```

   ```
   cd apps/xero
   npx wrangler --env dev secret put XERO_CLIENT_ID
   npx wrangler --env dev secret put XERO_CLIENT_SECRET
   npx wrangler --env dev secret put COOKIE_ENCRYPTION_KEY
   ```

5. **Deploy** from the repo root:

   ```
   pnpm deploy:gmail:dev
   # or
   pnpm deploy:xero:dev
   ```

6. **Connect from Claude.ai** → Settings → Connectors → Add custom MCP:
   `https://<provider>-dev.<your-subdomain>.workers.dev/mcp`. The first
   `/authorize` hit prompts a fresh Cloudflare Access session for the new
   hostname (separate Access app, separate cookie) — this is expected.

The prod and dev Workers share the same Durable Object class names
(`GmailMCP`, `XeroMCP`), but Wrangler scopes DO namespaces
per-environment, so dev grant state is fully isolated from prod.

## Development

From the repo root:

```
pnpm typecheck     # all packages
pnpm test          # all packages
pnpm build         # all packages (no-op for most; spec loaders generate)
```

Per-app dev server:

```
pnpm --filter @apps/gmail dev
```

Note: local `wrangler dev` does not exercise Cloudflare Access. Test the
Access policy by hitting the deployed `/authorize` URL.

## Operational reference

- **Observability**: each `wrangler.jsonc` has `observability.enabled = true`
  with full head sampling. Tail logs at Cloudflare dashboard → Workers →
  your worker → Logs, or with `npx wrangler tail`. To ship logs elsewhere,
  add a [Tail Worker](https://developers.cloudflare.com/workers/observability/logs/tail-workers/)
  via `tail_consumers` in `wrangler.jsonc` (forward to a SIEM, Datadog,
  BetterStack, or your own collector), or enable
  [Workers Logpush](https://developers.cloudflare.com/workers/observability/logs/logpush/)
  for direct delivery to R2, S3, or supported HTTP endpoints (Workers Paid plan).
- **Audit**: tool invocations log structured audit entries via
  `packages/scaffold/src/audit.ts` — searchable in Workers Observability.
- **Security runbook**: see [`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) for the audit-log redaction default, the deliberate PII-logging unlock path, and KV-state inspection.
- **Surface review**: each provider exports a `surfaceReview` allow-list
  classifying every `operationId` as `allow` / `elicit` / `deny`. New ops
  added by a spec re-sync are implicit-deny until classified.
- **Refresh-token rotation**: handled in `packages/scaffold/src/refresh.ts`.
  Xero rotates on every use (60-day idle expiry); Google's are long-lived.

## Adding a new provider

1. Create `packages/providers/<name>/` mirroring `gmail` or `xero`:
   `index.ts` (the `ApiProvider` value), `surface-review.ts`, `spec.json`,
   `elicit-renderers.ts`.
2. Add a spec loader under `packages/spec-loaders/` if the spec needs
   transformation.
3. Add an app under `apps/<deployment>/` with `wrangler.jsonc`,
   `package.json`, and a four-line `src/index.ts`.
4. Add a `module "<name>"` block to `infra/main.tf` and corresponding
   outputs to `infra/outputs.tf` (OpenTofu reads the same `.tf` files).
5. Run `pnpm install` (workspace re-link), `pnpm typecheck`, deploy as
   above.

## Where to look next

- `docs/cloudflare-getting-started.md` — onboarding for Cloudflare newcomers.
- `apps/xero/README.md` — worked example of per-app setup.
- `infra/README.md` — OpenTofu stack detail.
- `packages/scaffold/SECURITY.md` — security model + the audit/redaction defaults.
