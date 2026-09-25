# Changelog

Curated notes for each public release. Newest first. (The auto-generated commit list for a release lives in that release's PR on the public mirror; this file is the readable summary.)

## v1.0.1 — 2026-09-25

**Optical: self-contained README.** `apps/optical/README.md` no longer links to internal design and planning docs that are not in the public repo. The setup prerequisites are now written out in full: where to set your deployment's endpoints, why it must be on a Custom Domain, and two `curl` checks (`/v1/tasks` and `/oauth/userinfo`) that confirm it serves the API the vendored spec expects. The example PKCE client registration now uses the scopes the provider actually requests (`scheduler:read scheduler:write`). The old `read write` value would have failed at `/oauth/authorize` with `invalid_scope`.

## v1.0.0 — 2026-09-24

**Optical provider ships publicly.** This is the headline change, and the reason for the 1.0 version: it is the first public release with all three providers (Gmail + Calendar, Xero, Optical). Optical is a separate, self-hosted scheduling backend. You describe work as tasks with timing constraints, grouped into projects or generated from recurring templates, and a solver packs them into a week that you preview, accept, and commit to Google Calendar. The codemode-mcp provider (`packages/providers/optical`, app `apps/optical`) is published as a reference: it does not come with a hosted backend, and its endpoints ship as `example.com` placeholders. Point it at your own Optical deployment by editing the provider's `apiBaseUrl` and OAuth URLs, or per environment with the `API_BASE_URL_OVERRIDE` / `OAUTH_{AUTHORIZE,TOKEN,USERINFO}_URL_OVERRIDE` Wrangler vars. The app ships with `prod` and `dev` environments, OpenTofu modules for both, and a `scripts/bootstrap-optical.sh` that runs the Tofu apply, KV-id paste, secrets, and deploy in one pass.

**Optical: API surface.** The vendored spec exposes 46 operations across: tasks, templates and projects (CRUD); planning (`resolve` a date window into a proposed plan, list and inspect pending plans, `acceptPlan` / `commit` to write it to Google Calendar, read the committed schedule); scheduling preferences (business hours, meeting policy, per-context config, and solver weights, each with update and reset-to-default); calendar busy feeds (create, list, edit, delete, regenerate secret, where create and regenerate return a single-use `reveal_url` so the feed secret never crosses the tool-call boundary); a public booking page (read and update its config, list bookings taken against it; the new `max_horizon_days` setting lets bookers page further ahead than one window); meeting polls (create, read, update, nudge, cancel, force-resolve); and change tracking (`subscribeWebhook` for a Google Calendar watch channel, `replanNow` to re-resolve on demand). The spec's `info.description` feeds the `execute` hint and the `docs` tool, so the workflow prose tracks the upstream API when you re-vendor it.

**Optical: surface-review defaults.** 44 of the 46 operations are `allow`. Two are `deny`: `getCalendarAccessToken`, which mints a raw Google OAuth token and needs a privileged scope the provider never requests, and `googleCalendarWebhook`, the machine-to-machine push receiver that would let the agent spoof calendar-change notifications. These are not intended to be used by the MCP agent frontend. Writes are kept at `allow` rather than `elicit` because Claude.ai does not render elicitation prompts and would silently soft-deny them. The reviewer notes flag the operations with the widest reach (`updateBookingPage`, which publishes a page anyone can book against; `nudgeMeetingPoll` and `resolveMeetingPoll`, which email third parties) as the first to move to `elicit` once client support lands.

**Optical: OAuth.** The provider uses authorization code + PKCE (S256) against a client registered on your Optical deployment, requesting `scheduler:read scheduler:write`. Refresh tokens rotate on every exchange and go through the shared TokenBroker Durable Object, like Xero, with a 90-day idle expiry. Optical's API is pure JSON, so the app has no attachment-staging bindings.

**Gmail: Subject header repair.** Sandbox code sometimes composed raw MIME with a double-applied UTF-8 wrapper, so non-ASCII characters in the Subject (em dashes, for example) arrived as mojibake. The provider now repairs the Subject host-side on `messages.send`, `drafts.create`, `drafts.update` and `drafts.send`: it unwinds the mis-encoded layers (strict-decode guarded, so genuine Latin-1 text is left alone) and re-emits the header as RFC 2047 encoded-words. The repair runs through a new fail-open `normalizeBody` hook on surface-review entries, applied before inspection, so the elicit dialog and the upstream send see the same bytes.

**Release notes.** This curated `CHANGELOG.md` now ships with each public release.

## v0.4.0 — 2026-08-19

**Docs surface & description budget** — the headline change. Tool descriptions were blowing past what clients comfortably ingest, so the scaffold now generates *compact* tool descriptions that fit a 1,800-character budget, with the full reference moved behind a new `codemode.docs(section)` tool (callable with a bare string, no-arg for the overview). A `buildProviderDocs` builder assembles per-provider documentation from the spec at init time, providers can contribute a `compactHint` (Gmail, Xero), and a shared description-budget test battery plus codemode/SDK drift guards pin the contract so upstream bumps or spec regenerations can't silently blow the budget again.

**Surface-review transparency** — every operation in a provider's spec is now annotated with its surface-review status (`[ACCESS: …]` markers), so the model can see up front whether a call is allowed, needs interactive approval, or is denied — including the caveat that call-time escalation to elicit simply fails on clients without elicitation support. The annotation marker is guarded against collisions with upstream spec prose.

**Gmail: Calendar surface** — the Google Calendar half of the Gmail provider is now exposed to clients: same connection, Calendar reachable under its own path prefix with namespaced operationIds.

**Gmail: per-deployment outbound allowlist & tester deployment** — the outbound recipient allowlist is now resolved per deployment rather than baked in provider-wide, enforcement happens at send time (drafts can be composed freely), and there's a tester deployment variant with its own bootstrap script for onboarding an external tester.

**Attachment staging fixes** — downloads now honor content-type overrides, set `Content-Disposition` properly, and the download path is discoverable by the model instead of needing to be guessed.

**Per-worker Access grants** — `allowed_emails` is now the operator baseline reaching every worker, and a new `extra_allowed_emails` map grants additional addresses per worker only — so a tester can be given `/authorize` on one deployment without inheriting access to the whole fleet.

**Xero** — upstream API rate-limit information is surfaced to the MCP client so the model can back off instead of blindly retrying.

**Scaffold** — `codemode.request` accepts sandbox-supplied `ctx.headers`; several robustness fixes from review (no-arg `codemode.docs()` RPC null-marshalling, docs-tool section enum narrowed to the provider's actual sections).
