# Changelog

Curated, human-written notes for each public release. Newest first. (The auto-generated commit list for a release lives in that release's PR on the public mirror; this file is the readable summary.)

## v0.4.0 — 2026-08-19

**Docs surface & description budget** — the headline change. Tool descriptions were blowing past what clients comfortably ingest, so the scaffold now generates *compact* tool descriptions that fit a 1,800-character budget, with the full reference moved behind a new `codemode.docs(section)` tool (callable with a bare string, no-arg for the overview). A `buildProviderDocs` builder assembles per-provider documentation from the spec at init time, providers can contribute a `compactHint` (Gmail, Xero), and a shared description-budget test battery plus codemode/SDK drift guards pin the contract so upstream bumps or spec regenerations can't silently blow the budget again.

**Surface-review transparency** — every operation in a provider's spec is now annotated with its surface-review status (`[ACCESS: …]` markers), so the model can see up front whether a call is allowed, needs interactive approval, or is denied — including the caveat that call-time escalation to elicit simply fails on clients without elicitation support. The annotation marker is guarded against collisions with upstream spec prose.

**Gmail: Calendar surface** — the Google Calendar half of the Gmail provider is now exposed to clients: same connection, Calendar reachable under its own path prefix with namespaced operationIds.

**Gmail: per-deployment outbound allowlist & tester deployment** — the outbound recipient allowlist is now resolved per deployment rather than baked in provider-wide, enforcement happens at send time (drafts can be composed freely), and there's a tester deployment variant with its own bootstrap script for onboarding an external tester.

**Attachment staging fixes** — downloads now honor content-type overrides, set `Content-Disposition` properly, and the download path is discoverable by the model instead of needing to be guessed.

**Per-worker Access grants** — `allowed_emails` is now the operator baseline reaching every worker, and a new `extra_allowed_emails` map grants additional addresses per worker only — so a tester can be given `/authorize` on one deployment without inheriting access to the whole fleet.

**Xero** — upstream API rate-limit information is surfaced to the MCP client so the model can back off instead of blindly retrying.

**Scaffold** — `codemode.request` accepts sandbox-supplied `ctx.headers`; several robustness fixes from review (no-arg `codemode.docs()` RPC null-marshalling, docs-tool section enum narrowed to the provider's actual sections).
