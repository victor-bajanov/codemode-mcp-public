variable "cloudflare_account_id" {
  description = "Cloudflare account ID. Set via TF_VAR_cloudflare_account_id (1Password reference in .env)."
  type        = string
}

variable "cloudflare_workers_subdomain" {
  description = "Your workers.dev subdomain — the <subdomain> in <subdomain>.workers.dev. Find under Workers & Pages → your account name."
  type        = string
}

variable "allowed_emails" {
  description = "Operator baseline: email addresses allowed through Cloudflare Access on /authorize for EVERY worker in this stack. Keep this to the addresses that should reach all of them — per-worker grants belong in extra_allowed_emails, not here."
  type        = list(string)
}

# Blast radius: `allowed_emails` reaches every worker, so granting one tester
# access to one deployment used to mean granting them /authorize on all six.
# They could then run an OAuth flow against, say, xero and hold a grant on
# infra you pay for. This map keeps such grants scoped to the worker that
# needs them.
#
# Keys are `worker_name` as passed to the module ("gmail", "optical-dev", …),
# NOT the module label — those differ for the dev deployments. An unknown key
# is silently ignored rather than erroring, so a typo shows up as a missing
# grant at the Access challenge; grep the plan output if a grant seems absent.
#
# Values are email addresses, so this is set in .env (untracked, and .env is on
# the release denylist) rather than being written literally here — the tracked
# tree stays free of addresses that would need their own redaction rules.
variable "extra_allowed_emails" {
  description = "Per-worker additional Access emails, keyed by worker_name (e.g. {\"optical\" = [\"tester@example.com\"]}). Merged on top of allowed_emails for that worker only. Set via TF_VAR_extra_allowed_emails."
  type        = map(list(string))
  default     = {}
}

variable "access_allowed_idp_ids" {
  description = "Cloudflare Access Identity Provider UUIDs allowed to authenticate. Look up at Zero Trust → Settings → Authentication; UUID is in the URL when editing the IdP."
  type        = list(string)
}
