variable "cloudflare_account_id" {
  description = "Cloudflare account ID. Set via TF_VAR_cloudflare_account_id (1Password reference in .env)."
  type        = string
}

variable "cloudflare_workers_subdomain" {
  description = "Your workers.dev subdomain — the <subdomain> in <subdomain>.workers.dev. Find under Workers & Pages → your account name."
  type        = string
}

variable "allowed_emails" {
  description = "Email addresses allowed through Cloudflare Access on /authorize for ALL workers in this stack. If you need per-worker policies, split the variable and pass distinct lists into each module instance."
  type        = list(string)
}

variable "access_allowed_idp_ids" {
  description = "Cloudflare Access Identity Provider UUIDs allowed to authenticate. Look up at Zero Trust → Settings → Authentication; UUID is in the URL when editing the IdP."
  type        = list(string)
}
