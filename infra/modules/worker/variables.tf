variable "cloudflare_account_id" {
  description = "Cloudflare account ID."
  type        = string
}

variable "cloudflare_workers_subdomain" {
  description = "<subdomain> in <subdomain>.workers.dev."
  type        = string
}

variable "worker_name" {
  description = "Worker script name (matches name in apps/<deployment>/wrangler.jsonc)."
  type        = string
}

variable "worker_display_name" {
  description = "Human-readable label, used in the Access policy name."
  type        = string
}

variable "custom_domain" {
  description = "Custom domain this Worker also serves on (the `custom_domain` route in apps/<deployment>/wrangler.jsonc), e.g. \"gmail-codemode-mcp.example.com\". Empty means workers.dev only. When set, a second Access application gates /authorize on that hostname — without it the custom domain bypasses Access entirely."
  type        = string
  default     = ""
}

variable "allowed_emails" {
  description = "Email addresses allowed through Cloudflare Access on /authorize."
  type        = list(string)
}

variable "access_allowed_idp_ids" {
  description = "Cloudflare Access Identity Provider UUIDs allowed to authenticate."
  type        = list(string)
}
