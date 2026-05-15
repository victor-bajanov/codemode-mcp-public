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

variable "allowed_emails" {
  description = "Email addresses allowed through Cloudflare Access on /authorize."
  type        = list(string)
}

variable "access_allowed_idp_ids" {
  description = "Cloudflare Access Identity Provider UUIDs allowed to authenticate."
  type        = list(string)
}
