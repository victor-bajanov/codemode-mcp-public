terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }
}

resource "cloudflare_workers_kv_namespace" "oauth" {
  account_id = var.cloudflare_account_id
  title      = "${var.worker_name}-OAUTH_KV"
}

resource "cloudflare_zero_trust_access_application" "authorize" {
  account_id                = var.cloudflare_account_id
  name                      = "${var.worker_name}-authorize"
  domain                    = "${var.worker_name}.${var.cloudflare_workers_subdomain}.workers.dev/authorize"
  type                      = "self_hosted"
  session_duration          = "24h"
  app_launcher_visible      = false
  auto_redirect_to_identity = true
  allowed_idps              = var.access_allowed_idp_ids
}

resource "cloudflare_zero_trust_access_policy" "authorize" {
  account_id     = var.cloudflare_account_id
  application_id = cloudflare_zero_trust_access_application.authorize.id
  name           = "${var.worker_display_name} Authorize"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_emails
  }
}
