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

# A Worker reachable on BOTH workers.dev and a custom domain needs an Access app
# per hostname — an Access application matches on host+path, so the app above
# leaves a custom-domain `/authorize` completely ungated. Any worker declaring a
# `custom_domain` route in its wrangler.jsonc must set `custom_domain` here too.
#
# Path scope is deliberately `/authorize` only, same as the workers.dev app:
# `/mcp`, `/token`, `/register` and `/staging/*` are called server-side by the
# MCP client, which cannot complete a browser Access login, and `/callback` is
# already gated by the KV-stored `state` token minted at `/authorize`.
resource "cloudflare_zero_trust_access_application" "authorize_custom_domain" {
  count = var.custom_domain == "" ? 0 : 1

  account_id                = var.cloudflare_account_id
  name                      = "${var.worker_name}-authorize-custom-domain"
  domain                    = "${var.custom_domain}/authorize"
  type                      = "self_hosted"
  session_duration          = "24h"
  app_launcher_visible      = false
  auto_redirect_to_identity = true
  allowed_idps              = var.access_allowed_idp_ids
}

resource "cloudflare_zero_trust_access_policy" "authorize_custom_domain" {
  count = var.custom_domain == "" ? 0 : 1

  account_id     = var.cloudflare_account_id
  application_id = cloudflare_zero_trust_access_application.authorize_custom_domain[0].id
  name           = "${var.worker_display_name} Authorize (custom domain)"
  precedence     = 1
  decision       = "allow"

  include {
    email = var.allowed_emails
  }
}
