terraform {
  required_version = ">= 1.6.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }
}

# Auth via env vars set by `op run --env-file=.env`:
#   CLOUDFLARE_API_TOKEN  (scoped token minted by infra/create-api-token.sh —
#                          same token is used by wrangler deploy)
provider "cloudflare" {}

# `custom_domain` matches routes[0].pattern in apps/gmail/wrangler.jsonc. gmail
# is the only deployment with a custom-domain route; every other module below is
# workers.dev-only and needs no second Access app.
module "gmail" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "gmail"
  worker_display_name          = "Gmail MCP"
  custom_domain                = "gmail-codemode-mcp.example.com"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "gmail", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "xero" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "xero"
  worker_display_name          = "Xero MCP"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "xero", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "optical" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "optical"
  worker_display_name          = "Optical MCP"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "optical", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "gmail_dev" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "gmail-dev"
  worker_display_name          = "Gmail MCP (dev)"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "gmail-dev", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

# Tester deployment: workers.dev-only, own KV/Access app. The tester's email
# is granted via TF_VAR_extra_allowed_emails["gmail-tester"] in .env so it
# stays scoped to this worker (and out of the tracked tree).
module "gmail_tester" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "gmail-tester"
  worker_display_name          = "Gmail MCP (tester)"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "gmail-tester", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "xero_dev" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "xero-dev"
  worker_display_name          = "Xero MCP (dev)"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "xero-dev", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "optical_dev" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "optical-dev"
  worker_display_name          = "Optical MCP (dev)"
  allowed_emails               = concat(var.allowed_emails, lookup(var.extra_allowed_emails, "optical-dev", []))
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

# State migration from the previous app naming (`gmail` /
# `xero`). The 1.1+ `moved` block re-anchors existing resources
# in state without destroy+recreate. The worker_name attribute change still
# triggers in-place updates on KV title, Access app name + domain, and the
# Access policy name — all safe in-place. Once `tofu plan` reports no
# movements pending, these can be deleted.

