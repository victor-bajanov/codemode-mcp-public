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

module "gmail" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "gmail"
  worker_display_name          = "Gmail MCP"
  allowed_emails               = var.allowed_emails
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "xero" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "xero"
  worker_display_name          = "Xero MCP"
  allowed_emails               = var.allowed_emails
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}


module "gmail_dev" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "gmail-dev"
  worker_display_name          = "Gmail MCP (dev)"
  allowed_emails               = var.allowed_emails
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}

module "xero_dev" {
  source                       = "./modules/worker"
  cloudflare_account_id        = var.cloudflare_account_id
  cloudflare_workers_subdomain = var.cloudflare_workers_subdomain
  worker_name                  = "xero-dev"
  worker_display_name          = "Xero MCP (dev)"
  allowed_emails               = var.allowed_emails
  access_allowed_idp_ids       = var.access_allowed_idp_ids
}


# State migration from the previous app naming (`gmail` /
# `xero`). The 1.1+ `moved` block re-anchors existing resources
# in state without destroy+recreate. The worker_name attribute change still
# triggers in-place updates on KV title, Access app name + domain, and the
# Access policy name — all safe in-place. Once `tofu plan` reports no
# movements pending, these can be deleted.

