output "gmail_oauth_kv_id" {
  value       = module.gmail.oauth_kv_id
  description = "Paste into apps/gmail/wrangler.jsonc kv_namespaces[0].id."
}

output "gmail_authorize_url" {
  value       = module.gmail.authorize_url
  description = "Visit in a browser to test the Gmail Access policy."
}

output "gmail_access_application_id" {
  value       = module.gmail.access_application_id
  description = "Access application ID for the gmail Worker."
}

output "gmail_custom_domain_authorize_url" {
  value       = module.gmail.custom_domain_authorize_url
  description = "Visit in a browser to test the Gmail Access policy on the custom domain."
}

output "gmail_custom_domain_access_application_id" {
  value       = module.gmail.custom_domain_access_application_id
  description = "Access application ID for the gmail Worker's custom domain."
}

output "xero_oauth_kv_id" {
  value       = module.xero.oauth_kv_id
  description = "Paste into apps/xero/wrangler.jsonc kv_namespaces[0].id."
}

output "xero_authorize_url" {
  value       = module.xero.authorize_url
  description = "Visit in a browser to test the Xero Access policy."
}

output "xero_access_application_id" {
  value       = module.xero.access_application_id
  description = "Access application ID for the xero Worker."
}




output "gmail_dev_oauth_kv_id" {
  value       = module.gmail_dev.oauth_kv_id
  description = "Paste into apps/gmail/wrangler.jsonc env.dev.kv_namespaces[0].id."
}

output "gmail_dev_authorize_url" {
  value       = module.gmail_dev.authorize_url
  description = "Visit in a browser to test the gmail-dev Access policy."
}

output "gmail_dev_access_application_id" {
  value       = module.gmail_dev.access_application_id
  description = "Access application ID for the gmail-dev Worker."
}

output "gmail_tester_oauth_kv_id" {
  value       = module.gmail_tester.oauth_kv_id
  description = "Paste into apps/gmail/wrangler.jsonc env.tester.kv_namespaces[0].id."
}

output "gmail_tester_authorize_url" {
  value       = module.gmail_tester.authorize_url
  description = "Visit in a browser to test the gmail-tester Access policy."
}

output "gmail_tester_access_application_id" {
  value       = module.gmail_tester.access_application_id
  description = "Access application ID for the gmail-tester Worker."
}

output "xero_dev_oauth_kv_id" {
  value       = module.xero_dev.oauth_kv_id
  description = "Paste into apps/xero/wrangler.jsonc env.dev.kv_namespaces[0].id."
}

output "xero_dev_authorize_url" {
  value       = module.xero_dev.authorize_url
  description = "Visit in a browser to test the xero-dev Access policy."
}

output "xero_dev_access_application_id" {
  value       = module.xero_dev.access_application_id
  description = "Access application ID for the xero-dev Worker."
}



