output "oauth_kv_id" {
  value       = cloudflare_workers_kv_namespace.oauth.id
  description = "Paste into wrangler.jsonc kv_namespaces[0].id for this worker."
}

output "authorize_url" {
  value       = "https://${cloudflare_zero_trust_access_application.authorize.domain}"
  description = "Visit in a browser to test the Cloudflare Access policy for this worker."
}

output "access_application_id" {
  value       = cloudflare_zero_trust_access_application.authorize.id
  description = "ID of the Access application — useful for linking IdPs in the dashboard."
}

output "custom_domain_authorize_url" {
  value       = one(cloudflare_zero_trust_access_application.authorize_custom_domain[*].domain) == null ? null : "https://${one(cloudflare_zero_trust_access_application.authorize_custom_domain[*].domain)}"
  description = "Custom-domain /authorize URL — visit in a browser to verify the Access policy. Null when this worker has no custom domain."
}

output "custom_domain_access_application_id" {
  value       = one(cloudflare_zero_trust_access_application.authorize_custom_domain[*].id)
  description = "ID of the custom-domain Access application. Null when this worker has no custom domain."
}
