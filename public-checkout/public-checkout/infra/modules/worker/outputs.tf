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
