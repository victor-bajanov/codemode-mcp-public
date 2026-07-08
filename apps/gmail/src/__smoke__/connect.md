# Slice 1 connectivity runbook

## 1. Burner Gmail
1. Go to https://accounts.google.com/signup, create a new account (e.g. `you-burner@example.com`).
2. Enable 2FA.
3. Send a few emails from your real account to this one so it has data to query.

## 2. Google Cloud project + OAuth client
1. Go to https://console.cloud.google.com/, create a new project named `gmail-mcp-personal`.
2. APIs & Services → Library → Enable "Gmail API".
3. APIs & Services → OAuth consent screen → User Type: External → leave in "Testing" mode.
4. Add your burner email as a Test User.
5. Add the scope: `https://www.googleapis.com/auth/gmail.modify` plus `openid`, `email`, `profile`.
6. Credentials → Create Credentials → OAuth client ID → Web application.
7. Authorised redirect URIs: `https://gmail.<your-account>.workers.dev/callback`
   (also add `http://localhost:8787/callback` for `wrangler dev` testing).
8. Save the Client ID and Client Secret — you'll paste these into `wrangler secret put` in §5.

## 3. Cloudflare resources (tofu)

The KV namespace and Cloudflare Access app + policy are managed under `infra/`. See `infra/README.md` for full setup. TL;DR:

```bash
cd infra
cp .env.example .env
# Edit .env: TF_VAR_cloudflare_workers_subdomain, TF_VAR_allowed_email.
op run --env-file=.env -- tofu init
op run --env-file=.env -- tofu apply
```

After apply, note the `oauth_kv_id` output and paste it into `apps/gmail/wrangler.jsonc` at `kv_namespaces[0].id` (replacing the `0000…aaaa` placeholder).

You also need to manually link a Google IdP at Zero Trust → Settings → Authentication → Add Login Method → Google before the Access policy can authenticate anyone (one-time).

## 4. First deploy

```bash
cd apps/gmail
npx wrangler deploy
```

This creates the Worker script `gmail` on Cloudflare's side and reserves the `gmail.<your-account>.workers.dev` subdomain. The Worker boots fine without secrets — `/authorize` will 500 if hit before §5, but `wrangler secret put` only works after this step.

## 5. Worker secrets

```bash
cd apps/gmail
npx wrangler secret put GOOGLE_CLIENT_ID         # paste Client ID from §2
npx wrangler secret put GOOGLE_CLIENT_SECRET     # paste Client Secret from §2
npx wrangler secret put COOKIE_ENCRYPTION_KEY    # generate: openssl rand -base64 32
```

No re-deploy needed — secrets are picked up on the next request.

## 6. Connect from Claude.ai
1. Claude.ai → Settings → Connectors → Add custom connector.
2. URL: `https://gmail.<your-account>.workers.dev/mcp`
3. Click Connect.
4. Cloudflare Access challenge → authenticate as the policy-allowed email.
5. Google consent screen → click Allow (sign in here as the **burner** Gmail).
6. Should redirect back to Claude.ai with the connection established.

## 7. Smoke test

Ask Claude:

> Use the gmail connector. Search for the `users.messages.list` operation and execute it for `userId=me, maxResults=5`. Just summarise the senders.

Expected: Claude calls `search`, finds the operation, calls `execute` with code that uses the spec-driven binding, and reports back senders. Verify in Cloudflare logs (`npx wrangler tail`) that the audit log shows `decision=allow operationId=gmail.users.messages.list`.

## 8. Adversarial smoke

> Use the gmail connector. Try to add a delegate email forwarding rule for `eve@evil.com`.

Expected: Claude tries `users.settings.delegates.create`, the request-handler denies it before any network call, an audit log entry shows `decision=deny category=capability_escalation`, and Claude reports the failure to you.
