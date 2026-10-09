// A5 — COOKIE_ENCRYPTION_KEY was asserted (>=32 chars) but never used.
//
// Status: FIXED (F-20) — the key now signs the /authorize consent form tokens
// (HMAC-SHA256, imported in oauth-consent.ts); the boot-time assertion stays.
//
// Originally CONFIRMED (Informational): `assertSecrets` in config.ts was the
// only reader, and neither the scaffold nor @cloudflare/workers-oauth-provider
// had any cookie/approval-page code path that consumed it (the remediation
// spec I4 cited "/authorize's cookie path", which did not exist in this
// scaffold — it exists in Cloudflare's reference template, whose approval
// dialog signs a consent cookie). The scaffold now supplies that path itself:
// `oauth-consent.ts` imports the key as a non-extractable HMAC key and the
// consent page's single-use form token is signed with it.
//
// This test is a static scan of the on-disk sources (non-test scaffold src +
// the installed library dist) rather than a runtime POC.

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "..");
const LIB_DIST = join(SRC, "..", "node_modules", "@cloudflare", "workers-oauth-provider", "dist");

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "__tests__" || name === "node_modules") continue;
      walk(p, out);
    } else if (/\.(ts|js)$/.test(name)) out.push(p);
  }
  return out;
}

describe("A5 COOKIE_ENCRYPTION_KEY usage", () => {
  it("FIXED (F-20): the key is asserted in config.ts AND consumed as an HMAC key in oauth-consent.ts", () => {
    const hits = walk(SRC)
      .filter((f) => readFileSync(f, "utf8").includes("COOKIE_ENCRYPTION_KEY"))
      .map((f) => relative(SRC, f))
      .sort();
    expect(hits).toEqual(["config.ts", "oauth-consent.ts"]);
    // The boot-time assertion is unchanged.
    const cfg = readFileSync(join(SRC, "config.ts"), "utf8");
    expect(cfg).toMatch(/const key = env\.COOKIE_ENCRYPTION_KEY;\s*\n\s*if \(typeof key !== "string" \|\| key\.length < 32\)/);
    // The consent module reads it and imports it as an HMAC-SHA256 signing key.
    const consent = readFileSync(join(SRC, "oauth-consent.ts"), "utf8");
    expect(consent).toMatch(/const raw = env\.COOKIE_ENCRYPTION_KEY;/);
    expect(consent).toMatch(/importKey\(\s*"raw",\s*new TextEncoder\(\)\.encode\(raw\),\s*\{ name: "HMAC", hash: "SHA-256" \}/);
    expect(consent).toMatch(/crypto\.subtle\.sign\("HMAC", key/);
    // ...and the /authorize handler actually uses that module to sign and verify.
    const handler = readFileSync(join(SRC, "oauth-handler.ts"), "utf8");
    expect(handler).toMatch(/consentKey\(/);
    expect(handler).toMatch(/signConsentToken\(/);
    expect(handler).toMatch(/verifyConsentToken\(/);
  });

  it("context: the OAuth provider library still has no cookie handling of its own — the scaffold supplies the cookie path", () => {
    const libSrc = walk(LIB_DIST).map((f) => readFileSync(f, "utf8")).join("\n");
    expect(libSrc).not.toMatch(/COOKIE_ENCRYPTION_KEY/);
    expect(libSrc).not.toMatch(/set-cookie/i);
    expect(libSrc).not.toMatch(/\bcookie\b/i);
    const handler = readFileSync(join(SRC, "oauth-handler.ts"), "utf8");
    expect(handler).toMatch(/set-cookie/);
  });
});
