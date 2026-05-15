// packages/scaffold/src/__tests__/assert-secrets.test.ts
//
// I4 — first request after a misconfigured deploy must fail loudly with an
// actionable error naming the >=32-char floor and the `wrangler secret put`
// remedy, instead of failing opaquely inside the cookie-decryption path
// during /authorize.

import { describe, it, expect } from "vitest";
import { assertSecrets } from "../config";

describe("assertSecrets", () => {
  it("throws when COOKIE_ENCRYPTION_KEY is absent", () => {
    expect(() => assertSecrets({})).toThrow(/missing or too short/);
  });

  it("throws on empty string", () => {
    expect(() => assertSecrets({ COOKIE_ENCRYPTION_KEY: "" })).toThrow(
      /missing or too short/,
    );
  });

  it("throws on a value under 32 chars", () => {
    expect(() => assertSecrets({ COOKIE_ENCRYPTION_KEY: "short" })).toThrow(
      /missing or too short/,
    );
  });

  it("returns void on a 32-char value", () => {
    expect(
      assertSecrets({ COOKIE_ENCRYPTION_KEY: "x".repeat(32) }),
    ).toBeUndefined();
  });
});
