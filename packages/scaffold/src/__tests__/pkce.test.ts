// packages/scaffold/src/__tests__/pkce.test.ts
//
// Unit tests for the PKCE helpers used by the OAuth authorization-code flow.

import { describe, it, expect } from "vitest";
import { generateCodeVerifier, sha256Base64Url } from "../pkce";

describe("generateCodeVerifier", () => {
  it("returns a 43-character base64url string with no padding or unsafe chars", () => {
    const v = generateCodeVerifier();
    expect(v).toHaveLength(43);
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(v).not.toContain("=");
    expect(v).not.toContain("+");
    expect(v).not.toContain("/");
  });

  it("returns a different value each invocation (probabilistic)", () => {
    const a = generateCodeVerifier();
    const b = generateCodeVerifier();
    expect(a).not.toBe(b);
  });
});

describe("sha256Base64Url", () => {
  it("matches the RFC 7636 Appendix B fixture", async () => {
    // RFC 7636 Appendix B: code_verifier
    //   "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // produces code_challenge
    //   "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const challenge = await sha256Base64Url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("returns base64url with no padding or unsafe chars", async () => {
    const c = await sha256Base64Url("hello");
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(c).not.toContain("=");
    expect(c).not.toContain("+");
    expect(c).not.toContain("/");
  });
});
