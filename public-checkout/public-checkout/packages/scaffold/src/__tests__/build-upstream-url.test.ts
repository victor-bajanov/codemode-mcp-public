// packages/scaffold/src/__tests__/build-upstream-url.test.ts
//
// M3 — origin-invariant upstream URL builder. Asserts that
// `new URL(path, base).origin === base.origin`, throwing ToolError with
// prefix `upstream-url-origin-mismatch:` on mismatch. Defence-in-depth on
// top of resolveOperation's static-template matching.

import { describe, it, expect } from "vitest";
import { buildUpstreamUrl } from "../build-upstream-url";
import { ToolError } from "../elicit";

describe("buildUpstreamUrl", () => {
  it("happy: base + path → composed URL on same origin", () => {
    const result = buildUpstreamUrl(
      "https://gmail.googleapis.com",
      "/gmail/v1/users/me/profile",
    );
    expect(result).toBe("https://gmail.googleapis.com/gmail/v1/users/me/profile");
  });

  it("appends query params from record (undefined dropped, values coerced)", () => {
    const result = buildUpstreamUrl(
      "https://api.example.com",
      "/x",
      { a: "1", b: 2, c: undefined, d: true },
    );
    // order is implementation-defined; assert the URL parses and each param is present
    const parsed = new URL(result);
    expect(parsed.origin + parsed.pathname).toBe("https://api.example.com/x");
    expect(parsed.searchParams.get("a")).toBe("1");
    expect(parsed.searchParams.get("b")).toBe("2");
    expect(parsed.searchParams.get("c")).toBeNull();
    expect(parsed.searchParams.get("d")).toBe("true");
  });

  it("scheme-relative attack ('//evil.com/path') throws origin-mismatch ToolError", () => {
    expect(() =>
      buildUpstreamUrl("https://api.example.com", "//evil.com/path"),
    ).toThrow(ToolError);
    try {
      buildUpstreamUrl("https://api.example.com", "//evil.com/path");
    } catch (e) {
      expect((e as Error).message).toContain("upstream-url-origin-mismatch");
    }
  });

  it("absolute-URL attack ('http://evil.com/path') throws origin-mismatch ToolError", () => {
    expect(() =>
      buildUpstreamUrl("https://api.example.com", "http://evil.com/path"),
    ).toThrow(ToolError);
    try {
      buildUpstreamUrl("https://api.example.com", "http://evil.com/path");
    } catch (e) {
      expect((e as Error).message).toContain("upstream-url-origin-mismatch");
    }
  });

  it("backslash quirk ('/\\\\evil.com/path'): runtime URL ctor treats backslashes as forward slashes; \
either the origin-mismatch guard fires OR the path normalises onto the original origin — \
crucially, no cross-origin request is allowed", () => {
    // Probe the runtime's actual behaviour and pin to that outcome.
    let result: string | null = null;
    let threwOriginMismatch = false;
    try {
      result = buildUpstreamUrl("https://api.example.com", "/\\evil.com/path");
    } catch (e) {
      if (e instanceof ToolError && e.message.includes("upstream-url-origin-mismatch")) {
        threwOriginMismatch = true;
      } else {
        throw e;
      }
    }
    // Either we threw the guard (Node/Workers WHATWG behaviour: backslashes
    // resolve to "//evil.com/path", which becomes scheme-relative → cross
    // origin), or we got back a string still on api.example.com.
    if (result !== null) {
      const parsed = new URL(result);
      expect(parsed.origin).toBe("https://api.example.com");
    } else {
      expect(threwOriginMismatch).toBe(true);
    }
  });

  it("trailing-slash base + leading-slash path: no double slash in output", () => {
    const result = buildUpstreamUrl("https://api.example.com/", "/v1/x");
    expect(result).toBe("https://api.example.com/v1/x");
    expect(result).not.toContain("//v1");
  });
});
