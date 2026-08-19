// Xero rate-limit header parsing.
//
// Xero returns X-DayLimit-Remaining / X-MinLimit-Remaining / X-AppMinLimit-Remaining
// on EVERY response, and additionally X-Rate-Limit-Problem (which limit was hit)
// plus Retry-After (seconds) on a 429. readXeroRateLimit turns those headers into
// the provider-agnostic UpstreamRateLimit the scaffold puts on the response
// envelope, so the MCP client is told *why* it was throttled and for how long.

import { describe, it, expect } from "vitest";
import { readXeroRateLimit } from "../rate-limit";

function res(status: number, headers: Record<string, string>): { status: number; headers: Headers } {
  return { status, headers: new Headers(headers) };
}

describe("readXeroRateLimit — every response", () => {
  it("parses the three remaining-call counters off a 200", () => {
    const rl = readXeroRateLimit(res(200, {
      "X-DayLimit-Remaining": "4998",
      "X-MinLimit-Remaining": "57",
      "X-AppMinLimit-Remaining": "9970",
    }));
    expect(rl).toEqual({ remaining: { day: 4998, minute: 57, appMinute: 9970 } });
  });

  it("returns undefined when upstream sent no rate-limit headers at all", () => {
    expect(readXeroRateLimit(res(200, { "content-type": "application/json" }))).toBeUndefined();
  });

  it("includes only the counters upstream actually sent", () => {
    const rl = readXeroRateLimit(res(200, { "X-MinLimit-Remaining": "0" }));
    expect(rl).toEqual({ remaining: { minute: 0 } });
  });

  it("ignores non-numeric counter values rather than emitting NaN", () => {
    const rl = readXeroRateLimit(res(200, {
      "X-DayLimit-Remaining": "unknown",
      "X-MinLimit-Remaining": "12",
    }));
    expect(rl).toEqual({ remaining: { minute: 12 } });
  });
});

describe("readXeroRateLimit — 429", () => {
  it("names the limit that was hit, the wait, and a client-facing message", () => {
    const rl = readXeroRateLimit(res(429, {
      "X-Rate-Limit-Problem": "minute",
      "Retry-After": "43",
      "X-DayLimit-Remaining": "4321",
      "X-MinLimit-Remaining": "0",
      "X-AppMinLimit-Remaining": "9000",
    }));
    expect(rl).toMatchObject({
      problem: "minute",
      limit: "per-minute limit (60 calls/minute per tenant)",
      retryAfterSeconds: 43,
      remaining: { day: 4321, minute: 0, appMinute: 9000 },
    });
    expect(rl?.message).toContain("per-minute limit");
    expect(rl?.message).toContain("43");
  });

  it("describes the daily limit", () => {
    const rl = readXeroRateLimit(res(429, { "X-Rate-Limit-Problem": "day", "Retry-After": "3600" }));
    expect(rl?.problem).toBe("day");
    expect(rl?.limit).toContain("daily limit");
    expect(rl?.retryAfterSeconds).toBe(3600);
  });

  it("describes the app-wide minute limit (appminute)", () => {
    const rl = readXeroRateLimit(res(429, { "X-Rate-Limit-Problem": "appminute", "Retry-After": "7" }));
    expect(rl?.problem).toBe("appminute");
    expect(rl?.limit).toContain("app-wide");
  });

  it("is case-insensitive on the problem value", () => {
    const rl = readXeroRateLimit(res(429, { "X-Rate-Limit-Problem": "AppMinute" }));
    expect(rl?.problem).toBe("appminute");
    expect(rl?.limit).toContain("app-wide");
  });

  it("passes an unrecognised problem value through verbatim", () => {
    const rl = readXeroRateLimit(res(429, { "X-Rate-Limit-Problem": "concurrent" }));
    expect(rl?.problem).toBe("concurrent");
    expect(rl?.limit).toBe("concurrent");
    expect(rl?.message).toContain("concurrent");
  });

  it("still reports a rate limit when the 429 carries no headers at all", () => {
    const rl = readXeroRateLimit(res(429, {}));
    expect(rl?.problem).toBeUndefined();
    expect(rl?.retryAfterSeconds).toBeUndefined();
    expect(rl?.message).toContain("rate limit");
  });

  it("ignores a non-numeric Retry-After", () => {
    const rl = readXeroRateLimit(res(429, { "Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT" }));
    expect(rl?.retryAfterSeconds).toBeUndefined();
  });
});

describe("xeroProvider wiring", () => {
  it("exposes readXeroRateLimit as the provider's readRateLimit hook", async () => {
    const { xeroProvider } = await import("../index");
    expect(xeroProvider.readRateLimit).toBe(readXeroRateLimit);
  });
});
