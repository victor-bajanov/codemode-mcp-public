// Tests for the smtpMsa body-level inspector wired into
// inspectSendAsCreate (H2 security-review remediation).

import { describe, it, expect, vi } from "vitest";

// Mirrors the prod (gmail/gmail-dev) wrangler var.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
};

describe("inspectSendAsCreate — smtpMsa body-level inspector", () => {
  it("allows a bare body with no smtpMsa sub-object (regression)", async () => {
    const { inspectSendAsCreate } = await import("../inspectors/sendas");
    const result = inspectSendAsCreate(
      { body: { sendAsEmail: "alias@example.com" } },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies smtpMsa with no host", async () => {
    const { inspectSendAsCreate } = await import("../inspectors/sendas");
    const result = inspectSendAsCreate({
      body: {
        sendAsEmail: "alias@example.com",
        smtpMsa: {},
      },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "smtp-msa-no-host",
    });
  });

  it("denies smtpMsa whose host is not on the allowlist", async () => {
    const { inspectSendAsCreate } = await import("../inspectors/sendas");
    const result = inspectSendAsCreate({
      body: {
        sendAsEmail: "alias@example.com",
        smtpMsa: { host: "smtp.evil.com", port: 587 },
      },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "smtp-msa-host-not-allowlisted",
    });
  });

  it("denies smtpMsa with a non-object (bad shape)", async () => {
    const { inspectSendAsCreate } = await import("../inspectors/sendas");
    const result = inspectSendAsCreate({
      body: {
        sendAsEmail: "alias@example.com",
        smtpMsa: "string-not-object",
      },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "smtp-msa-bad-shape",
    });
  });
});

describe("inspectSendAsCreate — smtpMsa with allowlist override", () => {
  it("allows an smtpMsa host when present on the (mocked) allowlist", async () => {
    vi.resetModules();
    vi.doMock("../inspectors/smtp-msa-allowlist", () => ({
      SMTP_MSA_HOST_ALLOWLIST: ["allowed.example.com"],
    }));
    const { inspectSendAsCreate } = await import("../inspectors/sendas");
    const result = inspectSendAsCreate(
      {
        body: {
          sendAsEmail: "alias@example.com",
          smtpMsa: { host: "allowed.example.com", port: 587 },
        },
      },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
    vi.doUnmock("../inspectors/smtp-msa-allowlist");
    vi.resetModules();
  });
});
