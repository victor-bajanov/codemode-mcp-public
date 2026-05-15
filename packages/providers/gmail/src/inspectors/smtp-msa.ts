import type { InspectResult } from "@local/shared";
import { SMTP_MSA_HOST_ALLOWLIST } from "./smtp-msa-allowlist.js";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

export function inspectSmtpMsa(body: unknown): InspectResult | null {
  if (!isObject(body)) return null;
  const msa = body["smtpMsa"];
  if (msa === undefined) return null;
  if (!isObject(msa)) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "smtp-msa-bad-shape",
    };
  }
  const host = msa["host"];
  if (typeof host !== "string" || host.length === 0) {
    return {
      decision: "deny",
      category: "capability_escalation",
      reason: "smtp-msa-no-host",
    };
  }
  const normHost = host.trim().toLowerCase();
  if (!SMTP_MSA_HOST_ALLOWLIST.map((h) => h.toLowerCase()).includes(normHost)) {
    return {
      decision: "deny",
      category: "capability_escalation",
      reason: "smtp-msa-host-not-allowlisted",
    };
  }
  return null; // clean — caller proceeds with other checks
}
