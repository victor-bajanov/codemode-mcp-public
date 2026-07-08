import type { InspectRequest, InspectResult } from "@local/shared";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Inspector for `gmail.users.settings.filters.create`.
 *
 * Filters can be benign (label routing) or dangerous (forwarding, deletion,
 * skipping the inbox). This inspector applies most-restrictive-first checks
 * on the request body's `action` block and returns a per-call decision.
 */
export function inspectFilterCreate(req: InspectRequest): InspectResult {
  const body = req.body;
  if (!isObject(body)) {
    return { decision: "deny", category: "malformed", reason: "filter-no-action" };
  }
  const action = body["action"];
  if (!isObject(action)) {
    return { decision: "deny", category: "malformed", reason: "filter-no-action" };
  }

  if (action["delete"] === true) {
    return { decision: "deny", category: "irreversible", reason: "filter-delete" };
  }

  const forward = action["forward"];
  const forwardingEmail = action["forwardingEmail"];
  if ((typeof forward === "string" && forward.length > 0) ||
      (typeof forwardingEmail === "string" && forwardingEmail.length > 0)) {
    return { decision: "deny", category: "capability_escalation", reason: "filter-forward" };
  }

  const removeLabelIds = action["removeLabelIds"];
  if (Array.isArray(removeLabelIds) && removeLabelIds.includes("INBOX")) {
    // Actual operator policy is `allow` (auto-archive is a common legitimate use case);
    // `elicit` is kept here to exercise the inspector->elicit path until live elicitation lands in slice 2.
    return {
      decision: "elicit",
      category: "persistent_state",
      reason: "filter-skip-inbox",
      summary: {
        criteria: JSON.stringify(body?.["criteria"] ?? {}).slice(0, 200),
        action: JSON.stringify(body?.["action"] ?? {}).slice(0, 200),
      },
    };
  }

  return { decision: "allow" };
}
