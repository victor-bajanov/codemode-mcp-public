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
    // Operator policy is `elicit`, deliberately. A filter that strips INBOX
    // hides matching mail from the user's view for every future message, with
    // no notification — persistent state the user should agree to explicitly,
    // even though auto-archive is itself a common legitimate use case.
    //
    // Consequence, and it is intended: on a client that cannot render an
    // elicitation prompt (Claude.ai — see scaffold/src/elicit.ts, which throws
    // `outcome: unsupported` rather than prompting), this is a hard failure,
    // so auto-archive filters cannot be created there at all. Failing closed is
    // the right side to err on for a rule that silently hides mail. The
    // surface-review `clientNote` tells the model this up front, and the
    // annotator appends the cannot-approve caveat, so the model reports it as
    // unavailable rather than claiming it asked for a confirmation.
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
