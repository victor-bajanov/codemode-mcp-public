import type { InspectRequest, InspectResult } from "@local/shared";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** True when `labels` holds one of `wanted` (case-insensitive). A bare
 *  string is read as a one-element list, so `addLabelIds: "TRASH"` is caught
 *  even if Google's JSON parser accepts a scalar for the repeated field. */
function hasLabel(labels: unknown, wanted: readonly string[]): boolean {
  const list: unknown[] = typeof labels === "string" ? [labels] : Array.isArray(labels) ? labels : [];
  return list.some((l) => typeof l === "string" && wanted.includes(l.trim().toUpperCase()));
}

/**
 * The `action` keys the inspector understands. Google's REST front end
 * parses bodies with the proto3 JSON mapping, which accepts the original
 * proto field name (`add_label_ids`) as well as the lowerCamelCase JSON name
 * (`addLabelIds`), so both spellings are read. `forwardingEmail` is not a
 * FilterAction field but is checked defensively as a forwarding alias.
 */
const KNOWN_ACTION_KEYS: ReadonlySet<string> = new Set([
  "addLabelIds", "add_label_ids",
  "removeLabelIds", "remove_label_ids",
  "forward",
  "forwardingEmail",
]);

/** True when either spelling of a repeated label field holds one of `wanted`. */
function actionHasLabel(
  action: Record<string, unknown>,
  camel: string,
  snake: string,
  wanted: readonly string[],
): boolean {
  return hasLabel(action[camel], wanted) || hasLabel(action[snake], wanted);
}

/**
 * Inspector for `gmail.users.settings.filters.create`.
 *
 * Filters can be benign (label routing) or dangerous (forwarding, deletion,
 * spam-filing, skipping the inbox). This inspector applies
 * most-restrictive-first checks on the request body's `action` block and
 * returns a per-call decision:
 *   1. No `action` object → deny/malformed/filter-no-action.
 *   2. Non-empty `forward` / `forwardingEmail` string → deny/
 *      capability_escalation/filter-forward.
 *   3. Any `action` key outside the known FilterAction set (both the
 *      lowerCamelCase and proto snake_case spellings) → deny/malformed/
 *      filter-unknown-action-field. Failing closed means a field spelling
 *      the inspector does not read can never carry a label change past it.
 *   4. `addLabelIds` (or `add_label_ids`) containing TRASH or SPAM → elicit/irreversible/
 *      filter-trash-or-spam. The Gmail FilterAction resource has no `delete`
 *      field: "Delete it" and "Mark as spam" are expressed as these two
 *      labels, and they hide matching mail more completely than archiving
 *      (F-8).
 *   5. `removeLabelIds` (or `remove_label_ids`) containing INBOX →
 *      elicit/persistent_state/filter-skip-inbox.
 *   6. Otherwise → allow.
 * Label ids are compared case-insensitively, and a bare string label field
 * is treated as a one-element list.
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

  const forward = action["forward"];
  const forwardingEmail = action["forwardingEmail"];
  if ((typeof forward === "string" && forward.length > 0) ||
      (typeof forwardingEmail === "string" && forwardingEmail.length > 0)) {
    return { decision: "deny", category: "capability_escalation", reason: "filter-forward" };
  }

  if (Object.keys(action).some((k) => !KNOWN_ACTION_KEYS.has(k))) {
    return { decision: "deny", category: "malformed", reason: "filter-unknown-action-field" };
  }

  if (actionHasLabel(action, "addLabelIds", "add_label_ids", ["TRASH", "SPAM"])) {
    // Same elicit policy, and the same Claude.ai consequence, as the INBOX
    // case below: every future matching message is binned or spam-filed
    // without notification, and trashed mail is purged after 30 days.
    return {
      decision: "elicit",
      category: "irreversible",
      reason: "filter-trash-or-spam",
      summary: {
        criteria: JSON.stringify(body?.["criteria"] ?? {}).slice(0, 200),
        action: JSON.stringify(body?.["action"] ?? {}).slice(0, 200),
      },
    };
  }

  if (actionHasLabel(action, "removeLabelIds", "remove_label_ids", ["INBOX"])) {
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
