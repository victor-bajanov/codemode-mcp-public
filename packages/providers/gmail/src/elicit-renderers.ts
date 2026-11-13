import type { ElicitRenderer, ElicitRendererInput, FormFields, Primitive } from "@local/shared";

// Approval-dialog renderers for the Gmail + Calendar provider (D-1).
//
// Each returns `{ headline, facts }`. The scaffold shows the facts as text
// under a `Request: METHOD path` line and asks only for `confirm`. Facts come
// from two trusted places: the decoded path parameters (the target that is
// actually sent) and the host inspector's summary. A target is never taken
// from the sandbox-supplied `body` (it used to be `body.id`, a decoy the
// caller controls on a DELETE). Path facts come first so the summary cannot
// push them past the scaffold's fact cap.

function pickPrimitives(
  src: Record<string, Primitive> | undefined,
  keys: readonly string[],
): FormFields {
  const out: FormFields = {};
  if (!src) return out;
  for (const k of keys) {
    const v: unknown = src[k];
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") out[k] = v;
  }
  return out;
}

/** Path parameters as dialog facts: `userId` is dropped (always the caller's
 *  own mailbox), and the bare `id` is relabelled `messageId` / `threadId` on
 *  message / thread operations, unless the template already has a parameter
 *  of that name (e.g. `messages/{messageId}/attachments/{id}`), in which case
 *  `id` keeps its name. Anything else keeps its template name. */
function pathFacts(input: ElicitRendererInput): FormFields {
  const out: FormFields = {};
  const params = input.pathParams;
  for (const [name, value] of Object.entries(params)) {
    if (name === "userId" || name === "id") continue;
    out[name] = value;
  }
  if (Object.hasOwn(params, "id")) {
    let label = "id";
    if (input.operationId.startsWith("gmail.users.messages.")) label = "messageId";
    else if (input.operationId.startsWith("gmail.users.threads.")) label = "threadId";
    if (Object.hasOwn(out, label)) label = "id";
    out[label] = params["id"]!;
  }
  return out;
}

/** Path facts first, then summary facts; a summary key never overrides a
 *  path-derived fact. */
function facts(input: ElicitRendererInput, summaryKeys: readonly string[]): FormFields {
  const out = pathFacts(input);
  for (const [k, v] of Object.entries(pickPrimitives(input.inspectorSummary, summaryKeys))) {
    if (!Object.hasOwn(out, k)) out[k] = v;
  }
  return out;
}

const isFilterOp = (operationId: string): boolean => operationId.includes(".settings.filters.");

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Same reading as `inspectors/filters.ts`: a bare string is a one-element
 *  list, labels compare trimmed and case-insensitively. */
function labelsOf(action: Record<string, unknown>, camel: string, snake: string): Set<string> {
  const out = new Set<string>();
  for (const v of [action[camel], action[snake]]) {
    const list: unknown[] = typeof v === "string" ? [v] : Array.isArray(v) ? v : [];
    for (const l of list) if (typeof l === "string") out.add(l.trim().toUpperCase());
  }
  return out;
}

/** What a filter does to matching mail, in words, read from the body that
 *  is sent. Empty when the action changes none of TRASH, SPAM or INBOX. */
function filterEffect(body: unknown): string {
  const action = isObject(body) ? body["action"] : undefined;
  if (!isObject(action)) return "";
  const add = labelsOf(action, "addLabelIds", "add_label_ids");
  const remove = labelsOf(action, "removeLabelIds", "remove_label_ids");
  const effects: string[] = [];
  if (add.has("TRASH")) effects.push("moves matching mail to TRASH");
  if (add.has("SPAM")) effects.push("marks matching mail as spam");
  if (remove.has("INBOX")) effects.push("removes INBOX (archives matching mail)");
  return effects.join("; ");
}

/** Criteria fields shown on their own lines, ahead of the criteria JSON, so
 *  padding in one field cannot push the sender out of the dialog. */
const CRITERIA_FIELDS: ReadonlyArray<readonly [label: string, keys: readonly string[]]> = [
  ["from", ["from"]],
  ["to", ["to"]],
  ["subject", ["subject"]],
  ["query", ["query"]],
  ["negatedQuery", ["negatedQuery", "negated_query"]],
];

function criteriaValueText(v: unknown): Primitive {
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean"
    ? v
    : JSON.stringify(v) ?? String(v);
}

/** Every spelling present is shown (joined " | "): Google accepts both the
 *  JSON and the proto name, and the dialog must not hide whichever one the
 *  upstream ends up honouring. */
function criteriaFacts(body: unknown): FormFields {
  const out: FormFields = {};
  const criteria = isObject(body) ? body["criteria"] : undefined;
  if (!isObject(criteria)) return out;
  for (const [label, keys] of CRITERIA_FIELDS) {
    const present = keys.filter((k) => criteria[k] !== undefined && criteria[k] !== null);
    if (present.length === 0) continue;
    const values = present.map((k) => criteriaValueText(criteria[k]));
    out[label] = values.length === 1 ? values[0]! : values.map(String).join(" | ");
  }
  return out;
}

/** Filter dialog: target (none today: userId is dropped), then the effect,
 *  then the criteria fields, then the inspector's criteria/action JSON. */
function filterRender(input: ElicitRendererInput): ReturnType<ElicitRenderer> {
  const effect = filterEffect(input.body);
  const out = pathFacts(input);
  if (effect !== "") out["effect"] = effect;
  for (const [k, v] of Object.entries(criteriaFacts(input.body))) {
    if (!Object.hasOwn(out, k)) out[k] = v;
  }
  for (const [k, v] of Object.entries(pickPrimitives(input.inspectorSummary, ["criteria", "action"]))) {
    if (!Object.hasOwn(out, k)) out[k] = v;
  }
  const headline = `Confirm Gmail filter (${input.operationId})`;
  return { headline: effect !== "" ? `${headline}: ${effect}` : headline, facts: out };
}

/** Summary keys the send, import and Calendar inspectors emit, in dialog
 *  order. With at most two path facts (calendarId, eventId) the scaffold's
 *  8-fact cap leaves six summary facts, so the decisive ones for each dialog
 *  come first: mass send (recipients, subject, count, attachments), message
 *  import (from, to, subject, date), event import/write (count, attendees,
 *  organizer, changes, summary, start, end), outside guests (guests,
 *  organizer, changes, summary, start, end). Who is affected (guests,
 *  organizer) and what the write changes come before the descriptive facts,
 *  so the cap only ever drops a descriptive one. */
const EXTERNAL_DATA_FLOW_KEYS = [
  "recipients", "from", "to", "subject", "date", "count", "attendees", "guests",
  "organizer", "changes", "summary", "start", "end", "attachments",
] as const;

const externalDataFlow: ElicitRenderer = (input) => ({
  headline: input.operationId.endsWith(".import")
    ? `Confirm Gmail import (${input.operationId})`
    : `Confirm Gmail external send (${input.operationId})`,
  facts: facts(input, EXTERNAL_DATA_FLOW_KEYS),
});

const irreversible: ElicitRenderer = (input) =>
  isFilterOp(input.operationId)
    ? filterRender(input)
    : {
        headline: `Confirm Gmail permanent delete (${input.operationId})`,
        facts: facts(input, ["messageId", "threadId"]),
      };

const SHOWN_IDS = 3;

const bulkDestructive: ElicitRenderer = (input) => {
  const out = pathFacts(input);
  const ids = (input.body as { ids?: unknown } | null | undefined)?.ids;
  const list = Array.isArray(ids) ? (ids as unknown[]) : [];
  out["count"] = list.length;
  if (list.length > 0) {
    const shown = list
      .slice(0, SHOWN_IDS)
      .map((id) => (typeof id === "string" ? id : JSON.stringify(id) ?? String(id)))
      .join(", ");
    out["ids"] = list.length > SHOWN_IDS ? `${shown} (+${list.length - SHOWN_IDS})` : shown;
  }
  return { headline: `Confirm Gmail bulk delete (${input.operationId})`, facts: out };
};

/** Only filters are `persistent_state` elicit operations in this provider. */
const persistentState: ElicitRenderer = filterRender;

export const gmailElicitRenderers: {
  external_data_flow: ElicitRenderer;
  irreversible: ElicitRenderer;
  bulk_destructive: ElicitRenderer;
  persistent_state: ElicitRenderer;
} = {
  external_data_flow: externalDataFlow,
  irreversible,
  bulk_destructive: bulkDestructive,
  persistent_state: persistentState,
};
