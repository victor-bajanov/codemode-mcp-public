import type { ElicitRenderer, FormFields, Primitive } from "@local/shared";

function pickPrimitives(
  src: Record<string, unknown> | undefined,
  keys: string[],
): FormFields {
  const out: FormFields = {};
  if (!src) return out;
  for (const k of keys) {
    const v = src[k];
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
      out[k] = v as Primitive;
    }
  }
  return out;
}

const externalDataFlow: ElicitRenderer = (input) => {
  const fields = pickPrimitives(input.inspectorSummary, ["recipients", "subject", "count"]);
  if (Object.keys(fields).length === 0) fields.confirm = true;
  return {
    message: `Confirm Gmail external send (${input.operationId})`,
    fields,
  };
};

const irreversible: ElicitRenderer = (input) => {
  const summary = pickPrimitives(input.inspectorSummary, ["messageId", "threadId"]);
  if (Object.keys(summary).length > 0) {
    return { message: `Confirm Gmail irreversible op (${input.operationId})`, fields: summary };
  }
  // Fall back: try body.id (singular Gmail delete shapes use {id})
  const body = (input.body as Record<string, unknown> | undefined) ?? undefined;
  if (body && typeof body["id"] === "string") {
    return {
      message: `Confirm Gmail irreversible op (${input.operationId})`,
      fields: { id: body["id"] as string },
    };
  }
  return { message: `Confirm Gmail irreversible op (${input.operationId})`, fields: { confirm: true } };
};

const bulkDestructive: ElicitRenderer = (input) => {
  const ids = (input.body as { ids?: unknown[] } | undefined)?.ids;
  const count = Array.isArray(ids) ? ids.length : 0;
  return {
    message: `Confirm Gmail bulk delete (${input.operationId})`,
    fields: { count },
  };
};

const persistentState: ElicitRenderer = (input) => {
  const fields = pickPrimitives(input.inspectorSummary, ["criteria", "action"]);
  if (Object.keys(fields).length === 0) fields.confirm = true;
  return {
    message: `Confirm Gmail filter (${input.operationId})`,
    fields,
  };
};

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
