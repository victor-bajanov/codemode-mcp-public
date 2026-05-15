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
  const fields = pickPrimitives(input.inspectorSummary, ["invoiceId", "to"]);
  if (Object.keys(fields).length === 0) fields.confirm = true;
  return {
    message: `Confirm Xero external send (${input.operationId})`,
    fields,
  };
};

const financialLegal: ElicitRenderer = (input) => {
  const body = (input.body as Record<string, unknown> | undefined) ?? undefined;
  const collection =
    (body?.["Payments"] as unknown[] | undefined) ??
    (body?.["PayRuns"] as unknown[] | undefined) ??
    [];
  const fields: FormFields = { count: Array.isArray(collection) ? collection.length : 0 };
  if (Array.isArray(collection)) {
    let total = 0;
    let allNumeric = true;
    for (const item of collection) {
      const amt = (item as { Amount?: unknown })?.Amount;
      if (typeof amt === "number") total += amt;
      else { allNumeric = false; break; }
    }
    if (allNumeric && collection.length > 0) fields.total = total;
  }
  return {
    message: `Confirm Xero financial op (${input.operationId})`,
    fields,
  };
};

const persistentState: ElicitRenderer = (input) => {
  const body = (input.body as Record<string, unknown> | undefined) ?? undefined;
  const employees = body?.["Employees"];
  if (Array.isArray(employees) && employees.length > 0) {
    const e = employees[0] as Record<string, unknown>;
    return {
      message: `Confirm Xero employee mutation (${input.operationId})`,
      fields: pickPrimitives(e, ["FirstName", "LastName", "Email"]),
    };
  }
  return {
    message: `Confirm Xero employee mutation (${input.operationId})`,
    fields: { confirm: true },
  };
};

export const xeroElicitRenderers: {
  external_data_flow: ElicitRenderer;
  financial_legal: ElicitRenderer;
  persistent_state: ElicitRenderer;
} = {
  external_data_flow: externalDataFlow,
  financial_legal: financialLegal,
  persistent_state: persistentState,
};
