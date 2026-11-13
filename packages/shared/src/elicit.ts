export type Primitive = string | number | boolean;

/** Primitive facts keyed by label. Also the audit `elicitFields` type. */
export type FormFields = Record<string, Primitive>;

export interface ElicitRendererInput {
  operationId: string;
  /** HTTP method of the matched operation (upper case). */
  method: string;
  /** The request path as matched (raw, before re-encoding for the wire). */
  path: string;
  /** Decoded path-template parameters of the matched operation. Renderers
   *  take targets (message ids, invoice ids) from here, never from `body`. */
  pathParams: Record<string, string>;
  query?: Record<string, Primitive | undefined>;
  body: unknown;
  inspectorSummary?: Record<string, Primitive>;
}

export interface ElicitRendererOutput {
  /** One line naming the action, e.g. "Confirm Gmail permanent delete (gmail.users.messages.delete)". */
  headline: string;
  /** Resolved facts SHOWN to the user (never asked as inputs); insertion
   *  order is kept and the scaffold shows the first 8. */
  facts: FormFields;
}

export type ElicitRenderer = (input: ElicitRendererInput) => ElicitRendererOutput;
