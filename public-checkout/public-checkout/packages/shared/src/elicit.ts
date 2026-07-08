export type Primitive = string | number | boolean;

export type FormFields = Record<string, Primitive>;

export interface ElicitRendererInput {
  operationId: string;
  body: unknown;
  query?: unknown;
  inspectorSummary?: Record<string, Primitive>;
}

export interface ElicitRendererOutput {
  message: string;
  fields: FormFields;
}

export type ElicitRenderer = (input: ElicitRendererInput) => ElicitRendererOutput;
