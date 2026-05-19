import { describe, it, expect } from "vitest";
import { gmailElicitRenderers } from "../elicit-renderers";

describe("gmail elicit-renderers — external_data_flow", () => {
  const r = gmailElicitRenderers.external_data_flow!;

  it("uses inspectorSummary fields when present (mass-send)", () => {
    const out = r({
      operationId: "gmail.users.messages.send",
      body: { raw: "QUJDREVG..." },
      inspectorSummary: { recipients: "a@b.com (+24)", subject: "Hi", count: 25 },
    });
    expect(out.fields).toMatchObject({ recipients: "a@b.com (+24)", subject: "Hi", count: 25 });
    expect(out.message).toContain("send");
  });

  it("falls back to a confirm field when no summary and body is opaque", () => {
    const out = r({ operationId: "gmail.users.messages.send", body: { raw: "AAAA..." } });
    expect(out.fields.confirm).toBe(true);
  });
});

describe("gmail elicit-renderers — irreversible", () => {
  const r = gmailElicitRenderers.irreversible!;

  it("surfaces messageId from inspectorSummary or body.id field", () => {
    const out = r({
      operationId: "gmail.users.messages.delete",
      body: undefined,
      inspectorSummary: { messageId: "msg_123" },
    });
    expect(out.fields).toMatchObject({ messageId: "msg_123" });
  });
});

describe("gmail elicit-renderers — bulk_destructive", () => {
  const r = gmailElicitRenderers.bulk_destructive!;

  it("surfaces the count of ids", () => {
    const out = r({
      operationId: "gmail.users.messages.batchDelete",
      body: { ids: ["a", "b", "c"] },
    });
    expect(out.fields).toMatchObject({ count: 3 });
  });

  it("falls back to count: 0 when no ids", () => {
    const out = r({ operationId: "gmail.users.messages.batchDelete", body: {} });
    expect(out.fields).toMatchObject({ count: 0 });
  });
});

describe("gmail elicit-renderers — persistent_state", () => {
  const r = gmailElicitRenderers.persistent_state!;

  it("uses inspectorSummary criteria + action", () => {
    const out = r({
      operationId: "gmail.users.settings.filters.create",
      body: { criteria: { from: "x" }, action: { removeLabelIds: ["INBOX"] } },
      inspectorSummary: { criteria: "{\"from\":\"x\"}", action: "{\"removeLabelIds\":[\"INBOX\"]}" },
    });
    expect(out.fields).toMatchObject({
      criteria: "{\"from\":\"x\"}",
      action: "{\"removeLabelIds\":[\"INBOX\"]}",
    });
  });
});
