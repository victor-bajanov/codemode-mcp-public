// Gmail/Calendar approval-dialog renderers (D-1). A renderer turns the matched
// request into `{ headline, facts }`; the scaffold shows the facts as text and
// asks only for `confirm`. Targets (message, thread, calendar, event ids) come
// from the decoded path parameters, never from the sandbox-supplied body.
import { describe, it, expect } from "vitest";
import type { ElicitRendererInput } from "@local/shared";
import { gmailElicitRenderers } from "../elicit-renderers";

function input(over: Partial<ElicitRendererInput> & { operationId: string }): ElicitRendererInput {
  return { method: "POST", path: "/", pathParams: {}, body: undefined, ...over };
}

describe("gmail elicit-renderers — external_data_flow", () => {
  const r = gmailElicitRenderers.external_data_flow;

  it("shows the mass-send inspector summary as facts, in a send headline", () => {
    const out = r(input({
      operationId: "gmail.users.messages.send",
      path: "/gmail/v1/users/me/messages/send",
      pathParams: { userId: "me" },
      body: { raw: "QUJDREVG" },
      inspectorSummary: {
        recipients: "a@b.com, c@b.com, d@b.com (+22)",
        subject: "Hi",
        count: 25,
        attachments: "report.pdf (10 bytes)",
      },
    }));
    expect(out.headline).toBe("Confirm Gmail external send (gmail.users.messages.send)");
    expect(out.facts).toEqual({
      recipients: "a@b.com, c@b.com, d@b.com (+22)",
      subject: "Hi",
      count: 25,
      attachments: "report.pdf (10 bytes)",
    });
  });

  it("shows the mass-invite summary (attendees, summary, count) and the calendar id", () => {
    const out = r(input({
      operationId: "calendar.events.import",
      path: "/calendar/v3/calendars/primary/events/import",
      pathParams: { calendarId: "primary" },
      inspectorSummary: { attendees: "x@y.z (+30)", summary: "Offsite", count: 31 },
    }));
    expect(out.facts).toEqual({ calendarId: "primary", attendees: "x@y.z (+30)", summary: "Offsite", count: 31 });
  });

  it("labels imports as imports, not sends", () => {
    expect(r(input({ operationId: "gmail.users.messages.import", pathParams: { userId: "me" } })).headline)
      .toBe("Confirm Gmail import (gmail.users.messages.import)");
    expect(r(input({ operationId: "calendar.events.import", pathParams: { calendarId: "primary" } })).headline)
      .toBe("Confirm Gmail import (calendar.events.import)");
  });

  it("never asks for a confirm fact and drops userId: an opaque send has no facts", () => {
    const out = r(input({ operationId: "gmail.users.messages.send", pathParams: { userId: "me" }, body: { raw: "AAAA" } }));
    expect(out.facts).toEqual({});
  });

  // Wave 2 (§4): every summary key the send/import/calendar inspectors emit
  // reaches the dialog, in a fixed order, within the scaffold's 8-fact cap.
  const SUMMARY_ORDER = [
    "recipients", "from", "to", "subject", "date", "count", "attendees", "guests",
    "organizer", "changes", "summary", "start", "end", "attachments",
  ];

  it.each([
    ["from", "ceo@corp.example"],
    ["to", "victim@corp.example"],
    ["date", "Tue, 10 Nov 2026 09:00:00 +1100"],
  ])("shows the %s summary key on a message import", (key, value) => {
    const out = r(input({
      operationId: "gmail.users.messages.import",
      pathParams: { userId: "me" },
      inspectorSummary: { [key]: value },
    }));
    expect(out.facts).toEqual({ [key]: value });
  });

  it("tightest event dialog: who is affected and what changes precede summary/start/end, so the 8-fact cap drops only descriptive facts", () => {
    const out = r(input({
      operationId: "calendar.events.patch",
      pathParams: { calendarId: "primary", eventId: "EV1" },
      inspectorSummary: {
        end: "E", start: "S", summary: "Board", changes: "description, summary", organizer: "me@corp.example",
        guests: "o@evil.example", attendees: "x@y.z (+30)", count: 31,
      },
    }));
    const keys = Object.keys(out.facts);
    expect(keys).toEqual([
      "calendarId", "eventId", "count", "attendees", "guests", "organizer", "changes", "summary", "start", "end",
    ]);
    expect(keys.slice(8)).toEqual(["start", "end"]);
  });

  it.each([
    ["guests", "outsider@evil.example (+2)"],
    ["organizer", "me@corp.example"],
    ["changes", "description, summary"],
    ["start", "2026-11-12T09:00:00+11:00"],
    ["end", "2026-11-12T10:00:00+11:00"],
  ])("shows the %s summary key", (key, value) => {
    const out = r(input({
      operationId: "calendar.events.import",
      pathParams: { calendarId: "primary" },
      inspectorSummary: { [key]: value },
    }));
    expect(out.facts).toEqual({ calendarId: "primary", [key]: value });
  });

  it("orders summary facts by the fixed key list, not by the inspector's key order", () => {
    const summary: Record<string, string> = {};
    for (const k of [...SUMMARY_ORDER].reverse()) summary[k] = `v-${k}`;
    const out = r(input({ operationId: "gmail.users.messages.send", pathParams: { userId: "me" }, inspectorSummary: summary }));
    expect(Object.keys(out.facts)).toEqual(SUMMARY_ORDER);
  });

  it("message import: from, to, subject, date in that order", () => {
    const out = r(input({
      operationId: "gmail.users.messages.import",
      pathParams: { userId: "me" },
      inspectorSummary: { date: "D", subject: "Wire transfer today", to: "victim@corp.example", from: "ceo@corp.example" },
    }));
    expect(Object.keys(out.facts)).toEqual(["from", "to", "subject", "date"]);
  });

  it("event write with two path facts: the six decisive summary facts fit the 8-fact cap", () => {
    const out = r(input({
      operationId: "calendar.events.update",
      pathParams: { calendarId: "primary", eventId: "EV1" },
      inspectorSummary: {
        end: "E", start: "S", summary: "Offsite", organizer: "me@corp.example", count: 31, attendees: "x@y.z (+30)",
      },
    }));
    expect(Object.keys(out.facts)).toEqual([
      "calendarId", "eventId", "count", "attendees", "organizer", "summary", "start", "end",
    ]);
    const guests = r(input({
      operationId: "calendar.events.patch",
      pathParams: { calendarId: "primary", eventId: "EV1" },
      inspectorSummary: { start: "S", summary: "Board", organizer: "me@corp.example", guests: "o@evil.example", changes: "description", end: "E" },
    }));
    expect(Object.keys(guests.facts)).toEqual([
      "calendarId", "eventId", "guests", "organizer", "changes", "summary", "start", "end",
    ]);
  });

  it("ignores non-primitive and unknown summary keys", () => {
    const out = r(input({
      operationId: "gmail.users.messages.send",
      inspectorSummary: {
        recipients: "a@b.com",
        other: "x",
        subject: { nested: "object" },
        count: ["array"],
      } as unknown as Record<string, string>,
    }));
    expect(out.facts).toEqual({ recipients: "a@b.com" });
  });
});

describe("gmail elicit-renderers — irreversible", () => {
  const r = gmailElicitRenderers.irreversible;

  it("FIXED (D-1): the message id comes from the path, never from body.id", () => {
    const out = r(input({
      operationId: "gmail.users.messages.delete",
      method: "DELETE",
      path: "/gmail/v1/users/me/messages/THE-MESSAGE-ACTUALLY-DELETED",
      pathParams: { userId: "me", id: "THE-MESSAGE-ACTUALLY-DELETED" },
      body: { id: "harmless-newsletter-id" },
    }));
    expect(out.headline).toBe("Confirm Gmail permanent delete (gmail.users.messages.delete)");
    expect(out.facts).toEqual({ messageId: "THE-MESSAGE-ACTUALLY-DELETED" });
    expect(JSON.stringify(out)).not.toContain("harmless-newsletter-id");
  });

  it("relabels a thread path id as threadId", () => {
    const out = r(input({
      operationId: "gmail.users.threads.delete",
      pathParams: { userId: "me", id: "18aaaaaaaaaaaaaa" },
    }));
    expect(out.facts).toEqual({ threadId: "18aaaaaaaaaaaaaa" });
  });

  it("keeps calendarId and eventId for a calendar event delete", () => {
    const out = r(input({
      operationId: "calendar.events.delete",
      pathParams: { calendarId: "primary", eventId: "BOARD-MEETING" },
    }));
    expect(out.headline).toBe("Confirm Gmail permanent delete (calendar.events.delete)");
    expect(out.facts).toEqual({ calendarId: "primary", eventId: "BOARD-MEETING" });
  });

  it("a path-derived target wins over an inspector summary claiming another", () => {
    const out = r(input({
      operationId: "gmail.users.messages.delete",
      pathParams: { userId: "me", id: "real" },
      inspectorSummary: { messageId: "decoy" },
    }));
    expect(out.facts).toEqual({ messageId: "real" });
  });

  it("a trash/spam filter is headlined with its effect and shows the effect first", () => {
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      pathParams: { userId: "me" },
      body: { criteria: { from: "x@y.z" }, action: { addLabelIds: ["TRASH"] } },
      inspectorSummary: { criteria: "{\"from\":\"x@y.z\"}", action: "{\"addLabelIds\":[\"TRASH\"]}" },
    }));
    expect(out.headline).toBe(
      "Confirm Gmail filter (gmail.users.settings.filters.create): moves matching mail to TRASH",
    );
    expect(out.facts).toEqual({
      effect: "moves matching mail to TRASH",
      from: "x@y.z",
      criteria: "{\"from\":\"x@y.z\"}",
      action: "{\"addLabelIds\":[\"TRASH\"]}",
    });
    expect(Object.keys(out.facts)[0]).toBe("effect");
  });

  it("filter effect reads snake_case keys, bare strings and any label case", () => {
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      body: { action: { add_label_ids: " spam ", remove_label_ids: ["Inbox"] } },
    }));
    expect(out.facts["effect"]).toBe("marks matching mail as spam; removes INBOX (archives matching mail)");
  });

  it("FIXED (D-1): a padded removeLabelIds list cannot push TRASH out of the dialog", () => {
    const padding = Array.from({ length: 40 }, (_, i) => `Label_${String(i).padStart(8, "0")}`);
    const action = { removeLabelIds: padding, addLabelIds: ["TRASH"] };
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      body: { criteria: { from: "security@bank.example" }, action },
      inspectorSummary: { criteria: JSON.stringify({ from: "security@bank.example" }), action: JSON.stringify(action) },
    }));
    expect(out.facts["effect"]).toBe("moves matching mail to TRASH");
    expect(out.headline).toContain("TRASH");
  });

  it("FIXED (D-1): criteria from/to/subject/query/negatedQuery are separate facts ahead of the JSON blob", () => {
    const criteria = {
      negatedQuery: "z".repeat(300),
      from: "security@bank.example",
      to: "me@corp.example",
      subject: "Your statement",
      query: "invoice",
    };
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      pathParams: { userId: "me" },
      body: { criteria, action: { addLabelIds: ["TRASH"] } },
      inspectorSummary: { criteria: JSON.stringify(criteria), action: "{}" },
    }));
    expect(Object.keys(out.facts)).toEqual([
      "effect", "from", "to", "subject", "query", "negatedQuery", "criteria", "action",
    ]);
    expect(out.facts["from"]).toBe("security@bank.example");
  });

  it("reads the snake_case negated_query spelling", () => {
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      body: { criteria: { negated_query: "keep" }, action: { addLabelIds: ["TRASH"] } },
    }));
    expect(out.facts["negatedQuery"]).toBe("keep");
  });

  it("shows both values when negatedQuery and negated_query are both sent", () => {
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      body: { criteria: { negatedQuery: "a", negated_query: "b" }, action: { addLabelIds: ["TRASH"] } },
    }));
    expect(out.facts["negatedQuery"]).toBe("a | b");
  });

  it("non-string criteria values are shown as JSON", () => {
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      body: { criteria: { from: ["a@b.c"] }, action: { addLabelIds: ["SPAM"] } },
    }));
    expect(out.facts["from"]).toBe("[\"a@b.c\"]");
  });
});

describe("gmail elicit-renderers — path relabelling", () => {
  it("does not clobber a real messageId path parameter with the relabelled id", () => {
    const out = gmailElicitRenderers.irreversible(input({
      operationId: "gmail.users.messages.attachments.get",
      pathParams: { userId: "me", messageId: "MSG", id: "ATT" },
    }));
    expect(out.facts).toEqual({ messageId: "MSG", id: "ATT" });
    const rev = gmailElicitRenderers.irreversible(input({
      operationId: "gmail.users.messages.attachments.get",
      pathParams: { id: "ATT", messageId: "MSG" },
    }));
    expect(rev.facts["messageId"]).toBe("MSG");
  });
});

describe("gmail elicit-renderers — bulk_destructive", () => {
  const r = gmailElicitRenderers.bulk_destructive;

  it("shows the id count and the first three ids with the remainder", () => {
    const out = r(input({
      operationId: "gmail.users.messages.batchDelete",
      pathParams: { userId: "me" },
      body: { ids: ["a", "b", "c", "d", "e"] },
    }));
    expect(out.headline).toBe("Confirm Gmail bulk delete (gmail.users.messages.batchDelete)");
    expect(out.facts).toEqual({ count: 5, ids: "a, b, c (+2)" });
  });

  it("no remainder suffix for three or fewer ids", () => {
    const out = r(input({ operationId: "gmail.users.messages.batchDelete", body: { ids: ["a", "b"] } }));
    expect(out.facts).toEqual({ count: 2, ids: "a, b" });
  });

  it("count 0 and no ids when the body carries no ids array", () => {
    const out = r(input({ operationId: "gmail.users.messages.batchDelete", body: {} }));
    expect(out.facts).toEqual({ count: 0 });
  });

  it("non-string ids are shown as JSON, not dropped", () => {
    const out = r(input({ operationId: "gmail.users.messages.batchDelete", body: { ids: [1, { x: 1 }] } }));
    expect(out.facts).toEqual({ count: 2, ids: "1, {\"x\":1}" });
  });
});

describe("gmail elicit-renderers — persistent_state", () => {
  const r = gmailElicitRenderers.persistent_state;

  it("shows the inspector's criteria and action", () => {
    const out = r(input({
      operationId: "gmail.users.settings.filters.create",
      pathParams: { userId: "me" },
      body: { criteria: { from: "x" }, action: { removeLabelIds: ["INBOX"] } },
      inspectorSummary: { criteria: "{\"from\":\"x\"}", action: "{\"removeLabelIds\":[\"INBOX\"]}" },
    }));
    expect(out.headline).toBe(
      "Confirm Gmail filter (gmail.users.settings.filters.create): removes INBOX (archives matching mail)",
    );
    expect(out.facts).toEqual({
      effect: "removes INBOX (archives matching mail)",
      from: "x",
      criteria: "{\"from\":\"x\"}",
      action: "{\"removeLabelIds\":[\"INBOX\"]}",
    });
  });
});

describe("gmail elicit-renderers — battery shape", () => {
  it("every renderer returns a headline and no confirm fact on an empty input", () => {
    for (const [cat, r] of Object.entries(gmailElicitRenderers)) {
      const out = r(input({ operationId: `x.${cat}` }));
      expect(out.headline, cat).not.toBe("");
      expect(Object.hasOwn(out.facts, "confirm"), cat).toBe(false);
    }
  });
});
