import { describe, it, expect } from "vitest";
import { runClientSweep, type ClientSweepKv } from "../oauth-client-sweep";

/** In-memory KV that paginates lists in fixed-size pages to exercise cursors. */
function fakeKv(pageSize = 1000): ClientSweepKv & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    async list({ prefix, cursor }) {
      const all = [...data.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number.parseInt(cursor, 10) : 0;
      const slice = all.slice(start, start + pageSize);
      const next = start + pageSize;
      const complete = next >= all.length;
      return {
        keys: slice.map((name) => ({ name })),
        list_complete: complete,
        ...(complete ? {} : { cursor: String(next) }),
      };
    },
    async get(key: string) {
      return data.get(key) ?? null;
    },
    async delete(key: string) {
      data.delete(key);
    },
  };
}

const DAY = 24 * 60 * 60 * 1000;
const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const NOW = 1_000_000_000_000;

function client(kv: ReturnType<typeof fakeKv>, id: string) {
  kv.data.set(`client:${id}`, JSON.stringify({ clientId: id }));
}
function stamp(kv: ReturnType<typeof fakeKv>, id: string, registeredAt: number) {
  kv.data.set(`clientreg:${id}`, JSON.stringify({ registeredAt }));
}
function grant(kv: ReturnType<typeof fakeKv>, userId: string, grantId: string, clientId: string) {
  kv.data.set(`grant:${userId}:${grantId}`, JSON.stringify({ clientId, id: grantId }));
}

describe("runClientSweep", () => {
  it("reaps an ungranted, stamped, aged client and its stamp", async () => {
    const kv = fakeKv();
    client(kv, "old");
    stamp(kv, "old", NOW - 31 * DAY);

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW });

    expect(r).toEqual({ scannedClients: 1, grantedClients: 0, stampedClients: 1, reapedClients: 1 });
    expect(kv.data.has("client:old")).toBe(false);
    expect(kv.data.has("clientreg:old")).toBe(false);
  });

  it("keeps a fresh ungranted client (within TTL — mid-authorization)", async () => {
    const kv = fakeKv();
    client(kv, "fresh");
    stamp(kv, "fresh", NOW - 1 * DAY);

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW });

    expect(r.reapedClients).toBe(0);
    expect(r.stampedClients).toBe(1);
    expect(kv.data.has("client:fresh")).toBe(true);
  });

  it("never reaps a granted client, even when aged", async () => {
    const kv = fakeKv();
    client(kv, "granted");
    stamp(kv, "granted", NOW - 90 * DAY);
    grant(kv, "user-1", "g1", "granted");

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW });

    expect(r).toEqual({ scannedClients: 1, grantedClients: 1, stampedClients: 0, reapedClients: 0 });
    expect(kv.data.has("client:granted")).toBe(true);
  });

  it("never reaps an unstamped (legacy) client, even when ungranted", async () => {
    const kv = fakeKv();
    client(kv, "legacy"); // no stamp

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW });

    expect(r.reapedClients).toBe(0);
    expect(r.stampedClients).toBe(0);
    expect(kv.data.has("client:legacy")).toBe(true);
  });

  it("dryRun computes the reap count without deleting", async () => {
    const kv = fakeKv();
    client(kv, "old");
    stamp(kv, "old", NOW - 31 * DAY);

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW, dryRun: true });

    expect(r.reapedClients).toBe(1);
    expect(kv.data.has("client:old")).toBe(true);
    expect(kv.data.has("clientreg:old")).toBe(true);
  });

  it("handles a mixed population and paginates over cursors", async () => {
    const kv = fakeKv(2); // tiny pages to force cursor iteration
    // aged ungranted → reap
    client(kv, "a1"); stamp(kv, "a1", NOW - 40 * DAY);
    client(kv, "a2"); stamp(kv, "a2", NOW - 60 * DAY);
    // fresh ungranted → keep
    client(kv, "f1"); stamp(kv, "f1", NOW - 2 * DAY);
    // aged but granted → keep
    client(kv, "g1"); stamp(kv, "g1", NOW - 100 * DAY); grant(kv, "u", "gr1", "g1");
    // legacy unstamped ungranted → keep
    client(kv, "l1");

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW });

    expect(r.scannedClients).toBe(5);
    expect(r.grantedClients).toBe(1);
    expect(r.reapedClients).toBe(2);
    expect(kv.data.has("client:a1")).toBe(false);
    expect(kv.data.has("client:a2")).toBe(false);
    expect(kv.data.has("client:f1")).toBe(true);
    expect(kv.data.has("client:g1")).toBe(true);
    expect(kv.data.has("client:l1")).toBe(true);
  });

  it("ignores malformed grant values (errs toward keeping clients)", async () => {
    const kv = fakeKv();
    client(kv, "c1");
    stamp(kv, "c1", NOW - 40 * DAY);
    kv.data.set("grant:u:bad", "{not-json");

    const r = await runClientSweep(kv, { clientTtlSeconds: TTL_SECONDS, nowMs: NOW });

    // grant unparseable → c1 counts as ungranted → aged → reaped
    expect(r.grantedClients).toBe(0);
    expect(r.reapedClients).toBe(1);
  });
});
