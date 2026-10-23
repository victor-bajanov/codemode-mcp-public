import { vi } from "vitest";

/** In-memory stand-in for a Durable Object's `ctx.storage` (the async KV API
 *  plus alarms). Values are structured-cloned on the way in and out, as the
 *  runtime serialises them. Every method is a `vi.fn`, so a test can make one
 *  fail or record call order. Share one instance between two broker objects
 *  to model the DO being evicted and re-created over the same storage. */
export function makeDoStorage() {
  const data = new Map<string, unknown>();
  let alarm: number | null = null;
  const storage = {
    data,
    get alarmAt(): number | null { return alarm; },
    get: vi.fn(async (key: string) => {
      const v = data.get(key);
      return v === undefined ? undefined : structuredClone(v);
    }),
    put: vi.fn(async (key: string, value: unknown) => { data.set(key, structuredClone(value)); }),
    delete: vi.fn(async (keys: string | string[]) => {
      if (Array.isArray(keys)) {
        // The runtime refuses a delete of more than 128 keys in one call.
        if (keys.length > 128) throw new RangeError("Maximum number of keys to delete is 128");
        let n = 0;
        for (const k of keys) if (data.delete(k)) n++;
        return n;
      }
      return data.delete(keys);
    }),
    list: vi.fn(async (opts?: { prefix?: string }) => {
      const out = new Map<string, unknown>();
      for (const k of [...data.keys()].sort()) {
        if (!opts?.prefix || k.startsWith(opts.prefix)) out.set(k, structuredClone(data.get(k)));
      }
      return out;
    }),
    getAlarm: vi.fn(async () => alarm),
    setAlarm: vi.fn(async (at: number | Date) => { alarm = typeof at === "number" ? at : at.getTime(); }),
    deleteAlarm: vi.fn(async () => { alarm = null; }),
  };
  return storage;
}

export type FakeDoStorage = ReturnType<typeof makeDoStorage>;

/** A `DurableObjectState` carrying only what the token broker uses: storage
 *  and `waitUntil` (a `vi.fn` unless the test passes its own). */
export function makeDoState(
  storage: FakeDoStorage = makeDoStorage(),
  waitUntil: (promise: Promise<unknown>) => void = vi.fn(),
): DurableObjectState {
  return { storage, waitUntil } as unknown as DurableObjectState;
}
