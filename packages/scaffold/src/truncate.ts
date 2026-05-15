const DEFAULT_BUDGET_BYTES = 64 * 1024;

function byteSize(s: string): number {
  return new TextEncoder().encode(s).length;
}

function truncateString(s: string, budget: number): string {
  if (byteSize(s) <= budget) return s;
  const sliceLen = Math.max(0, budget - 30);
  return s.slice(0, sliceLen) + ` ... [TRUNCATED ${byteSize(s) - sliceLen} bytes]`;
}

export function truncateForReturn(value: unknown, budget = DEFAULT_BUDGET_BYTES): unknown {
  if (typeof value === "string") return truncateString(value, budget);
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    let used = 2;     // "[]"
    for (const item of value) {
      const next = truncateForReturn(item, budget);
      const nextSize = byteSize(JSON.stringify(next));
      if (used + nextSize > budget) {
        out.push(`[TRUNCATED ${value.length - out.length} more items]`);
        return out;
      }
      out.push(next);
      used += nextSize + 1;
    }
    return out;
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    let used = 2;     // "{}"
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const next = truncateForReturn(v, budget);
      const nextSize = byteSize(JSON.stringify({ [k]: next }));
      if (used + nextSize > budget) {
        // Still include the truncated value and mark that we ran out of budget
        out[k] = next;
        out["__truncated__"] = true;
        return out;
      }
      out[k] = next;
      used += nextSize;
    }
    return out;
  }
  return value;
}

export function stringifyForMcpResult(value: unknown, budget = DEFAULT_BUDGET_BYTES): string {
  const truncated = truncateForReturn(value, budget);
  if (typeof truncated === "string") return truncated;
  return JSON.stringify(truncated, null, 2);
}
