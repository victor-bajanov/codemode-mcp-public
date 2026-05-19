export function deepFreeze<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (value === null || typeof value !== "object") return value;
  const obj = value as object;
  if (seen.has(obj)) return value;
  seen.add(obj);
  Object.freeze(obj);
  for (const key of Object.keys(obj)) {
    const v = (obj as Record<string, unknown>)[key];
    if (v !== null && typeof v === "object") deepFreeze(v, seen);
  }
  return value;
}
