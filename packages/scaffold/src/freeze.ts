export function deepFreeze<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (value === null || typeof value !== "object") return value;
  // TypedArrays / DataViews are exempt: `Object.freeze` throws
  // `TypeError: Cannot freeze array buffer views with elements` on any non-empty
  // view, and freezing them is meaningless anyway (their bytes are not
  // configurable properties). Return them unfrozen — callers rely on this so an
  // inspected `rawBody: Uint8Array` payload does not crash deepFreeze.
  if (ArrayBuffer.isView(value)) return value;
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
