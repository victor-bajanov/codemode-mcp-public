// C-2 (2026-11 security review): sandbox console output separated from the
// host log stream.
//
// codemode 0.4.2's generated executor.js overrides exactly console.log, .warn
// and .error inside `evaluate()` (capturing them into the run's `logs`), then
// emits every provider's `prelude` string, then the LLM code. Every other
// console method (info, debug, trace, table, …) was left as the runtime's own,
// so sandbox code could print a line byte-identical to a genuine
// `AUDIT {…}` line from auditLog(). The scaffold's `__docsHost` provider —
// handed to every sandbox run, `search` included — carries the prelude below.

/** The console methods codemode itself captures; the prelude leaves them be. */
export const SANDBOX_CONSOLE_KEEP = ["log", "warn", "error"] as const;

/** Emitted by codemode after its console.log/warn/error overrides and before the LLM code:
 *  every other console method (info, debug, trace, table, dir, group*, count*, time*, assert,
 *  profile*, timeStamp, context, createTask, and anything the runtime adds) is late-bound to
 *  console.log, i.e. codemode's capturing override — so nothing the sandbox prints reaches the
 *  host's log stream, and no line it writes can be mistaken for an AUDIT line (C-2).
 *  Late-bound: `console.log` is read at call time, so it is the capturing override; the
 *  originals are unreferenced once replaced and cannot be recovered by later code. Each
 *  assignment is guarded on its own, so a non-writable method (or a frozen console) cannot
 *  stop the rest, and the block never throws. */
export const SANDBOX_CONSOLE_PRELUDE =
  "    try { " +
  `const __keep = new Set(${JSON.stringify(SANDBOX_CONSOLE_KEEP)}); ` +
  "const __names = new Set([...Object.getOwnPropertyNames(console), " +
  '"info", "debug", "trace", "dir", "dirxml", "table", "group", "groupCollapsed", "groupEnd", ' +
  '"count", "countReset", "time", "timeEnd", "timeLog", "assert", "profile", "profileEnd", ' +
  '"timeStamp", "context", "createTask"]); ' +
  "for (const __m of __names) { " +
  'if (!__keep.has(__m) && typeof console[__m] === "function") { ' +
  "try { console[__m] = (...__a) => console.log(...__a); } catch {} } } " +
  "} catch {}";
