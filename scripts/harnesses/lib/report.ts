/**
 * Tiny PASS/FAIL reporter shared by both harnesses. Keeps output greppable
 * (`PASS:` / `FAIL:` prefixes) and prints a summary block before exit.
 */

export interface Assertion {
  label: string;
  ok: boolean;
  detail?: string | undefined;
}

export function printAssertions(assertions: readonly Assertion[]): boolean {
  let allOk = true;
  for (const a of assertions) {
    const tag = a.ok ? "PASS" : "FAIL";
    if (!a.ok) allOk = false;
    const detail = a.detail !== undefined ? ` — ${a.detail}` : "";
    process.stdout.write(`  ${tag}: ${a.label}${detail}\n`);
  }
  return allOk;
}

export function summary(label: string, ok: boolean): void {
  process.stdout.write("\n");
  process.stdout.write(`=== ${label}: ${ok ? "PASS" : "FAIL"} ===\n`);
}

export function dumpTail(label: string, lines: readonly string[], count = 20): void {
  process.stderr.write(`\n--- ${label} (last ${count}) ---\n`);
  for (const l of lines.slice(-count)) {
    process.stderr.write(`${l}\n`);
  }
  process.stderr.write(`--- end ${label} ---\n`);
}
