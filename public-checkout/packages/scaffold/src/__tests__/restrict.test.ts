// Partial order: allow < elicit < deny.
// mostRestrictive(a, b) returns whichever is further along the order
// (i.e. the maximum under this ordering). Inspectors can only tighten
// a static decision, never weaken it.

import { describe, it, expect } from "vitest";
import { mostRestrictive } from "../restrict";
import type { Decision } from "@local/shared";

describe("mostRestrictive", () => {
  it.each<[Decision, Decision, Decision]>([
    // (a,        b,        expected)
    ["allow",  "allow",  "allow"],
    ["allow",  "elicit", "elicit"],
    ["allow",  "deny",   "deny"],
    ["elicit", "allow",  "elicit"],
    ["elicit", "elicit", "elicit"],
    ["elicit", "deny",   "deny"],
    ["deny",   "allow",  "deny"],
    ["deny",   "elicit", "deny"],
    ["deny",   "deny",   "deny"],
  ])("mostRestrictive(%s, %s) === %s", (a, b, expected) => {
    expect(mostRestrictive(a, b)).toBe(expected);
  });
});
