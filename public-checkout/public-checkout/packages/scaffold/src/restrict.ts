// Partial order: allow < elicit < deny. Returns the maximum (most restrictive) of two decisions.

import type { Decision } from "@local/shared";

const RANK: Record<Decision, number> = { allow: 0, elicit: 1, deny: 2 };

export function mostRestrictive(a: Decision, b: Decision): Decision {
  return RANK[a] >= RANK[b] ? a : b;
}
