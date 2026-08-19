// Shared description-budget + docs-completeness battery
// (description-budget-docs-surface, spec D3/D7) — see providerDescriptionBudgetTests
// in @local/scaffold/testing so all providers share the same battery.

import { providerDescriptionBudgetTests } from "@local/scaffold/testing";
import { xeroProvider } from "../index";

// Xero's worker has staging (D1 + R2 + upload origin) configured.
providerDescriptionBudgetTests(xeroProvider, {
  stagingEnabled: true,
  expectCompactHint: true,
});
