// Shared description-budget + docs-completeness battery
// (description-budget-docs-surface, spec D3/D7) — see providerDescriptionBudgetTests
// in @local/scaffold/testing so all providers share the same battery.

import { providerDescriptionBudgetTests } from "@local/scaffold/testing";
import { opticalProvider } from "../index";

// Optical's worker has no staging (D1/R2/upload origin) configured.
providerDescriptionBudgetTests(opticalProvider, {
  stagingEnabled: false,
  expectCompactHint: true,
});
