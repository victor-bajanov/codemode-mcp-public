// Shared description-budget + docs-completeness battery
// (description-budget-docs-surface, spec D3/D7) — see providerDescriptionBudgetTests
// in @local/scaffold/testing so all providers share the same battery.

import { providerDescriptionBudgetTests } from "@local/scaffold/testing";
import { gmailProvider } from "../index";

// Gmail's worker has staging (D1 + R2 + upload origin) configured.
// expectsCrlfJoin: GMAIL_ATTACHMENT_HINT's RFC 822 snippet builds a body via
// `.join("\r\n")` (spec D7) — require it outright rather than only checking
// docs.full IF it happens to be there (review finding F1).
providerDescriptionBudgetTests(gmailProvider, {
  stagingEnabled: true,
  expectsCrlfJoin: true,
  expectCompactHint: true,
});
