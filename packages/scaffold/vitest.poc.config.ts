// Security-review proof-of-concept harness. These tests document the
// behaviour observed during the 2026-10 defensive security review; they are
// deliberately excluded from the default `pnpm test` run (see vitest.config.ts)
// and executed with:
//   npx vitest run --config vitest.poc.config.ts
import { defineConfig } from "vitest/config";
import base from "./vitest.config";

export default defineConfig({
  ...base,
  test: {
    include: ["src/__tests__/security-poc/**/*.poc.test.ts"],
    exclude: ["**/node_modules/**"],
  },
});
