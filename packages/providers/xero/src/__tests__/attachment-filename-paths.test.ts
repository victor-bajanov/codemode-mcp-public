// F-1 regression: attachment file names containing `#` or `?` must stay
// reachable. The upload and download hints tell the model to build the path
// with encodeURIComponent(fileName); the matcher used to refuse the encoded
// `%23` / `%3F`, so such attachments could not be reached at all. They are
// safe: the wire path re-encodes every parameter.

import { describe, it, expect } from "vitest";
import { resolveOperation } from "@local/scaffold";
import { spec } from "../index";

const INVOICE = "11111111-1111-1111-1111-111111111111";

describe("Xero attachment paths with # or ? in the file name", () => {
  for (const fileName of ["Receipt #123.pdf", "what?.pdf", "my file.pdf", "100% done.pdf", "résumé.pdf"]) {
    it(`${JSON.stringify(fileName)} resolves to the attachment operation`, () => {
      const path = `/api.xro/2.0/Invoices/${INVOICE}/Attachments/${encodeURIComponent(fileName)}`;
      const op = resolveOperation(spec, "GET", path);
      expect(op, path).not.toBeNull();
      // First template wins: the ById and ByFileName templates share a shape.
      expect(op!.operationId).toMatch(/^xero\.accounting\.getInvoiceAttachmentBy/);
    });
  }
});
