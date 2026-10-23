import { describe, it, expect } from "vitest";
import { sanitiseRowFilename } from "../sanitise-filename";

describe("sanitiseRowFilename", () => {
  it("strips C0/C1 controls, Cf format characters and lone surrogates", () => {
    expect(sanitiseRowFilename("a\r\nb\uD800c")).toBe("abc");
    expect(sanitiseRowFilename("x\u0085y\u009fz")).toBe("xyz");
    expect(sanitiseRowFilename("evil\u202Efdp.exe")).toBe("evilfdp.exe");
    expect(sanitiseRowFilename("z\u200Bw\uFEFF")).toBe("zw");
  });

  it("keeps paired surrogates and ordinary Unicode", () => {
    expect(sanitiseRowFilename("résumé 📄.pdf")).toBe("résumé 📄.pdf");
  });

  it("caps at 255 code points without splitting a pair", () => {
    const out = sanitiseRowFilename("📄".repeat(300))!;
    expect([...out]).toHaveLength(255);
    expect((out as unknown as { isWellFormed(): boolean }).isWellFormed()).toBe(true);
  });

  it("returns null when nothing survives, or for null", () => {
    expect(sanitiseRowFilename("\u0000")).toBeNull();
    expect(sanitiseRowFilename("\u202E\r")).toBeNull();
    expect(sanitiseRowFilename(null)).toBeNull();
  });
});
