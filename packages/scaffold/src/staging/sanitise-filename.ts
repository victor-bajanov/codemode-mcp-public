// A staged row's `filename` came from `register_file_handle` or the sandbox,
// so it may carry controls (C0/C1), Unicode format characters (category Cf:
// bidi overrides, zero-width chars, BOM) or lone surrogates. Strip them, cap
// at 255 code points, and treat an empty result as no filename.

const STRIP = /[\u0000-\u001F\u007F-\u009F]|\p{Cf}|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/gu;

export function sanitiseRowFilename(filename: string | null): string | null {
  if (filename === null) return null;
  const clean = [...filename.replace(STRIP, "")].slice(0, 255).join("");
  return clean.length > 0 ? clean : null;
}
