import { parse as parseYaml } from "yaml";

export function parseSpecYaml(content: string): {
  paths: Record<string, unknown>;
  components?: { schemas?: Record<string, unknown> };
  [k: string]: unknown;
} {
  const doc = parseYaml(content);
  if (!doc || typeof doc !== "object") {
    throw new Error("parseSpecYaml: not an object");
  }
  if (!("paths" in doc)) {
    throw new Error("parseSpecYaml: missing `paths`");
  }
  return doc as { paths: Record<string, unknown> };
}
