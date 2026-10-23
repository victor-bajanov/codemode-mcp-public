import type { ApiProvider } from "./api-provider";

/** The principal a set of props resolves to: the provider's audit accessor
 *  when it has one, else a string `props.userId`; null when neither yields
 *  one. Single definition shared by the MCP session binding (F-16), the
 *  broker addressing in buildUpstreamArgs and the sign-in slot seed in
 *  /callback, so the key the seed writes is the one the broker reads. */
export function principalOf<P extends Record<string, unknown>>(
  provider: Pick<ApiProvider<P, never>, "audit">,
  props: P | undefined,
): string | null {
  if (props === undefined || props === null) return null;
  return (
    provider.audit?.principalIdAccessor?.(props) ??
    (typeof (props as Record<string, unknown>).userId === "string"
      ? ((props as Record<string, unknown>).userId as string)
      : null)
  );
}
