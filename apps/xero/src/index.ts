import { setupProvider } from "@local/scaffold";
import { xeroProvider } from "@local/providers-xero";

export const { McpAgent: XeroMCP, default: OAuthHandler } = setupProvider(xeroProvider);
export default OAuthHandler;
