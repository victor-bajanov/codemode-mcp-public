import { setupProvider } from "@local/scaffold";
import { gmailProvider } from "@local/providers-gmail";

export const {
  McpAgent: GmailMCP,
  TokenBrokerDO: GmailTokenBroker,
  default: OAuthHandler,
} = setupProvider(gmailProvider);
export default OAuthHandler;
