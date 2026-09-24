import { setupProvider } from "@local/scaffold";
import { opticalProvider } from "@local/providers-optical";

export const {
  McpAgent: OpticalMCP,
  TokenBrokerDO: OpticalTokenBroker,
  default: OAuthHandler,
} = setupProvider(opticalProvider);
export default OAuthHandler;
