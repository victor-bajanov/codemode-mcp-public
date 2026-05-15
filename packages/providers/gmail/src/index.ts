import type { ApiProvider } from "@local/scaffold";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import specJson from "./spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { gmailElicitRenderers } from "./elicit-renderers.js";

const spec = specJson as unknown as OpenApiSpec;

export const gmailProvider: ApiProvider = {
  name: "gmail",
  displayName: "Gmail (personal)",
  oauth: {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: [
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.settings.basic",
      "openid",
      "email",
      "profile",
    ],
    clientIdSecretName: "GOOGLE_CLIENT_ID",
    clientSecretSecretName: "GOOGLE_CLIENT_SECRET",
    userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    extraAuthorizeParams: {
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: "true",
    },
  },
  spec,
  surfaceReview,
  elicitRenderers: gmailElicitRenderers,
  apiBaseUrl: "https://gmail.googleapis.com",
  audit: {
    principalIdAccessor: (props) => props.userId as string | undefined,
  },
};

// re-exports for places that import bare:
export { spec, surfaceReview };
