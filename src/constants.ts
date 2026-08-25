export const EVE_ONLINE_PROVIDER_ID = "eve-online" as const;
export const EVE_ONLINE_PROVIDER_NAME = "EVE Online" as const;

export const EVE_SSO_ISSUER = "https://login.eveonline.com" as const;
export const EVE_SSO_AUTHORIZATION_URL =
  "https://login.eveonline.com/v2/oauth/authorize" as const;
export const EVE_SSO_TOKEN_URL =
  "https://login.eveonline.com/v2/oauth/token" as const;
export const EVE_SSO_DISCOVERY_URL =
  "https://login.eveonline.com/.well-known/oauth-authorization-server" as const;
export const EVE_SSO_AUDIENCE = "EVE Online" as const;
export const EVE_IMAGE_SERVER_URL = "https://images.evetech.net" as const;

export const EVE_ONLINE_CALLBACK_PATH =
  `/api/auth/callback/${EVE_ONLINE_PROVIDER_ID}` as const;

export const EVE_PORTRAIT_SIZES = [32, 64, 128, 256, 512, 1024] as const;

export type EvePortraitSize = (typeof EVE_PORTRAIT_SIZES)[number];
