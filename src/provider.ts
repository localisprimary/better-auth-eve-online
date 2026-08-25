import type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth";

import {
  EVE_ONLINE_PROVIDER_ID,
  EVE_ONLINE_PROVIDER_NAME,
  EVE_SSO_AUTHORIZATION_URL,
  EVE_SSO_ISSUER,
  EVE_SSO_TOKEN_URL,
  type EvePortraitSize,
} from "./constants";
import {
  createEveOnlineAccessTokenVerifier,
  type EveOnlineProfile,
} from "./token";

type ForwardedProviderOptions = Pick<
  GenericOAuthConfig,
  | "disableImplicitSignUp"
  | "disableSignUp"
  | "overrideUserInfo"
  | "redirectURI"
  | "scopes"
>;

type MappedUser = ReturnType<
  NonNullable<GenericOAuthConfig["mapProfileToUser"]>
>;

export type EveOnlineMapProfileToUser = (
  profile: EveOnlineProfile,
) => MappedUser;

export interface EveOnlineOptions extends ForwardedProviderOptions {
  /** Client ID from the EVE Developers application page. */
  clientId: string;
  /** Client secret from the EVE Developers application page. */
  clientSecret: string;
  /** Keep PKCE enabled unless an older EVE application configuration rejects it.
   * @default true
   */
  pkce?: boolean;
  /** Portrait resolution exposed as the Better Auth user's image. Defaults to 256.
   * @default 256 */
  portraitSize?: EvePortraitSize;
  /** Override fetch for access-token metadata and JWKS requests. */
  fetch?: typeof globalThis.fetch;
  /** How long EVE's discovered signing keys remain cached. Defaults to five minutes. */
  jwksCacheTtlMs?: number;
  /** Allowed clock skew when checking access-token timestamps. Defaults to 30 seconds. */
  clockToleranceSeconds?: number;
  /** Map the verified EVE profile to mutable Better Auth user fields. */
  mapProfileToUser?: EveOnlineMapProfileToUser;
}

/**
 * Create an EVE Online configuration for Better Auth's Generic OAuth plugin.
 *
 * EVE identifies a selected character, not the player's login account. Each
 * character therefore becomes its own Better Auth account subject.
 */
export function eveOnline(
  options: EveOnlineOptions,
): GenericOAuthConfig<typeof EVE_ONLINE_PROVIDER_ID> {
  if (options.clientId.trim().length === 0) {
    throw new TypeError("clientId must not be empty");
  }
  if (options.clientSecret.trim().length === 0) {
    throw new TypeError("clientSecret must not be empty");
  }

  const verifyAccessToken = createEveOnlineAccessTokenVerifier({
    clientId: options.clientId,
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.jwksCacheTtlMs === undefined
      ? {}
      : { jwksCacheTtlMs: options.jwksCacheTtlMs }),
    ...(options.clockToleranceSeconds === undefined
      ? {}
      : { clockToleranceSeconds: options.clockToleranceSeconds }),
    ...(options.portraitSize === undefined
      ? {}
      : { portraitSize: options.portraitSize }),
  });
  const mapProfileToUser = options.mapProfileToUser;

  return {
    providerId: EVE_ONLINE_PROVIDER_ID,
    name: EVE_ONLINE_PROVIDER_NAME,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: EVE_SSO_AUTHORIZATION_URL,
    tokenUrl: EVE_SSO_TOKEN_URL,
    tokenEndpointAuth: { method: "client_secret_basic" },
    accountIssuer: EVE_SSO_ISSUER,
    accountSubject: ({ profile }) => profile.sub as string,
    pkce: options.pkce ?? true,
    getUserInfo: async (tokens) => {
      if (!tokens.accessToken) {
        return null;
      }
      try {
        return await verifyAccessToken(tokens.accessToken);
      } catch {
        return null;
      }
    },
    ...(options.scopes === undefined ? {} : { scopes: options.scopes }),
    ...(options.redirectURI === undefined
      ? {}
      : { redirectURI: options.redirectURI }),
    ...(mapProfileToUser === undefined
      ? {}
      : {
          mapProfileToUser: (profile) =>
            mapProfileToUser(profile as EveOnlineProfile),
        }),
    ...(options.disableImplicitSignUp === undefined
      ? {}
      : { disableImplicitSignUp: options.disableImplicitSignUp }),
    ...(options.disableSignUp === undefined
      ? {}
      : { disableSignUp: options.disableSignUp }),
    ...(options.overrideUserInfo === undefined
      ? {}
      : { overrideUserInfo: options.overrideUserInfo }),
  };
}
