# better-auth-eve-online

[![NPM Version](https://img.shields.io/npm/v/%40localisprimary%2Fbetter-auth-eve-online?style=flat)](https://www.npmjs.com/package/@localisprimary/better-auth-eve-online)

A small, secure [EVE Online SSO](https://developers.eveonline.com/docs/services/sso/) provider helper for [Better Auth](https://better-auth.com/). It is built for Better Auth's Generic OAuth plugin and has zero runtime dependencies.

The provider:

- uses EVE's authorization-code flow with PKCE;
- authenticates confidential token requests with `client_secret_basic`;
- verifies EVE's signed JWT access token against the JWKS URL discovered from EVE's metadata endpoint;
- validates the signature, issuer, expiry, authorized party, and both required audiences;
- maps the selected EVE character to a Better Auth profile; and
- caches signing keys for five minutes and refreshes immediately when it sees an unknown key ID.

## Install

```sh
pnpm add better-auth-eve-online better-auth
```

This package supports Better Auth 1.7 or newer.

## Configure EVE

Create an application in the [EVE Developers portal](https://developers.eveonline.com/applications). Register the exact Better Auth callback URL:

```text
https://your-domain.example/api/auth/callback/eve-online
```

For local development that is usually:

```text
http://localhost:3000/api/auth/callback/eve-online
```

The origin and Better Auth base path must match your actual `baseURL` configuration. Assign every ESI scope that your application will request in the EVE application settings.

## Configure Better Auth

```ts
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { eveOnline } from "better-auth-eve-online";

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL,
  plugins: [
    genericOAuth({
      config: [
        eveOnline({
          clientId: process.env.EVE_CLIENT_ID!,
          clientSecret: process.env.EVE_CLIENT_SECRET!,
          scopes: [
            "esi-skills.read_skills.v1",
            "esi-skills.read_skillqueue.v1",
          ],
        }),
      ],
    }),
  ],
});
```

Keep `EVE_CLIENT_SECRET` on the server. If the application only needs sign-in and no authenticated ESI routes, omit `scopes`.

Start sign-in using Better Auth's standard social API:

```ts
await authClient.signIn.social({
  provider: "eve-online",
  callbackURL: "/dashboard",
});
```

## Character identity and email

EVE SSO authenticates the character selected during login. It does not expose the player's email address. The provider therefore uses the immutable JWT subject (`CHARACTER:EVE:<character-id>`) as the external account identity and supplies `<character-id>@eve.invalid` as Better Auth's required email field.

The `.invalid` domain is reserved and can never receive mail. `emailVerified` is always `false`. Do not enable Better Auth's `requireEmailVerification` for this provider. If your user model needs a reachable email address, collect and verify it separately after sign-in.

The raw OAuth profile includes:

```ts
interface EveOnlineProfile {
  id: string;
  sub: `CHARACTER:EVE:${string}`;
  characterId: string;
  name: string;
  email: string;
  emailVerified: false;
  image: string;
  scopes: string[];
  characterOwnerHash?: string;
  tenant?: string;
  region?: string;
  tier?: string;
  claims: EveOnlineAccessTokenClaims;
}
```

Use `mapProfileToUser` for additional Better Auth user fields:

```ts
eveOnline({
  clientId: process.env.EVE_CLIENT_ID!,
  clientSecret: process.env.EVE_CLIENT_SECRET!,
  mapProfileToUser: (profile) => ({
    eveCharacterId: String(profile.characterId),
  }),
});
```

Define `eveCharacterId` in Better Auth's `user.additionalFields` when using that example.

## Standalone token verification

The same verifier can validate EVE access tokens before an ESI request. Reuse the created function so its JWKS cache remains warm:

```ts
import { createEveOnlineAccessTokenVerifier } from "better-auth-eve-online";

const verifyEveToken = createEveOnlineAccessTokenVerifier({
  clientId: process.env.EVE_CLIENT_ID!,
});

const character = await verifyEveToken(accessToken);
console.log(character.characterId, character.scopes);
```

Validation failures throw `EveOnlineTokenError` with a machine-readable `code`. The provider itself converts validation failures to `null`, allowing Better Auth to stop the OAuth callback through its normal `unable_to_get_user_info` path.

## Options

In addition to `clientId` and `clientSecret`, `eveOnline` accepts:

- `scopes`, `redirectURI`, `disableImplicitSignUp`, `disableSignUp`, `overrideUserInfo`, and `mapProfileToUser` from Better Auth's Generic OAuth configuration;
- `pkce` (default `true`);
- `portraitSize` (`32`, `64`, `128`, `256`, `512`, or `1024`; default `256`);
- `jwksCacheTtlMs` (default five minutes);
- `clockToleranceSeconds` (default 30); and
- `fetch`, to override access-token metadata and JWKS requests, typically in tests.

## Development

```sh
pnpm install
pnpm check
```

Vite builds the ESM library, TypeScript emits declarations, Vitest exercises token validation, ESLint performs type-aware linting, and Prettier enforces formatting.

## License

MIT
