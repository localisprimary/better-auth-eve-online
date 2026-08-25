import { webcrypto } from "node:crypto";

import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  EVE_ONLINE_PROVIDER_ID,
  EVE_SSO_AUTHORIZATION_URL,
  EVE_SSO_DISCOVERY_URL,
  EVE_SSO_TOKEN_URL,
  createEveOnlineAccessTokenVerifier,
  eveOnline,
} from "../src";

const CLIENT_ID = "test-client-id";
const KEY_ID = "test-key";
const JWKS_URL = "https://login.eveonline.com/oauth/jwks";

afterEach(() => {
  vi.unstubAllGlobals();
});

function encodeBase64Url(value: Uint8Array | string): string {
  const bytes =
    typeof value === "string" ? new TextEncoder().encode(value) : value;
  return Buffer.from(bytes).toString("base64url");
}

async function createSigningFixture() {
  const keyPair = (await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicJwk = {
    ...(await webcrypto.subtle.exportKey("jwk", keyPair.publicKey)),
    kid: KEY_ID,
    alg: "RS256",
    use: "sig",
  };

  const sign = async (overrides: Record<string, unknown> = {}) => {
    const header = encodeBase64Url(
      JSON.stringify({ alg: "RS256", typ: "JWT", kid: KEY_ID }),
    );
    const payload = encodeBase64Url(
      JSON.stringify({
        iss: "login.eveonline.com",
        aud: [CLIENT_ID, "EVE Online"],
        azp: CLIENT_ID,
        sub: "CHARACTER:EVE:2112345678",
        name: "Ada Lovelace",
        owner: "owner-hash",
        scp: ["esi-skills.read_skills.v1"],
        tenant: "tranquility",
        exp: Math.floor(Date.now() / 1000) + 1200,
        ...overrides,
      }),
    );
    const input = `${header}.${payload}`;
    const signature = await webcrypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      keyPair.privateKey,
      new TextEncoder().encode(input),
    );
    return `${input}.${encodeBase64Url(new Uint8Array(signature))}`;
  };

  const fetchMock = vi.fn<typeof fetch>((input) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url === EVE_SSO_DISCOVERY_URL) {
      return Promise.resolve(Response.json({ jwks_uri: JWKS_URL }));
    }
    if (url === JWKS_URL) {
      return Promise.resolve(Response.json({ keys: [publicJwk] }));
    }
    return Promise.resolve(new Response(null, { status: 404 }));
  });

  return { fetchMock, sign };
}

describe("eveOnline", () => {
  it("creates a Better Auth Generic OAuth configuration", () => {
    const provider = eveOnline({
      clientId: CLIENT_ID,
      clientSecret: "secret",
      scopes: ["esi-skills.read_skills.v1"],
      mapProfileToUser: (profile) => ({
        name: `${profile.characterId.toUpperCase()}:${profile.name}`,
      }),
    });

    expect(provider.providerId).toBe(EVE_ONLINE_PROVIDER_ID);
    expect(provider.discoveryUrl).toBe(EVE_SSO_DISCOVERY_URL);
    expect(provider.authorizationUrl).toBeUndefined();
    expect(provider.tokenUrl).toBeUndefined();
    expect(provider.tokenEndpointAuth).toEqual({
      method: "client_secret_basic",
    });
    expect(provider.pkce).toBe(true);
    expect(provider.scopes).toEqual(["esi-skills.read_skills.v1"]);
  });

  it("rejects missing credentials immediately", () => {
    expect(() => eveOnline({ clientId: "", clientSecret: "secret" })).toThrow(
      "clientId must not be empty",
    );
    expect(() => eveOnline({ clientId: CLIENT_ID, clientSecret: "" })).toThrow(
      "clientSecret must not be empty",
    );
  });

  it("returns null to Better Auth when token validation fails", async () => {
    const provider = eveOnline({
      clientId: CLIENT_ID,
      clientSecret: "secret",
      fetch: vi.fn(),
    });

    await expect(
      provider.getUserInfo?.({ accessToken: "not-a-jwt" }),
    ).resolves.toBeNull();
  });

  it("registers as a Better Auth social provider", async () => {
    const discoveryFetch = vi.fn<typeof fetch>((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url === EVE_SSO_DISCOVERY_URL) {
        return Promise.resolve(
          Response.json({
            issuer: "https://login.eveonline.com",
            authorization_endpoint: EVE_SSO_AUTHORIZATION_URL,
            token_endpoint: EVE_SSO_TOKEN_URL,
            jwks_uri: JWKS_URL,
          }),
        );
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", discoveryFetch);

    const auth = betterAuth({
      baseURL: "http://localhost:3000",
      secret: "fS6@yP9!wD2#nK7$xR4&cV8*zM5!hQ3@",
      plugins: [
        genericOAuth({
          config: [eveOnline({ clientId: CLIENT_ID, clientSecret: "secret" })],
        }),
      ],
    });

    const context = await auth.$context;
    expect(
      context.socialProviders.some(
        (provider) => provider.id === EVE_ONLINE_PROVIDER_ID,
      ),
    ).toBe(true);
    const discoveryInput = discoveryFetch.mock.calls[0]?.[0];
    const discoveryUrl =
      discoveryInput instanceof Request
        ? discoveryInput.url
        : discoveryInput instanceof URL
          ? discoveryInput.href
          : discoveryInput;
    expect(discoveryUrl).toBe(EVE_SSO_DISCOVERY_URL);
  });
});

describe("createEveOnlineAccessTokenVerifier", () => {
  it("verifies the access token and maps the EVE character profile", async () => {
    const { fetchMock, sign } = await createSigningFixture();
    const verify = createEveOnlineAccessTokenVerifier({
      clientId: CLIENT_ID,
      fetch: fetchMock,
      portraitSize: 512,
    });

    const profile = await verify(await sign());

    expect(profile).toMatchObject({
      id: "2112345678",
      sub: "CHARACTER:EVE:2112345678",
      characterId: "2112345678",
      name: "Ada Lovelace",
      email: "2112345678@eve.invalid",
      emailVerified: false,
      characterOwnerHash: "owner-hash",
      scopes: ["esi-skills.read_skills.v1"],
      tenant: "tranquility",
      image:
        "https://images.evetech.net/characters/2112345678/portrait?size=512",
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await verify(await sign({ name: "Grace Hopper" }));
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    {
      name: "wrong audience",
      claims: { aud: ["another-client", "EVE Online"] },
      code: "INVALID_AUDIENCE",
    },
    {
      name: "expired token",
      claims: { exp: Math.floor(Date.now() / 1000) - 120 },
      code: "TOKEN_EXPIRED",
    },
    {
      name: "invalid character subject",
      claims: { sub: "USER:EVE:2112345678" },
      code: "INVALID_SUBJECT",
    },
  ])("rejects a token with $name", async ({ claims, code }) => {
    const { fetchMock, sign } = await createSigningFixture();
    const verify = createEveOnlineAccessTokenVerifier({
      clientId: CLIENT_ID,
      fetch: fetchMock,
    });

    await expect(verify(await sign(claims))).rejects.toMatchObject({ code });
  });

  it("rejects a token whose signature was changed", async () => {
    const { fetchMock, sign } = await createSigningFixture();
    const verify = createEveOnlineAccessTokenVerifier({
      clientId: CLIENT_ID,
      fetch: fetchMock,
    });
    const token = await sign();
    const [header, payload, signature] = token.split(".") as [
      string,
      string,
      string,
    ];
    const tamperedSignature = `${signature[0] === "a" ? "b" : "a"}${signature.slice(1)}`;
    const tampered = `${header}.${payload}.${tamperedSignature}`;

    await expect(verify(tampered)).rejects.toMatchObject({
      code: "INVALID_SIGNATURE",
    });
  });
});
