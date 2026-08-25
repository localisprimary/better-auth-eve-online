import {
  EVE_IMAGE_SERVER_URL,
  EVE_SSO_AUDIENCE,
  EVE_SSO_DISCOVERY_URL,
} from "./constants";
import { EveOnlineTokenError } from "./errors";

const DEFAULT_JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 30;
const MAX_JWT_LENGTH = 64 * 1024;
const CHARACTER_SUBJECT_PATTERN = /^CHARACTER:EVE:([1-9]\d*)$/;
const ACCEPTED_ISSUERS = new Set([
  "login.eveonline.com",
  "https://login.eveonline.com",
  "https://login.eveonline.com/",
]);

type SupportedAlgorithm = "RS256" | "ES256";

interface JwtHeader {
  alg: SupportedAlgorithm;
  kid: string;
}

interface JsonWebKeySet {
  keys: SigningJsonWebKey[];
}

interface CachedKeys {
  expiresAt: number;
  keys: SigningJsonWebKey[];
}

type SigningJsonWebKey = JsonWebKey & { kid?: string };

export interface EveOnlineAccessTokenClaims {
  aud: string | string[];
  azp?: string;
  exp: number;
  iat?: number;
  iss: string;
  jti?: string;
  name: string;
  owner?: string;
  region?: string;
  scp?: string | string[];
  sub: `CHARACTER:EVE:${string}`;
  tenant?: string;
  tier?: string;
  [claim: string]: unknown;
}

export interface EveOnlineProfile {
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
  [field: string]: unknown;
}

export interface EveOnlineTokenVerifierOptions {
  /** EVE application client ID. It must appear in the token audience. */
  clientId: string;
  /** Override fetch for non-standard runtimes or tests. */
  fetch?: typeof globalThis.fetch;
  /** How long the discovered signing keys remain cached. Defaults to five minutes. */
  jwksCacheTtlMs?: number;
  /** Allowed clock skew when checking exp/nbf. Defaults to 30 seconds. */
  clockToleranceSeconds?: number;
  /** Portrait resolution returned in the Better Auth profile. */
  portraitSize?: 32 | 64 | 128 | 256 | 512 | 1024;
}

export type EveOnlineAccessTokenVerifier = (
  accessToken: string,
) => Promise<EveOnlineProfile>;

function tokenError(
  code: ConstructorParameters<typeof EveOnlineTokenError>[0],
  message: string,
): EveOnlineTokenError {
  return new EveOnlineTokenError(code, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw tokenError("INVALID_TOKEN", "JWT contains invalid base64url data");
  }

  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");

  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw tokenError("INVALID_TOKEN", "JWT contains malformed base64url data");
  }
}

function decodeJsonSegment(value: string): Record<string, unknown> {
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
      decodeBase64Url(value),
    );
    const parsed: unknown = JSON.parse(decoded);
    if (!isRecord(parsed)) {
      throw new TypeError("JWT segment is not an object");
    }
    return parsed;
  } catch (error) {
    if (error instanceof EveOnlineTokenError) {
      throw error;
    }
    throw tokenError("INVALID_TOKEN", "JWT contains invalid JSON");
  }
}

function parseHeader(segment: string): JwtHeader {
  const header = decodeJsonSegment(segment);
  if (header.alg !== "RS256" && header.alg !== "ES256") {
    throw tokenError("INVALID_TOKEN", "JWT uses an unsupported algorithm");
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    throw tokenError("INVALID_TOKEN", "JWT is missing a signing key ID");
  }
  return { alg: header.alg, kid: header.kid };
}

function parseClaims(segment: string): EveOnlineAccessTokenClaims {
  const claims = decodeJsonSegment(segment);
  if (
    typeof claims.iss !== "string" ||
    typeof claims.sub !== "string" ||
    typeof claims.name !== "string" ||
    typeof claims.exp !== "number" ||
    !Number.isFinite(claims.exp) ||
    !(typeof claims.aud === "string" || Array.isArray(claims.aud))
  ) {
    throw tokenError("INVALID_TOKEN", "JWT is missing required EVE claims");
  }
  if (
    Array.isArray(claims.aud) &&
    !claims.aud.every((audience) => typeof audience === "string")
  ) {
    throw tokenError("INVALID_TOKEN", "JWT audience claim is invalid");
  }
  return claims as EveOnlineAccessTokenClaims;
}

function validateClaims(
  claims: EveOnlineAccessTokenClaims,
  clientId: string,
  clockToleranceSeconds: number,
): string {
  if (!ACCEPTED_ISSUERS.has(claims.iss)) {
    throw tokenError("INVALID_ISSUER", "JWT issuer is not the EVE SSO");
  }

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(EVE_SSO_AUDIENCE) || !audiences.includes(clientId)) {
    throw tokenError(
      "INVALID_AUDIENCE",
      "JWT audience does not contain EVE Online and the configured client ID",
    );
  }
  if (claims.azp !== undefined && claims.azp !== clientId) {
    throw tokenError(
      "INVALID_AUDIENCE",
      "JWT authorized party does not match the configured client ID",
    );
  }

  const now = Date.now() / 1000;
  if (claims.exp <= now - clockToleranceSeconds) {
    throw tokenError("TOKEN_EXPIRED", "EVE access token has expired");
  }
  if (
    claims.nbf !== undefined &&
    (typeof claims.nbf !== "number" ||
      !Number.isFinite(claims.nbf) ||
      claims.nbf > now + clockToleranceSeconds)
  ) {
    throw tokenError("TOKEN_NOT_ACTIVE", "EVE access token is not active yet");
  }

  const subjectMatch = CHARACTER_SUBJECT_PATTERN.exec(claims.sub);
  if (!subjectMatch?.[1]) {
    throw tokenError(
      "INVALID_SUBJECT",
      "JWT subject is not an EVE character identifier",
    );
  }
  if (claims.name.trim().length === 0) {
    throw tokenError("INVALID_PROFILE", "JWT character name is empty");
  }
  return subjectMatch[1];
}

function isCompatibleKey(
  key: SigningJsonWebKey,
  header: JwtHeader,
): key is SigningJsonWebKey & { kid: string } {
  if (key.kid !== header.kid || (key.use !== undefined && key.use !== "sig")) {
    return false;
  }
  if (key.key_ops !== undefined && !key.key_ops.includes("verify")) {
    return false;
  }
  if (key.alg !== undefined && key.alg !== header.alg) {
    return false;
  }
  return (
    (header.alg === "RS256" && key.kty === "RSA") ||
    (header.alg === "ES256" && key.kty === "EC" && key.crv === "P-256")
  );
}

function cryptoAlgorithm(
  algorithm: SupportedAlgorithm,
): RsaHashedImportParams | EcKeyImportParams {
  return algorithm === "RS256"
    ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
    : { name: "ECDSA", namedCurve: "P-256" };
}

async function verifySignature(
  header: JwtHeader,
  key: SigningJsonWebKey,
  signingInput: string,
  signature: Uint8Array<ArrayBuffer>,
): Promise<void> {
  try {
    const algorithm = cryptoAlgorithm(header.alg);
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      algorithm,
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      header.alg === "RS256"
        ? { name: "RSASSA-PKCS1-v1_5" }
        : { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      signature,
      new TextEncoder().encode(signingInput),
    );
    if (!valid) {
      throw tokenError(
        "INVALID_SIGNATURE",
        "EVE access token signature is invalid",
      );
    }
  } catch (error) {
    if (error instanceof EveOnlineTokenError) {
      throw error;
    }
    throw tokenError(
      "INVALID_SIGNATURE",
      "EVE access token signature is invalid",
    );
  }
}

function toProfile(
  claims: EveOnlineAccessTokenClaims,
  characterId: string,
  portraitSize: number,
): EveOnlineProfile {
  const scopes = Array.isArray(claims.scp)
    ? claims.scp.filter((scope): scope is string => typeof scope === "string")
    : typeof claims.scp === "string"
      ? claims.scp.split(" ").filter(Boolean)
      : [];

  const profile: EveOnlineProfile = {
    id: characterId,
    sub: claims.sub,
    characterId,
    name: claims.name,
    email: `${characterId}@eve.invalid`,
    emailVerified: false,
    image: `${EVE_IMAGE_SERVER_URL}/characters/${characterId}/portrait?size=${portraitSize}`,
    scopes,
    claims,
  };

  if (typeof claims.owner === "string") {
    profile.characterOwnerHash = claims.owner;
  }
  if (typeof claims.tenant === "string") {
    profile.tenant = claims.tenant;
  }
  if (typeof claims.region === "string") {
    profile.region = claims.region;
  }
  if (typeof claims.tier === "string") {
    profile.tier = claims.tier;
  }
  return profile;
}

function createKeyLoader(
  fetchImplementation: typeof globalThis.fetch,
  cacheTtlMs: number,
): (forceRefresh?: boolean) => Promise<SigningJsonWebKey[]> {
  let cached: CachedKeys | undefined;
  let pending: Promise<SigningJsonWebKey[]> | undefined;

  const requestKeys = async (): Promise<SigningJsonWebKey[]> => {
    let metadataResponse: Response;
    try {
      metadataResponse = await fetchImplementation(EVE_SSO_DISCOVERY_URL, {
        headers: { Accept: "application/json" },
      });
    } catch {
      throw tokenError(
        "METADATA_REQUEST_FAILED",
        "Unable to request EVE SSO metadata",
      );
    }
    if (!metadataResponse.ok) {
      throw tokenError(
        "METADATA_REQUEST_FAILED",
        `EVE SSO metadata request failed with HTTP ${metadataResponse.status}`,
      );
    }

    let metadata: unknown;
    try {
      metadata = await metadataResponse.json();
    } catch {
      throw tokenError(
        "METADATA_REQUEST_FAILED",
        "EVE SSO metadata response is not valid JSON",
      );
    }
    if (!isRecord(metadata) || typeof metadata.jwks_uri !== "string") {
      throw tokenError(
        "METADATA_REQUEST_FAILED",
        "EVE SSO metadata does not include a JWKS URL",
      );
    }

    let jwksUrl: URL;
    try {
      jwksUrl = new URL(metadata.jwks_uri);
      if (jwksUrl.protocol !== "https:") {
        throw new TypeError("JWKS URL must use HTTPS");
      }
    } catch {
      throw tokenError(
        "METADATA_REQUEST_FAILED",
        "EVE SSO metadata contains an invalid JWKS URL",
      );
    }

    let jwksResponse: Response;
    try {
      jwksResponse = await fetchImplementation(jwksUrl, {
        headers: { Accept: "application/json" },
      });
    } catch {
      throw tokenError(
        "JWKS_REQUEST_FAILED",
        "Unable to request EVE signing keys",
      );
    }
    if (!jwksResponse.ok) {
      throw tokenError(
        "JWKS_REQUEST_FAILED",
        `EVE signing-key request failed with HTTP ${jwksResponse.status}`,
      );
    }

    let jwks: unknown;
    try {
      jwks = await jwksResponse.json();
    } catch {
      throw tokenError(
        "JWKS_REQUEST_FAILED",
        "EVE signing-key response is not valid JSON",
      );
    }
    if (
      !isRecord(jwks) ||
      !Array.isArray(jwks.keys) ||
      !jwks.keys.every(isRecord)
    ) {
      throw tokenError("JWKS_REQUEST_FAILED", "EVE signing-key set is invalid");
    }
    return (jwks as unknown as JsonWebKeySet).keys;
  };

  return async (forceRefresh = false): Promise<SigningJsonWebKey[]> => {
    const now = Date.now();
    if (!forceRefresh && cached && cached.expiresAt > now) {
      return cached.keys;
    }
    if (!forceRefresh && pending) {
      return pending;
    }

    const request = requestKeys().then((keys) => {
      cached = { keys, expiresAt: Date.now() + cacheTtlMs };
      return keys;
    });
    pending = request;
    try {
      return await request;
    } finally {
      if (pending === request) {
        pending = undefined;
      }
    }
  };
}

export function createEveOnlineAccessTokenVerifier(
  options: EveOnlineTokenVerifierOptions,
): EveOnlineAccessTokenVerifier {
  if (options.clientId.trim().length === 0) {
    throw new TypeError("clientId must not be empty");
  }
  const fetchImplementation = options.fetch ?? globalThis.fetch;
  if (typeof fetchImplementation !== "function") {
    throw new TypeError("A Fetch API implementation is required");
  }
  const cacheTtlMs = options.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS;
  const clockToleranceSeconds =
    options.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  if (!Number.isFinite(cacheTtlMs) || cacheTtlMs < 0) {
    throw new RangeError("jwksCacheTtlMs must be a non-negative number");
  }
  if (!Number.isFinite(clockToleranceSeconds) || clockToleranceSeconds < 0) {
    throw new RangeError("clockToleranceSeconds must be a non-negative number");
  }

  const portraitSize = options.portraitSize ?? 256;
  const loadKeys = createKeyLoader(fetchImplementation, cacheTtlMs);

  return async (accessToken: string): Promise<EveOnlineProfile> => {
    if (accessToken.length === 0 || accessToken.length > MAX_JWT_LENGTH) {
      throw tokenError(
        "INVALID_TOKEN",
        "EVE access token has an invalid length",
      );
    }
    const segments = accessToken.split(".");
    if (
      segments.length !== 3 ||
      segments.some((segment) => segment.length === 0)
    ) {
      throw tokenError(
        "INVALID_TOKEN",
        "EVE access token is not a compact JWT",
      );
    }
    const [headerSegment, payloadSegment, signatureSegment] = segments as [
      string,
      string,
      string,
    ];
    const header = parseHeader(headerSegment);
    const claims = parseClaims(payloadSegment);

    let keys = await loadKeys();
    let key = keys.find((candidate) => isCompatibleKey(candidate, header));
    if (!key) {
      keys = await loadKeys(true);
      key = keys.find((candidate) => isCompatibleKey(candidate, header));
    }
    if (!key) {
      throw tokenError("KEY_NOT_FOUND", "No EVE signing key matches the JWT");
    }

    await verifySignature(
      header,
      key,
      `${headerSegment}.${payloadSegment}`,
      decodeBase64Url(signatureSegment),
    );
    const characterId = validateClaims(
      claims,
      options.clientId,
      clockToleranceSeconds,
    );
    return toProfile(claims, characterId, portraitSize);
  };
}

export async function verifyEveOnlineAccessToken(
  accessToken: string,
  options: EveOnlineTokenVerifierOptions,
): Promise<EveOnlineProfile> {
  return createEveOnlineAccessTokenVerifier(options)(accessToken);
}
