export type EveOnlineTokenErrorCode =
  | "INVALID_TOKEN"
  | "INVALID_SIGNATURE"
  | "INVALID_ISSUER"
  | "INVALID_AUDIENCE"
  | "TOKEN_EXPIRED"
  | "TOKEN_NOT_ACTIVE"
  | "INVALID_SUBJECT"
  | "INVALID_PROFILE"
  | "KEY_NOT_FOUND"
  | "METADATA_REQUEST_FAILED"
  | "JWKS_REQUEST_FAILED";

export class EveOnlineTokenError extends Error {
  readonly code: EveOnlineTokenErrorCode;

  constructor(code: EveOnlineTokenErrorCode, message: string) {
    super(message);
    this.name = "EveOnlineTokenError";
    this.code = code;
  }
}
