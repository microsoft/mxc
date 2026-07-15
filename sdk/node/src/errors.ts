// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Closed set of MXC wire-format error codes. Mirrors `MxcErrorCode` on the
 * Rust side one-for-one and serialises as the same snake_case strings on
 * the wire. Backend-specific failures that don't fit one of these codes
 * surface as `backend_error`, with structured information carried in
 * `details`.
 */
export type ErrorCode =
  | 'malformed_request'
  | 'unsupported_containment'
  | 'unsupported_phase'
  | 'backend_unavailable'
  | 'malformed_id'
  | 'stale_id'
  | 'not_provisioned'
  | 'not_started'
  | 'already_started'
  | 'already_stopped'
  | 'policy_validation'
  | 'backend_error';

/**
 * Typed error thrown by the MXC SDK in response to a wire-format error
 * envelope. Discriminate by comparing `.code` to a wire-format error code
 * string; the TypeScript string-literal union gives the same IDE
 * completion as a class hierarchy without the multiplicative class count.
 */
export class MxcError extends Error {
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.details = details;
    // Restore the prototype chain so `instanceof MxcError` keeps working
    // after the TypeScript ES2020 → ES5-compatible class downlevelling.
    Object.setPrototypeOf(this, new.target.prototype);
    this.name = 'MxcError';
  }
}

/**
 * Constructs an `MxcError` from a wire-format error code. Accepts a plain
 * `string` so callers parsing a wire envelope don't need to narrow first;
 * unknown codes still produce an `MxcError` with `.code` set to whatever
 * was on the wire.
 */
export function mxcErrorFromCode(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): MxcError {
  return new MxcError(code as ErrorCode, message, details);
}
