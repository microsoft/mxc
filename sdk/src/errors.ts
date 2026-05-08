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
 * Base class for typed errors thrown by the MXC SDK in response to a
 * wire-format error envelope. Use `instanceof <subclass>` or compare
 * `.code` to discriminate.
 */
export class MxcError extends Error {
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.details = details;
    // Restore the prototype chain so `instanceof <subclass>` keeps working
    // after the TypeScript ES2020 → ES5-compatible class downlevelling.
    Object.setPrototypeOf(this, new.target.prototype);
    this.name = new.target.name;
  }
}

export class MxcMalformedRequestError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('malformed_request', message, details);
  }
}

export class MxcUnsupportedContainmentError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('unsupported_containment', message, details);
  }
}

export class MxcUnsupportedPhaseError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('unsupported_phase', message, details);
  }
}

export class MxcBackendUnavailableError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('backend_unavailable', message, details);
  }
}

export class MxcMalformedIdError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('malformed_id', message, details);
  }
}

export class MxcStaleIdError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('stale_id', message, details);
  }
}

export class MxcNotProvisionedError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('not_provisioned', message, details);
  }
}

export class MxcNotStartedError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('not_started', message, details);
  }
}

export class MxcAlreadyStartedError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('already_started', message, details);
  }
}

export class MxcAlreadyStoppedError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('already_stopped', message, details);
  }
}

export class MxcPolicyValidationError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('policy_validation', message, details);
  }
}

// Code `backend_error` already ends in `_error`, so the naming convention
// drops the redundant suffix that would otherwise produce `MxcBackendErrorError`.
export class MxcBackendError extends MxcError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('backend_error', message, details);
  }
}

/**
 * Constructs the typed `MxcError` subclass corresponding to a wire-format
 * error code. Falls back to the base `MxcError` for unknown codes; in
 * practice the wire format's closed enum should not produce these.
 */
export function mxcErrorFromCode(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): MxcError {
  switch (code) {
    case 'malformed_request': return new MxcMalformedRequestError(message, details);
    case 'unsupported_containment': return new MxcUnsupportedContainmentError(message, details);
    case 'unsupported_phase': return new MxcUnsupportedPhaseError(message, details);
    case 'backend_unavailable': return new MxcBackendUnavailableError(message, details);
    case 'malformed_id': return new MxcMalformedIdError(message, details);
    case 'stale_id': return new MxcStaleIdError(message, details);
    case 'not_provisioned': return new MxcNotProvisionedError(message, details);
    case 'not_started': return new MxcNotStartedError(message, details);
    case 'already_started': return new MxcAlreadyStartedError(message, details);
    case 'already_stopped': return new MxcAlreadyStoppedError(message, details);
    case 'policy_validation': return new MxcPolicyValidationError(message, details);
    case 'backend_error': return new MxcBackendError(message, details);
    default: return new MxcError(code as ErrorCode, message, details);
  }
}
