// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Closed set of MXC wire-format error codes. Mirrors `MxcErrorCode` on the
 * Rust side one-for-one and serialises as the same snake_case strings on
 * the wire. Backend-specific failures that don't fit one of these codes
 * surface as `backend_error`, with structured information carried in the
 * named fields below (or in `details`).
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
 * Every field an `MxcError` can carry, in the same flat shape as the wire
 * error envelope — `operation`, `nativeCode` and `remediation` sit alongside
 * `code` and `message`, not nested inside `details`.
 *
 * **Invariant:** `nativeCode` implies `operation`, and `remediation` implies
 * `operation`. `operation` marks that an underlying API call was in flight;
 * the other two refine it, and neither appears on its own. A failure MXC
 * raises before or outside any API call carries only `code` and `message`.
 */
export interface MxcErrorFields {
  /** Machine-readable category. Branch on this first. */
  code: ErrorCode;
  /** Human-readable description of the failure. */
  message: string;
  /**
   * The underlying API call that failed, namespaced by its interface — e.g.
   * `IsoSessionOps.RunProcessWithOptionsAsync`. Low-cardinality and free of
   * call parameters, so it is safe to group on in telemetry.
   */
  operation?: string;
  /**
   * The underlying platform status as a string — an HRESULT such as
   * `0x80070490` on Windows, an errno or equivalent elsewhere.
   */
  nativeCode?: string;
  /** The API's actionable "how to fix it" hint, when it supplied one. */
  remediation?: string;
  /**
   * Open extension point for backend-specific structured data that has no
   * dedicated field. Named fields are reserved for backend-neutral concepts.
   */
  details?: Record<string, unknown>;
}

/**
 * The `error` arm of a wire response envelope, as received from the
 * executor. Identical to {@link MxcErrorFields} except that `code` is an
 * open `string`: an unrecognised code is passed through verbatim rather than
 * being coerced or dropped.
 */
export interface WireError extends Omit<MxcErrorFields, 'code'> {
  code: string;
}

/**
 * Typed error thrown by the MXC SDK in response to a wire-format error
 * envelope. Discriminate by comparing `.code` to a wire-format error code
 * string; the TypeScript string-literal union gives the same IDE
 * completion as a class hierarchy without the multiplicative class count.
 */
export class MxcError extends Error {
  readonly code: ErrorCode;
  readonly operation?: string;
  readonly nativeCode?: string;
  readonly remediation?: string;
  readonly details?: Record<string, unknown>;

  /** Canonical form: pass the full field set as one object. */
  constructor(fields: MxcErrorFields);
  /**
   * Positional form, retained for compatibility. Declared last so that
   * `ConstructorParameters<typeof MxcError>` keeps resolving to this shape.
   */
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>);
  constructor(
    codeOrFields: ErrorCode | MxcErrorFields,
    message?: string,
    details?: Record<string, unknown>,
  ) {
    const fields: MxcErrorFields =
      typeof codeOrFields === 'string'
        ? { code: codeOrFields, message: message as string, details }
        : codeOrFields;
    super(fields.message);
    this.code = fields.code;
    this.operation = fields.operation;
    this.nativeCode = fields.nativeCode;
    this.remediation = fields.remediation;
    this.details = fields.details;
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
 *
 * For a complete wire envelope prefer {@link mxcErrorFromEnvelope}, which
 * carries the structured fields too.
 */
export function mxcErrorFromCode(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): MxcError {
  return new MxcError(code as ErrorCode, message, details);
}

/**
 * Constructs an `MxcError` from the `error` arm of a wire response envelope.
 *
 * This is the single place the wire's open `code` string is widened to the
 * closed `ErrorCode` union, so unknown-code passthrough behaves identically
 * everywhere the SDK parses an envelope.
 */
export function mxcErrorFromEnvelope(error: WireError): MxcError {
  return new MxcError({
    code: error.code as ErrorCode,
    message: error.message,
    operation: error.operation,
    nativeCode: error.nativeCode,
    remediation: error.remediation,
    details: error.details,
  });
}
