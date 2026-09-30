// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/** An append-only native code; unknown values retain their numeric identity. */
export interface PolicyResultCode {
  code: number;
  name?: string;
}

export interface NativePolicyDetail {
  failureClass: PolicyResultCode;
  failureReason: PolicyResultCode;
  requiredAction: PolicyResultCode;
  resourceKind: PolicyResultCode;
  valueKind: PolicyResultCode;
  /** Decimal uint64 strings, not potentially lossy JavaScript numbers. */
  requestedValue: string;
  requiredValue: string;
  flags: number;
  resource?: string;
  resourceOffsetChars: number;
  resourceCharsWritten: number;
  resourceCharsRequired: number;
}

export interface NativePolicyResult {
  version: number;
  outcome: PolicyResultCode;
  /** A bounded subset, not an exhaustive list of conflicts. */
  details: NativePolicyDetail[];
  detailsCapacity: number;
  detailsCount: number;
  resourceCapacityChars: number;
  resourceCharsWritten: number;
  resourceCharsRequired: number;
}

export interface PolicyChange {
  /** Normalized setting name, not a literal patch into the caller's JSON. */
  setting: string;
  before: unknown;
  after: unknown;
}

export interface PolicyEnforcementAttempt {
  attempt: number;
  hresult: string;
  result: NativePolicyResult;
  changes?: PolicyChange[];
}

export interface PolicyEnforcementReport {
  reportVersion: number;
  requestedMode: 'pass-through' | 'mutate';
  modeApplied: boolean;
  availability: 'available' | 'unavailable' | 'notApplicable' | 'notEvaluated';
  termination: 'created' | 'ignored' | 'rejected' | 'unrepairable' | 'noProgress'
    | 'attemptLimit' | 'evaluationFailed' | 'nativeFailure' | 'invalidResult';
  environmentCreated: boolean;
  originalPolicyHash: string;
  effectivePolicyHash: string;
  attempts: PolicyEnforcementAttempt[];
  message?: string;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function uint32(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function code(value: unknown): value is PolicyResultCode {
  return object(value) && uint32(value.code)
    && (value.name === undefined || typeof value.name === 'string');
}

function uint64(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9]{1,20}$/.test(value)
    && BigInt(value) <= 18446744073709551615n;
}

function nativeDetail(value: unknown): value is NativePolicyDetail {
  return object(value) && code(value.failureClass) && code(value.failureReason)
    && code(value.requiredAction) && code(value.resourceKind) && code(value.valueKind)
    && uint64(value.requestedValue) && uint64(value.requiredValue) && uint32(value.flags)
    && (value.resource === undefined || typeof value.resource === 'string')
    && uint32(value.resourceOffsetChars) && uint32(value.resourceCharsWritten)
    && uint32(value.resourceCharsRequired);
}

function nativeResult(value: unknown): value is NativePolicyResult {
  return object(value) && uint32(value.version) && code(value.outcome)
    && Array.isArray(value.details) && value.details.length <= 64
    && value.details.every(nativeDetail)
    && uint32(value.detailsCapacity) && uint32(value.detailsCount)
    && uint32(value.resourceCapacityChars) && uint32(value.resourceCharsWritten)
    && uint32(value.resourceCharsRequired);
}

function attempt(value: unknown): value is PolicyEnforcementAttempt {
  return object(value) && uint32(value.attempt) && value.attempt >= 1 && value.attempt <= 64
    && typeof value.hresult === 'string' && nativeResult(value.result)
    && (value.changes === undefined || (Array.isArray(value.changes)
      && value.changes.every(change => object(change) && typeof change.setting === 'string'
        && 'before' in change && 'after' in change)));
}

function report(value: unknown): value is PolicyEnforcementReport {
  return object(value) && value.reportVersion === 1
    && (value.requestedMode === 'pass-through' || value.requestedMode === 'mutate')
    && typeof value.modeApplied === 'boolean' && typeof value.environmentCreated === 'boolean'
    && typeof value.originalPolicyHash === 'string' && typeof value.effectivePolicyHash === 'string'
    && typeof value.availability === 'string'
    && ['available', 'unavailable', 'notApplicable', 'notEvaluated'].includes(value.availability)
    && typeof value.termination === 'string'
    && ['created', 'ignored', 'rejected', 'unrepairable', 'noProgress', 'attemptLimit',
      'evaluationFailed', 'nativeFailure', 'invalidResult'].includes(value.termination)
    && (value.message === undefined || typeof value.message === 'string')
    && Array.isArray(value.attempts) && value.attempts.length <= 64 && value.attempts.every(attempt);
}

/**
 * Read a typed report from `MxcError.details` or a result's `outputMetadata`.
 * Absence is distinct from a native `noApplicablePolicy` outcome.
 */
export function getPolicyEnforcementReport(details: unknown): PolicyEnforcementReport | undefined {
  if (!object(details) || details.policyEnforcement === undefined) return undefined;
  if (!report(details.policyEnforcement)) {
    throw new TypeError('MXC returned malformed or unsupported policy-enforcement details');
  }
  return details.policyEnforcement;
}
