// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { MxcError } from '../errors.js';
import { hasDuplicateJsonKeys } from './json-duplicate-keys.js';

/** Native status strings for MxcError.nativeCode. */
export const PolicyFailureNativeCodes = Object.freeze({
  /** HRESULT_FROM_WIN32(ERROR_ACCESS_DISABLED_BY_POLICY), formatted as an SDK native code. */
  PolicyBlocked: '0x800704EC',
} as const);

/** Known native outcomes; outcome fields also retain unknown numbers. */
export const PolicyFailureOutcomes = Object.freeze({
  Unknown: 0,
  Blocked: 1,
  EvaluationFailed: 2,
} as const);

/** Known native failure classes. */
export const PolicyFailureClasses = Object.freeze({
  None: 0,
  Network: 1,
  Filesystem: 2,
  EnforcementMode: 3,
} as const);

/** Known native failure reasons. */
export const PolicyFailureReasons = Object.freeze({
  None: 0,
  CapabilityNotAllowed: 1,
  AccessExceedsCeiling: 2,
  DenyRequired: 3,
  RequestPathLimit: 4,
} as const);

/** Known suggested changes, not authorization to apply them. */
export const PolicyFailureActions = Object.freeze({
  None: 0,
  RemoveCapability: 1,
  RestrictFilesystemAccess: 2,
  ReducePathCount: 3,
} as const);

/** Known native resource categories. */
export const PolicyFailureResourceKinds = Object.freeze({
  None: 0,
  Path: 1,
  Capability: 2,
} as const);

/** Known native value categories. */
export const PolicyFailureValueKinds = Object.freeze({
  None: 0,
  Access: 1,
  PathCount: 2,
} as const);

/** Decimal-string access values for requestedValue/requiredValue when valueKind is Access. */
export const PolicyFailureAccessValues = Object.freeze({
  None: '0',
  ReadOnly: '1',
  ReadWrite: '2',
} as const);

/** Known native flag bits; flags fields also retain unknown bits. */
export const PolicyFailureFlags = Object.freeze({
  None: 0,
  HasActionableDetails: 1,
  ResourceComplete: 2,
  ResourceUnavailable: 4,
} as const);

/** Supported policy-failure format and native result versions. */
export const PolicyFailureVersions = Object.freeze({
  /** The supported `formatVersion`. */
  Format: 1,
  /** The native result version written for `version`. */
  Result: 1,
  /** The native reader version written for `minimumReaderVersion`. */
  MinimumReader: 1,
} as const);

/** Creation-policy observations, not a policy approval. */
export interface PolicyFailures {
  formatVersion: number;
  results: PolicyFailureResult[];
}

/** One native refusal batch. Unknown numeric codes remain inspectable. */
export interface PolicyFailureResult {
  version: number;
  minimumReaderVersion: number;
  outcome: number;
  details: PolicyFailureDetail[];
}

/** A native observation; values describe the request Windows evaluated. */
export interface PolicyFailureDetail {
  failureClass: number;
  failureReason: number;
  requiredAction: number;
  resourceKind: number;
  valueKind: number;
  flags: number;
  requestedValue: string;
  requiredValue: string;
  /**
   * Native resource text without a terminator. An empty string differs from
   * absence. `PolicyFailureFlags.ResourceComplete` reports completeness.
   * Invalid native UTF-16 is omitted and marked unavailable.
   */
  resource?: string;
}

const MAX_INVOCATION_BYTES = 4 * 1024 * 1024;
const MAX_INVOCATION_RESULTS = 64;
const MAX_INVOCATION_DETAILS = 1024;
const MAX_INVOCATION_RESOURCE_UNITS = 262_144;
const MAX_DETAILS_PER_RESULT = 64;
const MAX_RESOURCE_UNITS_PER_RESULT = 32_768;
// Storage includes one final native batch beyond the limits for preparation.
const MAX_STORAGE_BYTES = MAX_INVOCATION_BYTES + 512 * 1024;
const MAX_STORAGE_RESULTS = MAX_INVOCATION_RESULTS + 1;
const MAX_STORAGE_DETAILS = MAX_INVOCATION_DETAILS + MAX_DETAILS_PER_RESULT;
const MAX_STORAGE_RESOURCE_UNITS = MAX_INVOCATION_RESOURCE_UNITS + MAX_RESOURCE_UNITS_PER_RESULT;

function malformed(message: string): never {
  throw new MxcError('malformed_request', `invalid policyFailures: ${message}`);
}

function record(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || required.some((key) => !Object.hasOwn(value, key))
      || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) {
    malformed('expected an object with the documented fields');
  }
  return value as Record<string, unknown>;
}

function uint32(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    malformed('native codes and versions must be unsigned 32-bit integers');
  }
  return value;
}

function uint64(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) {
    malformed('requestedValue and requiredValue must be unsigned decimal strings');
  }
  const significant = value.replace(/^0+/, '');
  if (significant.length > 20
      || (significant.length === 20 && significant > '18446744073709551615')) {
    malformed('requestedValue and requiredValue must fit unsigned 64-bit values');
  }
  return value;
}

// Each present resource also reserves a terminator unit within the per-result limit.
function checkResourceLength(length: number): void {
  if (length >= MAX_RESOURCE_UNITS_PER_RESULT) malformed('per-result resource limit exceeded');
}

function resourceText(value: unknown): string {
  if (typeof value !== 'string') malformed('resource must be a string');
  checkResourceLength(value.length);
  if (/\p{Surrogate}/u.test(value)) malformed('resource must be valid UTF-16');
  return value;
}

function readPolicyFailures(value: unknown): PolicyFailures {
  const failures = record(value, ['formatVersion', 'results']);
  if (failures.formatVersion !== PolicyFailureVersions.Format) malformed('unsupported formatVersion');
  if (!Array.isArray(failures.results) || failures.results.length > MAX_STORAGE_RESULTS) {
    malformed(`results must be an array of at most ${MAX_STORAGE_RESULTS} native batches`);
  }
  let detailCount = 0;
  let resourceCount = 0;
  const results = Array.from(failures.results, (entry: unknown): PolicyFailureResult => {
    const result = record(entry, ['version', 'minimumReaderVersion', 'outcome', 'details']);
    if (!Array.isArray(result.details) || result.details.length > MAX_DETAILS_PER_RESULT) {
      malformed(`each result must contain an array of at most ${MAX_DETAILS_PER_RESULT} details`);
    }
    detailCount += result.details.length;
    if (detailCount > MAX_STORAGE_DETAILS) malformed('total detail storage limit exceeded');
    let resultResourceCount = 0;
    const details = Array.from(result.details, (entry: unknown): PolicyFailureDetail => {
      const detail = record(entry, [
        'failureClass', 'failureReason', 'requiredAction', 'resourceKind',
        'valueKind', 'flags', 'requestedValue', 'requiredValue',
      ], ['resource']);
      const resource = detail.resource == null ? undefined : resourceText(detail.resource);
      resultResourceCount += resource === undefined ? 0 : resource.length + 1;
      if (resultResourceCount > MAX_RESOURCE_UNITS_PER_RESULT) malformed('per-result resource limit exceeded');
      return {
        failureClass: uint32(detail.failureClass),
        failureReason: uint32(detail.failureReason),
        requiredAction: uint32(detail.requiredAction),
        resourceKind: uint32(detail.resourceKind),
        valueKind: uint32(detail.valueKind),
        flags: uint32(detail.flags),
        requestedValue: uint64(detail.requestedValue),
        requiredValue: uint64(detail.requiredValue),
        ...(resource === undefined ? {} : { resource }),
      };
    });
    resourceCount += resultResourceCount;
    if (resourceCount > MAX_STORAGE_RESOURCE_UNITS) malformed('total resource storage limit exceeded');
    return {
      version: uint32(result.version),
      minimumReaderVersion: uint32(result.minimumReaderVersion),
      outcome: uint32(result.outcome),
      details,
    };
  });
  return { formatVersion: PolicyFailureVersions.Format, results };
}

function storageJson(value: PolicyFailures): string {
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json, 'utf8') > MAX_STORAGE_BYTES) malformed('JSON storage limit exceeded');
  return json;
}

/** Parse caller-owned storage, preserving unknown codes and resource text. */
export function parsePolicyFailures(json: string): PolicyFailures {
  if (typeof json !== 'string' || Buffer.byteLength(json, 'utf8') > MAX_STORAGE_BYTES) {
    malformed('expected a JSON string of at most 4.5 MiB');
  }
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    malformed('malformed JSON');
  }
  if (hasDuplicateJsonKeys(json)) malformed('duplicate JSON object keys');
  return readPolicyFailures(value);
}

/** Serialize caller-owned storage. Native preparation enforces stricter input limits. */
export function serializePolicyFailures(value: PolicyFailures): string {
  return storageJson(readPolicyFailures(value));
}

/** Merge complete batches in first-seen order into an owned, bounded report. */
export function mergePolicyFailures(older: PolicyFailures, newer: PolicyFailures): PolicyFailures {
  const inputs = [readPolicyFailures(older), readPolicyFailures(newer)];
  const results: PolicyFailureResult[] = [];
  const seen = new Set<string>();
  for (const input of inputs) {
    storageJson(input);
    for (const result of input.results) {
      const key = JSON.stringify(result, (name, value: unknown) => (
        (name === 'requestedValue' || name === 'requiredValue') && typeof value === 'string'
          ? value.replace(/^0+(?=\d)/, '') : value
      ));
      if (!seen.has(key)) {
        seen.add(key);
        results.push(result);
      }
    }
  }
  const merged = readPolicyFailures({ formatVersion: PolicyFailureVersions.Format, results });
  storageJson(merged);
  return merged;
}

/**
 * Extract an owned copy from an SDK error. Malformed native details raise
 * `backend_error`; `parsePolicyFailures` raises `malformed_request` for
 * invalid stored observations.
 */
export function policyFailuresFromError(error: unknown): PolicyFailures | undefined {
  if (!(error instanceof MxcError) || error.details?.policyFailures === undefined) return undefined;
  try {
    const failures = readPolicyFailures(error.details.policyFailures);
    storageJson(failures);
    return failures;
  } catch (cause) {
    if (cause instanceof MxcError && cause.code === 'malformed_request') {
      throw new MxcError('backend_error', 'native policy failures are malformed');
    }
    throw cause;
  }
}
