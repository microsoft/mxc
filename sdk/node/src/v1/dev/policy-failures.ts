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
  /** UTF-16 code units without a terminator. Absence differs from an empty array. */
  resource?: number[];
}

// Storage includes one final native batch beyond the limits for preparation.
const MAX_STORAGE_BYTES = 4.5 * 1024 * 1024;
const MAX_STORAGE_RESULTS = 65;
const MAX_STORAGE_DETAILS = 1088;
const MAX_STORAGE_RESOURCE_UNITS = 294_912;

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

function resourceUnits(value: unknown): number[] {
  if (!Array.isArray(value)) malformed('resource must be an array of UTF-16 code units');
  if (value.length >= 32_768) malformed('per-result resource limit exceeded');
  return Array.from(value, (unit: unknown) => {
    if (typeof unit !== 'number' || !Number.isInteger(unit) || unit < 0 || unit > 0xffff) {
      malformed('resource must contain unsigned 16-bit integers');
    }
    return unit;
  });
}

function readPolicyFailures(value: unknown): PolicyFailures {
  const failures = record(value, ['formatVersion', 'results']);
  if (failures.formatVersion !== 1) malformed('unsupported formatVersion');
  if (!Array.isArray(failures.results) || failures.results.length > MAX_STORAGE_RESULTS) {
    malformed('results must be an array of at most 65 native batches');
  }
  let detailCount = 0;
  let resourceCount = 0;
  const results = Array.from(failures.results, (entry: unknown): PolicyFailureResult => {
    const result = record(entry, ['version', 'minimumReaderVersion', 'outcome', 'details']);
    if (!Array.isArray(result.details) || result.details.length > 64) {
      malformed('each result must contain an array of at most 64 details');
    }
    detailCount += result.details.length;
    if (detailCount > MAX_STORAGE_DETAILS) malformed('total detail storage limit exceeded');
    let resultResourceCount = 0;
    const details = Array.from(result.details, (entry: unknown): PolicyFailureDetail => {
      const detail = record(entry, [
        'failureClass', 'failureReason', 'requiredAction', 'resourceKind',
        'valueKind', 'flags', 'requestedValue', 'requiredValue',
      ], ['resource']);
      const resource = detail.resource === undefined || detail.resource === null
        ? undefined : resourceUnits(detail.resource);
      if (resource !== undefined) resultResourceCount += resource.length + 1;
      if (resultResourceCount > 32_768) malformed('per-result resource limit exceeded');
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
  return { formatVersion: 1, results };
}

function storageJson(value: PolicyFailures): string {
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json, 'utf8') > MAX_STORAGE_BYTES) malformed('JSON storage limit exceeded');
  return json;
}

/** Parse caller-owned storage, preserving unknown codes and raw UTF-16 units. */
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
  const merged = readPolicyFailures({ formatVersion: 1, results });
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

/**
 * Decode resource text strictly. This does not establish completeness or safety
 * for use as a path or as corrective policy.
 */
export function policyFailureResourceText(detail: PolicyFailureDetail): string | undefined {
  if (detail.resource === undefined) return undefined;
  const units = resourceUnits(detail.resource);
  let text = '';
  for (let index = 0; index < units.length; index += 1) {
    const unit = units[index];
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = units[++index];
      if (low === undefined || low < 0xdc00 || low > 0xdfff) malformed('resource contains malformed UTF-16');
      text += String.fromCharCode(unit, low);
    } else {
      if (unit >= 0xdc00 && unit <= 0xdfff) malformed('resource contains malformed UTF-16');
      text += String.fromCharCode(unit);
    }
  }
  return text;
}
