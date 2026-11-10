// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { MxcError } from '../errors.js';
import { hasDuplicateJsonKeys } from './json-duplicate-keys.js';

/** Preparation authorization, independent of creation options and the JSON version. */
export interface PolicyPreparationOptions {
  experimental?: boolean;
}

/** A JSON value, including real JSON null. Numbers must be finite. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** An RFC 6901 JSON Pointer, using ~0 and ~1 to escape ~ and /. */
export type JsonPointer = string;

/** An ordered edit; operation distinguishes absence from a real JSON null. */
export type PolicyPreparationChange =
  | { operation: 'add'; path: JsonPointer; before: null; after: JsonValue }
  | { operation: 'remove'; path: JsonPointer; before: JsonValue; after: null }
  | { operation: 'replace'; path: JsonPointer; before: JsonValue; after: JsonValue };

/** A candidate request and its ordered edits, for application inspection and acceptance. */
export interface PreparedPolicyRequest {
  requestJson: string;
  changes: PolicyPreparationChange[];
}

const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_RESULT_BYTES = 32 * 1024 * 1024;
const MAX_CHANGES = 4096;

function malformed(message: string): never {
  throw new MxcError('malformed_request', `invalid prepared policy request: ${message}`);
}

function validText(value: string): boolean {
  return Buffer.from(value, 'utf8').toString('utf8') === value;
}

function checkRequestJson(requestJson: unknown): asserts requestJson is string {
  if (typeof requestJson !== 'string' || requestJson.includes('\0') || !validText(requestJson)) {
    malformed('requestJson must contain valid UTF-8 JSON text');
  }
  let request: unknown;
  try {
    request = JSON.parse(requestJson);
  } catch {
    malformed('requestJson must contain a JSON object');
  }
  if (request === null || typeof request !== 'object' || Array.isArray(request)) {
    malformed('requestJson must contain a JSON object');
  }
}

/** @internal Validate transport text without selecting a contract, phase, or backend. */
export function checkPolicyPreparationRequest(requestJson: unknown): asserts requestJson is string {
  if (typeof requestJson !== 'string' || Buffer.byteLength(requestJson, 'utf8') > MAX_INPUT_BYTES) {
    malformed('input requestJson must be a JSON string of at most 8 MiB UTF-8');
  }
  checkRequestJson(requestJson);
}

function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || fields.some((key) => !Object.hasOwn(value, key))
      || Object.keys(value).some((key) => !fields.includes(key))) {
    malformed('expected an object with the documented fields');
  }
  return value as Record<string, unknown>;
}

function copyJsonValue(value: unknown, ancestors = new Set<object>()): JsonValue {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && validText(value)) return value;
  if (typeof value !== 'object' || value === null
      || (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)
      || ancestors.has(value)) {
    malformed('before and after must be JSON values');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return Array.from(value, (entry: unknown) => copyJsonValue(entry, ancestors));
    }
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => {
      if (!validText(key)) malformed('JSON object keys must contain valid Unicode');
      return [key, copyJsonValue(entry, ancestors)];
    }));
  } finally {
    ancestors.delete(value);
  }
}

function readPreparedPolicyRequest(value: unknown): PreparedPolicyRequest {
  const result = record(value, ['requestJson', 'changes']);
  checkRequestJson(result.requestJson);
  if (!Array.isArray(result.changes) || result.changes.length > MAX_CHANGES) {
    malformed('changes must be an array of at most 4096 edits');
  }
  const changes = Array.from(result.changes, (entry: unknown): PolicyPreparationChange => {
    const change = record(entry, ['operation', 'path', 'before', 'after']);
    if (typeof change.path !== 'string' || !validText(change.path)
        || (change.path !== '' && !change.path.startsWith('/'))
        || /~(?:[^01]|$)/.test(change.path)) {
      malformed('path must be an RFC 6901 JSON Pointer');
    }
    const before = copyJsonValue(change.before);
    const after = copyJsonValue(change.after);
    switch (change.operation) {
      case 'add':
        if (before !== null) malformed('add requires before: null for absence');
        return { operation: 'add', path: change.path, before, after };
      case 'remove':
        if (after !== null) malformed('remove requires after: null for absence');
        return { operation: 'remove', path: change.path, before, after };
      case 'replace':
        return { operation: 'replace', path: change.path, before, after };
      default:
        malformed('operation must be add, remove, or replace');
    }
  });
  return { requestJson: result.requestJson, changes };
}

/** Parse application-owned preparation storage without echoing malformed input. */
export function parsePreparedPolicyRequest(json: string): PreparedPolicyRequest {
  if (typeof json !== 'string' || Buffer.byteLength(json, 'utf8') > MAX_RESULT_BYTES
      || !validText(json)) {
    malformed('expected a JSON string of at most 32 MiB UTF-8');
  }
  try {
    const value = JSON.parse(json) as unknown;
    if (hasDuplicateJsonKeys(json)) malformed('duplicate JSON object keys');
    return readPreparedPolicyRequest(value);
  } catch (error) {
    if (error instanceof MxcError) throw error;
    malformed('malformed JSON or invalid JSON values');
  }
}

/** Serialize an owned, checked candidate; both before and after remain present. */
export function serializePreparedPolicyRequest(value: PreparedPolicyRequest): string {
  try {
    const json = JSON.stringify(readPreparedPolicyRequest(value));
    if (Buffer.byteLength(json, 'utf8') > MAX_RESULT_BYTES) malformed('JSON result limit exceeded');
    return json;
  } catch (error) {
    if (error instanceof MxcError) throw error;
    malformed('invalid JSON values');
  }
}
