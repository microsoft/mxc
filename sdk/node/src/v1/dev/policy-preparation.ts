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
  return !/\p{Surrogate}/u.test(value);
}

class JsonResultBudget {
  bytes = 0;
  readonly copies = new WeakMap<object, { value: JsonValue; bytes: number }>();

  add(bytes: number): void {
    this.bytes += bytes;
    if (this.bytes > MAX_RESULT_BYTES) malformed('JSON result limit exceeded');
  }

  string(value: string): void {
    if (value.length > MAX_RESULT_BYTES - this.bytes - 2) malformed('JSON result limit exceeded');
    this.add(2 + Buffer.byteLength(value, 'utf8'));
    for (const match of value.matchAll(/["\\\u0000-\u001f]/g)) {
      const code = match[0].charCodeAt(0);
      // Short escapes add one byte; the other control escapes add five.
      this.add(code >= 0x20 || code === 8 || code === 9 || code === 10
        || code === 12 || code === 13 ? 1 : 5);
    }
  }
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

function copyJsonValue(
  value: unknown,
  budget?: JsonResultBudget,
  ancestors = new Set<object>(),
): JsonValue {
  if (value === null || typeof value === 'boolean') {
    budget?.add(value === false ? 5 : 4);
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    budget?.add(String(value).length);
    return value;
  }
  if (typeof value === 'string') {
    budget?.string(value);
    if (validText(value)) return value;
    malformed('before and after must be JSON values');
  }
  if (typeof value !== 'object' || value === null
      || (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)
      || ancestors.has(value)) {
    malformed('before and after must be JSON values');
  }
  const cached = budget?.copies.get(value);
  if (budget && cached) {
    budget.add(cached.bytes);
    return cached.value;
  }
  const start = budget?.bytes ?? 0;
  budget?.add(2);
  ancestors.add(value);
  try {
    let copy: JsonValue;
    if (Array.isArray(value)) {
      const entries: JsonValue[] = [];
      for (const entry of value) {
        if (entries.length !== 0) budget?.add(1);
        entries.push(copyJsonValue(entry, budget, ancestors));
      }
      copy = entries;
    } else {
      const entries: { [key: string]: JsonValue } = {};
      let first = true;
      for (const key in value) {
        if (!Object.hasOwn(value, key)) continue;
        if (!first) budget?.add(1);
        first = false;
        budget?.string(key);
        if (!validText(key)) malformed('JSON object keys must contain valid Unicode');
        budget?.add(1);
        Object.defineProperty(entries, key, {
          value: copyJsonValue((value as Record<string, unknown>)[key], budget, ancestors),
          enumerable: true, configurable: true, writable: true,
        });
      }
      copy = entries;
    }
    // Keep shared snapshots compact, but charge for every serialized occurrence.
    if (budget) budget.copies.set(value, { value: copy, bytes: budget.bytes - start });
    return copy;
  } finally {
    ancestors.delete(value);
  }
}

function readPreparedPolicyRequest(value: unknown, budget?: JsonResultBudget): PreparedPolicyRequest {
  const result = record(value, ['requestJson', 'changes']);
  budget?.add('{"requestJson":,"changes":[]}'.length);
  const requestJson = result.requestJson;
  if (typeof requestJson === 'string') budget?.string(requestJson);
  checkRequestJson(requestJson);
  const edits = result.changes;
  if (!Array.isArray(edits) || edits.length > MAX_CHANGES) {
    malformed('changes must be an array of at most 4096 edits');
  }
  const changes = Array.from(edits, (entry: unknown, index): PolicyPreparationChange => {
    if (index !== 0) budget?.add(1);
    budget?.add('{"operation":,"path":,"before":,"after":}'.length);
    const change = record(entry, ['operation', 'path', 'before', 'after']);
    const path = change.path;
    if (typeof path === 'string') budget?.string(path);
    if (typeof path !== 'string' || !validText(path)
        || (path !== '' && !path.startsWith('/'))
        || /~(?:[^01]|$)/.test(path)) {
      malformed('path must be an RFC 6901 JSON Pointer');
    }
    const operation = change.operation;
    if (typeof operation === 'string') budget?.string(operation);
    const before = copyJsonValue(change.before, budget);
    const after = copyJsonValue(change.after, budget);
    switch (operation) {
      case 'add':
        if (before !== null) malformed('add requires before: null for absence');
        return { operation: 'add', path, before, after };
      case 'remove':
        if (after !== null) malformed('remove requires after: null for absence');
        return { operation: 'remove', path, before, after };
      case 'replace':
        return { operation: 'replace', path, before, after };
      default:
        malformed('operation must be add, remove, or replace');
    }
  });
  return { requestJson, changes };
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
    const json = JSON.stringify(readPreparedPolicyRequest(value, new JsonResultBudget()));
    if (Buffer.byteLength(json, 'utf8') > MAX_RESULT_BYTES) malformed('JSON result limit exceeded');
    return json;
  } catch (error) {
    if (error instanceof MxcError) throw error;
    malformed('invalid JSON values');
  }
}
