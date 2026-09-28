// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { readAvailableBackendsJson } from './bindings/available-backends.js';
import type { AvailableBackend } from './types.js';

type AvailableBackendsJsonReader = () => string;
let availableBackendsJsonReader: AvailableBackendsJsonReader = readAvailableBackendsJson;

/** @internal Test-only reader seam; production always uses the pinned native owner. */
export function _setAvailableBackendsJsonReader(
  reader?: AvailableBackendsJsonReader,
): void {
  availableBackendsJsonReader = reader ?? readAvailableBackendsJson;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringArray(
  value: unknown,
  field: 'capabilities' | 'warnings',
  index: number,
): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error(`invalid available backend at index ${index}: ${field} must be an array`);
  }
  if (!value.every((item) => typeof item === 'string')) {
    throw new Error(
      `invalid available backend at index ${index}: ${field} entries must be strings`,
    );
  }
  return value;
}

function projectAvailableBackend(value: unknown, index: number): AvailableBackend {
  if (!isRecord(value) || typeof value.backend !== 'string') {
    throw new Error(`invalid available backend at index ${index}: backend must be a string`);
  }
  if (value.tier !== undefined && typeof value.tier !== 'string') {
    throw new Error(`invalid available backend at index ${index}: tier must be a string`);
  }

  return {
    backend: value.backend,
    ...(value.tier === undefined ? {} : { tier: value.tier }),
    capabilities: stringArray(value.capabilities, 'capabilities', index),
    warnings: stringArray(value.warnings, 'warnings', index),
  };
}

/**
 * Return every containment backend the native engine can currently run.
 *
 * The first uncontended Linux call is synchronous and has a conservative
 * 16-second native deadline, excluding ordinary scheduler jitter.
 */
export function getAvailableBackends(): AvailableBackend[] {
  const parsed: unknown = JSON.parse(availableBackendsJsonReader());
  if (!Array.isArray(parsed)) {
    throw new Error('invalid available backends payload: expected an array');
  }
  return parsed.map(projectAvailableBackend);
}
