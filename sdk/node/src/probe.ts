// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFileSync } from 'node:child_process';
import { findWxcExecutable } from './platform.js';
import type {
  ContainerConfig,
  IsolationTier,
  ProbeFacts,
  ProbeOutput,
  UiCapabilitySupport,
} from './types.js';

type RequestProbeRunner = (args: readonly string[]) => string;

function defaultRequestProbeRunner(args: readonly string[]): string {
  if (process.platform !== 'win32') {
    throw new Error(
      'the request-aware probe is available only for Windows ProcessContainer',
    );
  }
  const executable = findWxcExecutable();
  if (!executable) {
    throw new Error('wxc-exec not found');
  }
  return execFileSync(executable, [...args], {
    timeout: 5000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

let requestProbeRunner: RequestProbeRunner = defaultRequestProbeRunner;

/** @internal Replaces the native process invocation for unit tests. */
export function _setRequestProbeRunner(
  runner?: RequestProbeRunner,
): void {
  requestProbeRunner = runner ?? defaultRequestProbeRunner;
}

/**
 * Probe which Windows ProcessContainer tier can serve an optional config.
 *
 * The probe is synchronous and does not create a sandbox. Omitting `config`
 * matches `wxc-exec --probe` without a config.
 */
export function probeSandboxSupport(config?: ContainerConfig): ProbeOutput {
  const args = config === undefined
    ? ['--probe']
    : [
        '--probe',
        '--config-base64',
        Buffer.from(JSON.stringify(config), 'utf-8').toString('base64'),
      ];
  const value: unknown = JSON.parse(requestProbeRunner(args));
  if (!isProbeOutput(value)) {
    throw new Error('invalid request probe output from wxc-exec');
  }
  return value;
}

function isProbeOutput(value: unknown): value is ProbeOutput {
  if (!isRecord(value)
      || !isOptionalTier(value.tier)
      || !isOptionalBoolean(value.needsDaclAugmentation)
      || !isStringArray(value.warnings)
      || !isProbeFacts(value.probes)
      || !isOptionalString(value.error)) {
    return false;
  }
  return true;
}

function isProbeFacts(value: unknown): value is ProbeFacts {
  if (!isRecord(value)) {
    return false;
  }
  const booleanFields: readonly (keyof ProbeFacts)[] = [
    'baseContainerApiPresent',
    'nativeCaptureAvailable',
    'guardedCaptureAvailable',
    'bfscfgPresent',
    'bfsCompiledIn',
    'baseContainerSupportsDenyPaths',
    'baseContainerSupportsEnumeratePaths',
    'baseContainerSupportsIngressHostLoopbackAllow',
    'isolationSessionAvailable',
    'hyperlightAvailable',
  ];
  return booleanFields.every((field) => typeof value[field] === 'boolean')
    && isUiCapabilitySupport(value.uiCapabilities);
}

function isUiCapabilitySupport(value: unknown): value is UiCapabilitySupport {
  if (!isRecord(value)) {
    return false;
  }
  const fields: readonly (keyof UiCapabilitySupport)[] = [
    'canBlockClipboardRead',
    'canBlockClipboardWrite',
    'canBlockInputInjection',
    'canBlockInputMethodChanges',
    'canBlockExternalUiObjects',
    'canBlockGlobalUiNamespace',
    'canBlockDesktopSwitching',
    'canBlockLogoffOrShutdown',
    'canBlockSystemParameterChanges',
    'canBlockDisplaySettingsChanges',
  ];
  return fields.every((field) => typeof value[field] === 'boolean');
}

function isOptionalTier(value: unknown): value is IsolationTier | undefined {
  return value === undefined
    || value === 'base-container'
    || value === 'appcontainer-bfs'
    || value === 'appcontainer-dacl';
}

function isOptionalBoolean(value: unknown): value is boolean | undefined {
  return value === undefined || typeof value === 'boolean';
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === 'string';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.every((entry) => typeof entry === 'string');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
