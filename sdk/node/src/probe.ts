// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { probeBindingRequestJson } from './bindings/probe.js';
import { prepareRequestSpec } from './bindings/request.js';
import type {
  ContainerConfig,
  IsolationTier,
  ProbeFacts,
  ProbeOutput,
  UiCapabilitySupport,
} from './types.js';

type RequestProbeRunner = (requestJson?: string) => string;

let requestProbeRunner: RequestProbeRunner = probeBindingRequestJson;

/** @internal Replaces the native binding invocation for unit tests. */
export function _setRequestProbeRunner(
  runner?: RequestProbeRunner,
): void {
  requestProbeRunner = runner ?? probeBindingRequestJson;
}

/**
 * Probe which Windows ProcessContainer tier can serve an optional config.
 *
 * The probe is synchronous and does not create a sandbox. Omitting `config`
 * probes the default empty request in-process through `mxc_ffi`.
 */
export function probeSandboxSupport(config?: ContainerConfig): ProbeOutput {
  const requestJson = config === undefined
    ? undefined
    : JSON.stringify(prepareRequestSpec(config));
  let value: unknown;
  try {
    value = JSON.parse(requestProbeRunner(requestJson));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`invalid request probe JSON from mxc_ffi: ${detail}`);
  }
  if (!isProbeOutput(value)) {
    throw new Error('invalid request probe output from mxc_ffi');
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
