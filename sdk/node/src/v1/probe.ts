// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { readProbeJson } from '../bindings/probe.js';
import { prepareContainerRequest } from './container.js';
import type {
  ContainerRequest,
  IsolationTier,
  ProbeFacts,
  ProbeOutput,
  UiCapabilitySupport,
} from './types.js';

type RequestProbeJsonReader = (requestJson?: string) => string;

const probeOutputFields: readonly (keyof ProbeOutput)[] = [
  'tier',
  'needsDaclAugmentation',
  'warnings',
  'probes',
  'error',
];
const probeOutputKeys = new Set<string>(probeOutputFields);

const probeFactBooleanFields: readonly (keyof ProbeFacts)[] = [
  'baseContainerApiPresent',
  'nativeCaptureAvailable',
  'guardedCaptureAvailable',
  'bfscfgPresent',
  'bfsCompiledIn',
  'baseContainerSupportsDenyPaths',
  'baseContainerSupportsEnumeratePaths',
  'baseContainerSupportsIngressHostLoopbackAllow',
  'baseContainerSupportsIdentitylessLoopbackProxy',
  'isolationSessionAvailable',
  'hyperlightAvailable',
];
const probeFactsKeys = new Set<string>([
  ...probeFactBooleanFields,
  'uiCapabilities',
]);

const uiCapabilitySupportFields: readonly (keyof UiCapabilitySupport)[] = [
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
const uiCapabilitySupportKeys = new Set<string>(uiCapabilitySupportFields);

let requestProbeJsonReader: RequestProbeJsonReader = readProbeJson;
let requestProbePlatform: NodeJS.Platform = process.platform;

/** @internal Replaces request-probe dependencies for unit tests. */
export function _setRequestProbeDependencies(
  reader?: RequestProbeJsonReader,
  platform?: NodeJS.Platform,
): void {
  requestProbeJsonReader = reader ?? readProbeJson;
  requestProbePlatform = platform ?? process.platform;
}

/**
 * Probe which Windows ProcessContainer tier can serve an optional request.
 *
 * The probe is synchronous and does not create a container. It calls the
 * packaged `mxc_ffi` native library in process.
 *
 * @throws Error when called off Windows, when the native probe fails, or when
 * it returns malformed probe JSON.
 */
export function probe(request?: ContainerRequest): ProbeOutput {
  let requestJson: string | undefined;
  if (request !== undefined) {
    requestJson = JSON.stringify(prepareContainerRequest(request));
    if (typeof requestJson !== 'string') {
      throw new TypeError(
        'request probe config must serialize to a JSON string',
      );
    }
  }

  if (requestProbePlatform !== 'win32') {
    throw new Error(
      'the request-aware probe is available only for Windows ProcessContainer',
    );
  }

  const responseJson = requestProbeJsonReader(requestJson);

  let value: unknown;
  try {
    value = JSON.parse(responseJson);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`invalid request probe JSON from mxc_ffi: ${detail}`, {
      cause: error,
    });
  }
  if (!isProbeOutput(value)) {
    throw new Error('invalid request probe output from mxc_ffi');
  }
  return value;
}

function isProbeOutput(value: unknown): value is ProbeOutput {
  if (!isRecord(value)
      || !hasOnlyAllowedKeys(value, probeOutputKeys)
      || !isStringArray(value.warnings)
      || !isProbeFacts(value.probes)) {
    return false;
  }

  if (value.tier !== undefined) {
    return isTier(value.tier)
      && typeof value.needsDaclAugmentation === 'boolean'
      && value.error === undefined;
  }

  return typeof value.error === 'string'
    && value.needsDaclAugmentation === undefined;
}

function isProbeFacts(value: unknown): value is ProbeFacts {
  if (!isRecord(value) || !hasOnlyAllowedKeys(value, probeFactsKeys)) return false;
  return probeFactBooleanFields.every((field) => typeof value[field] === 'boolean')
    && isUiCapabilitySupport(value.uiCapabilities);
}

function isUiCapabilitySupport(value: unknown): value is UiCapabilitySupport {
  if (!isRecord(value)
      || !hasOnlyAllowedKeys(value, uiCapabilitySupportKeys)) {
    return false;
  }
  return uiCapabilitySupportFields.every(
    (field) => typeof value[field] === 'boolean',
  );
}

function isTier(value: unknown): value is IsolationTier {
  return value === 'base-container'
    || value === 'appcontainer-bfs'
    || value === 'appcontainer-dacl';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function hasOnlyAllowedKeys(
  value: Record<string, unknown>,
  allowedKeys: ReadonlySet<string>,
): boolean {
  return Object.keys(value).every((key) => allowedKeys.has(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
