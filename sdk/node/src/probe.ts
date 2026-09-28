// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { findWxcExecutable } from './platform.js';
import type {
  ContainerConfig,
  IsolationTier,
  ProbeFacts,
  ProbeOutput,
  UiCapabilitySupport,
} from './types.js';

type RequestProbeRunner = (executable: string, args: readonly string[]) => string;
type ExecutableFinder = () => string | null;

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

function defaultRequestProbeRunner(executable: string, args: readonly string[]): string {
  return execFileSync(executable, [...args], {
    timeout: 5000,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

let requestProbeRunner: RequestProbeRunner = defaultRequestProbeRunner;
let executableFinder: ExecutableFinder = findWxcExecutable;
let requestProbePlatform: NodeJS.Platform = process.platform;

/** @internal Replaces request-probe dependencies for unit tests. */
export function _setRequestProbeDependencies(
  runner?: RequestProbeRunner,
  finder?: ExecutableFinder,
  platform?: NodeJS.Platform,
): void {
  requestProbeRunner = runner ?? defaultRequestProbeRunner;
  executableFinder = finder ?? findWxcExecutable;
  requestProbePlatform = platform ?? process.platform;
}

/**
 * Probe which Windows ProcessContainer tier can serve an optional config.
 *
 * The probe is synchronous and does not create a sandbox. It invokes the
 * packaged `wxc-exec --probe` diagnostic and removes its temporary config
 * before returning.
 *
 * @throws Error when called off Windows, when `wxc-exec` is unavailable or
 * fails, or when the executor returns malformed probe JSON.
 */
export function probeSandboxSupport(config?: ContainerConfig): ProbeOutput {
  if (requestProbePlatform !== 'win32') {
    throw new Error(
      'the request-aware probe is available only for Windows ProcessContainer',
    );
  }

  const executable = executableFinder();
  if (!executable) {
    throw new Error(
      'wxc-exec.exe not found; the request-aware probe requires the packaged Windows executor',
    );
  }

  let tempDirectory: string | undefined;
  try {
    const args = ['--probe'];
    if (config !== undefined) {
      tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-request-probe-'));
      const configPath = path.join(tempDirectory, 'config.json');
      fs.writeFileSync(configPath, JSON.stringify(config), 'utf-8');
      args.push(configPath);
    }

    let stdout: string;
    try {
      stdout = requestProbeRunner(executable, args);
    } catch (error) {
      throw new Error(
        `wxc-exec request probe failed: ${subprocessErrorDetail(error)}`,
        { cause: error },
      );
    }

    let value: unknown;
    try {
      value = JSON.parse(stdout);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`invalid request probe JSON from wxc-exec: ${detail}`, {
        cause: error,
      });
    }
    if (!isProbeOutput(value)) {
      throw new Error('invalid request probe output from wxc-exec');
    }
    return value;
  } finally {
    if (tempDirectory !== undefined) {
      fs.rmSync(tempDirectory, { recursive: true, force: true });
    }
  }
}

function subprocessErrorDetail(error: unknown): string {
  if (error && typeof error === 'object' && 'stderr' in error) {
    const stderr = (error as { stderr?: string | Buffer }).stderr;
    const text = Buffer.isBuffer(stderr) ? stderr.toString('utf-8') : stderr;
    if (text?.trim()) return text.trim();
  }
  return error instanceof Error ? error.message : String(error);
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
