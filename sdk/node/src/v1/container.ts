// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import { randomBytes } from 'node:crypto';
import {
    ContainerRequest,
    ContainerConfig,
    ContainmentChoice,
    ExecutionResult,
    type MxcOptions,
    UnsupportedV1NetworkFields,
} from './types.js';
import { applyLinuxNetworkPolicy } from '../helper.js';
import { diagLog } from '../diagnostic.js';
import { MxcError } from './errors.js';
import { prepareOneShotRequest } from '../bindings/one-shot.js';
import {
  runOneShotJsonAsync,
  type BindingRunResult,
} from '../bindings/run.js';
import {
  spawnBindingSandboxProcess,
} from '../bindings/streaming.js';
import type { MxcProcess } from './container-process.js';
import { spawnBindingSandboxWithPty } from '../bindings/pty.js';
import { spawnProcessContainerWithPty } from '../bindings/process-container-pty.js';
import type { MxcPtyProcess } from './mxc-pty-process.js';
import { SDK_CONTRACT_VERSION } from './contract-version.js';
import type { RunOptions, SpawnOptions, SpawnWithPtyOptions } from './operation-options.js';

export { SDK_CONTRACT_VERSION };
const V1_CONTAINMENTS = new Set<ContainmentChoice>([
    'process',
    'processcontainer',
    'wslc',
    'lxc',
    'seatbelt',
    'isolation_session',
    'bubblewrap',
]);

/** Generates a 128-bit random container identifier as 32 hexadecimal characters. */
function generateRandomContainerName(): string {
    return randomBytes(16).toString("hex");
}

function validateV1Request(
  request: ContainerRequest,
  containment: ContainmentChoice,
): void {
    if ('version' in request) {
        throw new MxcError(
            'malformed_request',
            'ContainerRequest does not accept a caller-selected version; use the raw-config API.',
        );
    }
    if ('runtimeConfig' in request) {
        throw new MxcError(
            'malformed_request',
            'ContainerRequest.runtimeConfig is not part of the V1 authoring API; '
            + 'use network.runtimeConfig instead.',
        );
    }
    if ('telemetry' in request) {
        throw new MxcError(
            'malformed_request',
            'ContainerRequest.telemetry is not part of the V1 authoring API; '
            + 'use the operation options instead.',
        );
    }
    if (!V1_CONTAINMENTS.has(containment)) {
        throw new MxcError(
            'unsupported_containment',
            `Containment '${String(containment)}' is not available in the v1.0 high-level SDK. `
            + 'Use a supported V1 containment.',
        );
    }
    if (request.containment?.type === 'processcontainer'
        && request.containment.config !== undefined
        && 'leastPrivilege' in request.containment.config) {
        throw new MxcError(
            'malformed_request',
            'containment.config.leastPrivilege is not part of the V1 authoring API.',
        );
    }
    if (containment === 'isolation_session' && request.ui !== undefined) {
        throw new MxcError(
            'malformed_request',
            'IsolationSession does not enforce UI policy; omit request.ui.',
        );
    }
    if (request.network !== undefined) {
        for (const field of UnsupportedV1NetworkFields) {
            if (field in request.network) {
                throw new MxcError(
                    'malformed_request',
                    `ContainerRequest.network.${field} is not part of the v1 API; `
                    + 'use directional network.egress/network.ingress and '
                    + 'network.runtimeConfig.networkProxy.',
                );
            }
        }
    }
}

/**
 * Builds the WSLC (WSL Container) portion of a ContainerConfig.
 * WSLC runs Linux containers on Windows via the WSL Container SDK.
 * The exact contract location is independent of the runtime experimental gate.
 */
function buildWslcContainerConfig(
    config: ContainerConfig,
    containerId: string,
): ContainerConfig {
    config.containment = 'wslc';
    config.containerId = containerId;

    config.wslc = {
        image: 'alpine:latest',
        gpu: false,
    };

    // WSLC uses its own networking mode (None/Bridged) derived from
    // the directional egress posture — no firewall enforcement needed.

    return config;
}

/**
 * Builds the Bubblewrap (bwrap) portion of a ContainerConfig.
 * Bubblewrap is Linux-only and uses shared cross-backend fields only —
 * no backend-specific config block. Network enforcement via iptables
 * reuses the same approach as LXC.
 */
function buildBubblewrapConfig(
    config: ContainerConfig,
): ContainerConfig {
    config.containment = 'bubblewrap';
    applyLinuxNetworkPolicy(config);
    return config;
}

/**
 * Builds the Linux process container (LXC) portion of a ContainerConfig.
 */
function buildLinuxProcessConfig(
    config: ContainerConfig,
): ContainerConfig {
    config.lxc = {
        distribution: 'alpine',
        release: '3.23',
    };
    applyLinuxNetworkPolicy(config);
    return config;
}

/**
 * Builds the macOS process container (seatbelt) portion of a ContainerConfig.
 *
 * The seatbelt backend's `sandbox-exec` reads a TinyScheme profile
 * generated server-side by `seatbelt_common::profile_builder`, so the SDK
 * only needs to set the containment type and ensure the top-level `seatbelt`
 * config block exists — the policy fields on `ContainerConfig` (filesystem /
 * network / ui) drive the actual rules.
 */
function buildDarwinProcessConfig(
    config: ContainerConfig,
): ContainerConfig {
    config.containment = 'seatbelt';
    config.seatbelt = config.seatbelt ?? {};
    return config;
}

/**
 * Builds the Windows process container portion of a ContainerConfig.
 */
function buildProcessBaseContainerConfig(
    config: ContainerConfig,
    request: ContainerRequest,
): ContainerConfig {
      const capabilities: string[] = [];
      const allowsInternet =
          request.network?.egress?.default === 'allow' ||
          Boolean(request.network?.egress?.allow?.length);
    if (allowsInternet) {
        capabilities.push("internetClient");
    }
    if (request.network?.ingress?.default === 'allow') {
        capabilities.push("privateNetworkClientServer");
    }

    config.processContainer = {
        capabilities,
        ui: {
            isolation: "container",
            desktopSystemControl: false,
            systemSettings: "none",
            ime: false,
        },
        filesystem: undefined,
        network: undefined,
    };

    return config;
}

/**
 * Builds the internal request config from a V1 container request.
 *
 * This adapter translates user-facing security intent into the exact request
 * consumed by the in-process binding.
 *
 * @param request - Cross-backend request and selected backend configuration
 * @returns An internal config consumed by the exact-contract adapter.
 */
function createContainerConfig(request: ContainerRequest): ContainerConfig {
    const selected = request.containment ?? { type: 'process' as const };
    validateV1Request(request, selected.type);
    const platform = os.platform();
    const containerId = request.containerName ?? generateRandomContainerName();

    const clearPolicy = request.filesystem?.clearPolicyOnExit ?? true;
    const config: ContainerConfig = {
        version: SDK_CONTRACT_VERSION,
        containerId,
        lifecycle: {
            destroyOnExit: true,
            preservePolicy: !clearPolicy,
        },
        process: {
            commandLine: request.command,
            timeout: request.timeoutMs ?? 0,
        },
    };

    const enumeratePaths = selected.type === 'processcontainer'
        ? selected.config?.filesystem?.enumeratePaths
        : undefined;
    if (enumeratePaths?.length) {
        const targetsWindowsProcessContainer =
            platform === 'win32' && selected.type === 'processcontainer';
        if (!targetsWindowsProcessContainer) {
            throw new Error(
                'containment.config.filesystem.enumeratePaths is supported only by the ' +
                'Windows ProcessContainer backend.',
            );
        }
    }

    config.filesystem = {
        readwritePaths: [...(request.filesystem?.readwritePaths ?? [])],
        readonlyPaths: [...(request.filesystem?.readonlyPaths ?? [])],
        deniedPaths: [...(request.filesystem?.deniedPaths ?? [])],
    };

    if (request.ui !== undefined) {
        config.ui = {
            disable: request.ui.disable,
            clipboard: request.ui.clipboard ?? "none",
            injection: request.ui.allowInputInjection ?? false,
        };
    }

    if (request.network?.egress !== undefined || request.network?.ingress !== undefined) {
        config.network = {
            egress: request.network.egress,
            ingress: request.network.ingress,
        };
    }
    if (request.network?.runtimeConfig?.networkProxy !== undefined) {
        config.runtimeConfig = {
            networkProxy: request.network.runtimeConfig.networkProxy,
        };
    }

    // Backend-specific config based on containment type
    if (selected.type === 'wslc') {
        const base = buildWslcContainerConfig(config, containerId);
        base.wslc = { ...base.wslc, ...selected.config };
        return base;
    }

    if (selected.type === 'isolation_session') {
        config.containment = 'isolation_session';
        diagLog(`createConfigFromRequest: containment=isolation_session, id=${containerId}`);
        return config;
    }

    if (selected.type === 'bubblewrap') {
        diagLog(`createConfigFromRequest: containment=bubblewrap, id=${containerId}`);
        return buildBubblewrapConfig(config);
    }

    if (selected.type === 'lxc') {
        diagLog(`createConfigFromRequest: containment=lxc, id=${containerId}`);
        config.containment = 'lxc';
        const base = buildLinuxProcessConfig(config);
        base.lxc = { ...base.lxc, ...selected.config };
        return base;
    }

    if (selected.type === 'seatbelt') {
        config.containment = 'seatbelt';
        diagLog(`createConfigFromRequest: containment=seatbelt, id=${containerId}`);
        const base = buildDarwinProcessConfig(config);
        base.seatbelt = { ...base.seatbelt, ...selected.config };
        return base;
    }

    if (selected.type === 'processcontainer') {
        config.containment = 'processcontainer';
        diagLog(`createConfigFromRequest: containment=processcontainer, id=${containerId}`);
        const base = buildProcessBaseContainerConfig(config, request);
        base.processContainer = {
          ...base.processContainer,
          ...selected.config,
        };
        return base;
    }

    if (selected.type === 'process') {
        config.containment = 'process';
        diagLog(`createConfigFromRequest: containment=process, id=${containerId}`);
        return config;
    }

    const unreachable: never = selected;
    throw new MxcError(
      'malformed_request',
      `unsupported containment '${String(unreachable)}'`,
    );
}

export const createConfigFromRequest = createContainerConfig;

function containerConfig(request: ContainerRequest): ContainerConfig {
  if (request === null || typeof request !== 'object') {
    throw new MxcError('malformed_request', 'container request must be an object');
  }
  if (typeof request.command !== 'string' || request.command.length === 0) {
    throw new MxcError('malformed_request', 'container request command must be a non-empty string');
  }
  return createContainerConfig(request);
}

/** @internal Maps a public request to the native exact contract. */
export function prepareContainerRequest(
  request: ContainerRequest,
  telemetry?: RunOptions['telemetry'],
) {
  const config = containerConfig(request);
  if (telemetry !== undefined) config.telemetry = { ...telemetry };
  return prepareOneShotRequest(config, {
    workingDirectory: request.workingDirectory,
    env: request.environment,
    inheritDefaultEnv: request.inheritDefaultEnvironment,
  });
}

function validateOperationOptions(
  apiName: string,
  options: MxcOptions,
  supportsDryRun: boolean,
  additionalOptionKeys: readonly string[] = [],
): void {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new MxcError('malformed_request', `${apiName} options must be an object`);
  }
  for (const [key, value] of Object.entries(options)) {
    if (key === 'dryRun' && !supportsDryRun) {
      throw new MxcError(
        'malformed_request',
        `${apiName} does not support dryRun because it executes the request`,
      );
    }
    if (key === 'telemetry') {
      if (
        value !== undefined &&
        (
          value === null ||
          typeof value !== 'object' ||
          Array.isArray(value) ||
          Object.entries(value).some(([field, enabled]) =>
            field !== 'enabled' || (enabled !== undefined && typeof enabled !== 'boolean'))
        )
      ) {
        throw new MxcError(
          'malformed_request',
          `${apiName} telemetry must contain only an optional boolean enabled`,
        );
      }
      continue;
    }
    if (
      key !== 'experimental' &&
      key !== 'dryRun' &&
      !additionalOptionKeys.includes(key)
    ) {
      throw new MxcError(
        'malformed_request',
        `${apiName} does not support option '${key}'`,
      );
    }
    if (additionalOptionKeys.includes(key)) continue;
    if (value !== undefined && typeof value !== 'boolean') {
      throw new MxcError(
        'malformed_request',
        `${apiName} option '${key}' must be a boolean`,
      );
    }
  }
}

function toExecutionResult(result: BindingRunResult): ExecutionResult {
  const output: ExecutionResult = {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    warnings: result.warnings,
  };
  if (result.outputMetadata !== undefined) {
    output.outputMetadata = result.outputMetadata;
  }
  return output;
}

/** Create a container request and asynchronously return its live process. */
export async function spawn(
  request: ContainerRequest,
  options: SpawnOptions = {},
): Promise<MxcProcess> {
  validateOperationOptions('spawn', options, false);
  return spawnBindingSandboxProcess(
    prepareContainerRequest(request, options.telemetry),
    options.experimental === true,
  );
}

/** Create a container request attached to an MXC-owned pseudo-terminal. */
export async function spawnWithPty(
  request: ContainerRequest,
  options: SpawnWithPtyOptions = {},
): Promise<MxcPtyProcess> {
  validateOperationOptions('spawnWithPty', options, false, ['size']);
  const size = options.size ?? { rows: 24, columns: 80 };
  if (
    !Number.isInteger(size.rows) ||
    !Number.isInteger(size.columns) ||
    size.rows < 1 ||
    size.rows > 32767 ||
    size.columns < 1 ||
    size.columns > 32767
  ) {
    throw new MxcError(
      'malformed_request',
      'PTY rows and columns must be integers between 1 and 32767',
    );
  }
  const preparedRequest = prepareContainerRequest(request, options.telemetry);
  const spawnPty = process.platform === 'win32'
      && preparedRequest.containment === 'processcontainer'
    ? spawnProcessContainerWithPty
    : spawnBindingSandboxWithPty;
  return spawnPty(
    preparedRequest,
    options.experimental === true,
    size.rows,
    size.columns,
  );
}

/** Run a container request asynchronously and capture its output. */
export async function run(
  request: ContainerRequest,
  options: RunOptions = {},
): Promise<ExecutionResult> {
  validateOperationOptions('run', options, false);
  return toExecutionResult(await runOneShotJsonAsync(
    prepareContainerRequest(request, options.telemetry),
    options.experimental === true,
  ));
}
