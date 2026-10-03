// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import { randomBytes } from 'node:crypto';
import {
    ContainerContainment,
    ContainerPolicy,
    ContainerRequest,
    ContainerConfig,
    SandboxContainment,
    Output,
    UnsupportedV1NetworkFields,
} from './types.js';
import { applyLinuxNetworkPolicy } from './helper.js';
import { diagLog } from './diagnostic.js';
import { MxcError } from './errors.js';
import { prepareOneShotRequest } from './bindings/one-shot.js';
import {
  runOneShotJson,
  runOneShotJsonAsync,
  type BindingRunResult,
} from './bindings/run.js';
import {
  spawnBindingSandboxProcess,
  spawnBindingSandboxProcessSync,
} from './bindings/streaming.js';
import { SDK_CONTRACT_VERSION } from './contract-version.js';

export { SDK_CONTRACT_VERSION };
const V1_CONTAINMENTS = new Set<SandboxContainment>([
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

function validateV1Policy(policy: ContainerPolicy, containment: SandboxContainment): void {
    if ('version' in policy) {
          throw new MxcError(
              'malformed_request',
              'ContainerPolicy no longer accepts a caller-selected version; '
              + 'the v1 SDK targets exact contract 1.0.0. '
              + 'The v1 API selects its exact wire contract.',
          );
    }
    if (!V1_CONTAINMENTS.has(containment)) {
        throw new MxcError(
            'unsupported_containment',
            `Containment '${String(containment)}' is not available in the v1.0 high-level SDK. `
            + 'Use a supported V1 containment.',
        );
    }
    if (policy.network !== undefined) {
        for (const field of UnsupportedV1NetworkFields) {
            if (field in policy.network) {
                throw new MxcError(
                    'malformed_request',
                    `ContainerPolicy.network.${field} is not part of the v1 API; `
                    + 'use directional network.egress/network.ingress and '
                    + 'runtimeConfig.networkProxy.',
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
    policy: ContainerPolicy,
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
    policy: ContainerPolicy,
): ContainerConfig {
    const capabilities: string[] = [];
    const allowsInternet =
        policy.network?.egress?.default === 'allow' ||
        Boolean(policy.network?.egress?.allow?.length) ||
        (policy.network as { allowOutbound?: boolean } | undefined)?.allowOutbound === true;
    if (allowsInternet) {
        capabilities.push("internetClient");
    }
    if (policy.network?.ingress?.default === 'allow') {
        capabilities.push("privateNetworkClientServer");
    }

    config.processContainer = {
        leastPrivilege: false,
        capabilities,
        ui: {
            isolation: "container",
            desktopSystemControl: false,
            systemSettings: "none",
            ime: false,
        },
        filesystem: policy.processContainer?.filesystem?.enumeratePaths?.length
            ? { enumeratePaths: [...policy.processContainer.filesystem.enumeratePaths] }
            : undefined,
        network: policy.processContainer?.network?.allowedProxyPeer !== undefined
            ? { allowedProxyPeer: policy.processContainer.network.allowedProxyPeer }
            : undefined,
    };

    return config;
}

/**
 * Builds the internal request config from a V1 policy and containment type.
 *
 * This adapter translates user-facing security intent into the exact request
 * consumed by the in-process binding.
 *
 * @param policy - The sandbox policy expressing security intent
 * @param containment - Containment backend type (default: "process")
 * @param containerName - Optional container name; auto-generated if omitted
 * @returns An internal config consumed by the exact-contract adapter.
 */
function createContainerConfig(
    policy: ContainerPolicy,
    containment: SandboxContainment = "process",
    containerName?: string,
): ContainerConfig {
    validateV1Policy(policy, containment);
    const platform = os.platform();
    const enumeratePaths = policy.processContainer?.filesystem?.enumeratePaths;

    const containerId = containerName ?? generateRandomContainerName();

    const clearPolicy = policy.filesystem?.clearPolicyOnExit ?? true;
    const config: ContainerConfig = {
        version: SDK_CONTRACT_VERSION,
        containerId,
        lifecycle: {
            destroyOnExit: true,
            preservePolicy: !clearPolicy,
        },
        process: {
            commandLine: '',
            timeout: policy.timeoutMs ?? 0,
        },
        telemetry: policy.telemetry === undefined ? undefined : { ...policy.telemetry },
    };

    if (enumeratePaths?.length) {
        const targetsWindowsProcessContainer =
            platform === 'win32' && containment === 'processcontainer';
        if (!targetsWindowsProcessContainer) {
            throw new Error(
                'processContainer.filesystem.enumeratePaths is supported only by the Windows ' +
                'ProcessContainer backend.'
            );
        }
    }

    config.filesystem = {
        readwritePaths: [...(policy.filesystem?.readwritePaths ?? [])],
        readonlyPaths: [...(policy.filesystem?.readonlyPaths ?? [])],
        deniedPaths: [...(policy.filesystem?.deniedPaths ?? [])],
    };
    if (enumeratePaths?.length) {
        config.processContainer = {
            filesystem: {
                enumeratePaths: [...enumeratePaths],
            },
        };
    }

    if (policy.ui !== undefined) {
        config.ui = {
            disable: !(policy.ui.allowWindows ?? false),
            clipboard: policy.ui.clipboard ?? "none",
            injection: policy.ui.allowInputInjection ?? false,
        };
    }

    if (policy.network?.egress !== undefined || policy.network?.ingress !== undefined) {
        config.network = {
            egress: policy.network.egress,
            ingress: policy.network.ingress,
        };
    }
    if (policy.runtimeConfig?.networkProxy !== undefined) {
        config.runtimeConfig = {
            networkProxy: policy.runtimeConfig.networkProxy,
        };
    }
    if (policy.processContainer?.network?.allowedProxyPeer !== undefined) {
        config.processContainer = {
            ...config.processContainer,
            network: {
                allowedProxyPeer: policy.processContainer.network.allowedProxyPeer,
            },
        };
    }

    // Backend-specific config based on containment type
    if (containment === 'wslc') {
        return buildWslcContainerConfig(config, policy, containerId);
    }

    if (containment === 'isolation_session') {
        config.containment = 'isolation_session';
        diagLog(`createConfigFromPolicy: containment=isolation_session, id=${containerId}`);
        return config;
    }

    if (containment === 'bubblewrap') {
        diagLog(`createConfigFromPolicy: containment=bubblewrap, id=${containerId}`);
        return buildBubblewrapConfig(config);
    }

    if (containment === 'lxc') {
        diagLog(`createConfigFromPolicy: containment=lxc, id=${containerId}`);
        config.containment = 'lxc';
        return buildLinuxProcessConfig(config);
    }

    if (containment === 'seatbelt') {
        config.containment = 'seatbelt';
        diagLog(`createConfigFromPolicy: containment=seatbelt, id=${containerId}`);
        return buildDarwinProcessConfig(config);
    }

    if (containment === 'processcontainer') {
        config.containment = 'processcontainer';
        diagLog(`createConfigFromPolicy: containment=processcontainer, id=${containerId}`);
        return buildProcessBaseContainerConfig(config, policy);
    }

    if (containment === 'process') {
        config.containment = 'process';
        diagLog(`createConfigFromPolicy: containment=process, id=${containerId}`);
        return config;
    }

    throw new Error(`Containment type '${containment}' is not yet supported.`);
}

export const createConfigFromPolicy = createContainerConfig;

/**
 * Builds a sandbox payload JSON object from the sandbox policy.
 * @param script The command line script to execute
 * @param policy The sandbox policy configuration
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @param containment Optional containment backend type
 * @returns The sandbox payload object
 */
export function buildSandboxPayload(
    script: string,
    policy: ContainerPolicy,
    workingDirectory?: string,
    containerName?: string,
    containment: SandboxContainment = "process",
): ContainerConfig {
    const config = createContainerConfig(policy, containment, containerName);

    config.process!.commandLine = script;
    config.process!.cwd = workingDirectory;

    return config;
}

function appendDiagnosticLine(output: string, line: string): string {
  const prefix = output.length === 0 || output.endsWith('\n') ? output : `${output}\n`;
  return `${prefix}${line}\n`;
}

function bufferedStderr(result: BindingRunResult): string {
  let stderr = result.stderr;
  for (const warning of result.warnings) {
    stderr = appendDiagnosticLine(stderr, warning);
  }

  if (
    result.outputMetadata !== null
    && typeof result.outputMetadata === 'object'
    && !Array.isArray(result.outputMetadata)
  ) {
    const captureDenials = (result.outputMetadata as Record<string, unknown>).captureDenials;
    if (captureDenials !== undefined) {
      stderr = appendDiagnosticLine(stderr, JSON.stringify(captureDenials));
    }
  }
  return stderr;
}

function containerConfig(request: ContainerRequest): ContainerConfig {
  if (request === null || typeof request !== 'object') {
    throw new MxcError('malformed_request', 'container request must be an object');
  }
  if (typeof request.command !== 'string' || request.command.length === 0) {
    throw new MxcError('malformed_request', 'container request command must be a non-empty string');
  }
  if (request.policy === null || typeof request.policy !== 'object') {
    throw new MxcError('malformed_request', 'container request policy must be an object');
  }

  const selected = request.containment ?? { type: 'process' as const };
  const config = createContainerConfig(
    request.policy,
    selected.type,
    request.containerName,
  );
  config.process!.commandLine = request.command;

  switch (selected.type) {
    case 'process':
    case 'isolation_session':
    case 'bubblewrap':
      break;
    case 'processcontainer':
      config.processContainer = { ...config.processContainer, ...selected.config };
      break;
    case 'wslc':
      config.wslc = { ...config.wslc, ...selected.config };
      break;
    case 'lxc':
      config.lxc = { ...config.lxc, ...selected.config };
      break;
    case 'seatbelt':
      config.seatbelt = { ...config.seatbelt, ...selected.config };
      break;
    default: {
      const unreachable: never = selected;
      throw new MxcError(
        'malformed_request',
        `unsupported containment '${String(unreachable)}'`,
      );
    }
  }
  return config;
}

function oneShotRequest(request: ContainerRequest) {
  const config = containerConfig(request);
  return prepareOneShotRequest(config, {
    workingDirectory: request.workingDirectory,
    env: request.environment,
    inheritDefaultEnv: request.inheritDefaultEnvironment,
  });
}

function toOutput(result: BindingRunResult): Output {
  const output: Output = {
    stdout: result.stdout,
    stderr: bufferedStderr(result),
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    warnings: result.warnings,
  };
  if (result.outputMetadata !== undefined) {
    output.outputMetadata = result.outputMetadata;
  }
  return output;
}

/** Spawn a one-shot request and return its live pipe-backed process. */
export function spawn(request: ContainerRequest) {
  return spawnBindingSandboxProcessSync(oneShotRequest(request));
}

/** Asynchronously spawn a one-shot request and return its live process. */
export async function spawnAsync(request: ContainerRequest) {
  return spawnBindingSandboxProcess(oneShotRequest(request));
}

/** Run a one-shot request synchronously and capture its output. */
export function run(request: ContainerRequest): Output {
  return toOutput(runOneShotJson(oneShotRequest(request)));
}

/** Run a one-shot request asynchronously and capture its output. */
export async function runAsync(request: ContainerRequest): Promise<Output> {
  return toOutput(await runOneShotJsonAsync(oneShotRequest(request)));
}
