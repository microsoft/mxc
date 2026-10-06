// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Adapts the public ContainerConfig model to the SDK-owned exact one-shot
// contract accepted by the native JSON FFI.

import { randomBytes } from 'node:crypto';
import type {
  Filesystem,
  Lxc,
  Network,
  OneShotContainment,
  OneShotRequest,
  OneShotWslc,
  PortMapping as WirePortMapping,
  Process,
  ProcessContainer,
  Seatbelt,
  Ui,
} from '../generated/v1_0_0/wire.js';
import { MxcError } from '../v1/errors.js';
import { SDK_CONTRACT_VERSION } from '../v1/contract-version.js';
import type {
  ContainerConfig,
  NetworkConfig,
  PortMapping,
  ProcessContainerConfig,
  WslcConfig,
} from '../v1/types.js';
import {
  UnsupportedV1NetworkFields,
} from '../v1/types.js';

export interface OneShotRequestOptions {
  workingDirectory?: string;
  env?: { [key: string]: string | undefined };
  inheritDefaultEnv?: boolean;
}

const SUPPORTED_ONE_SHOT_CONTAINMENTS = new Set<string>([
  'process',
  'processcontainer',
  'wslc',
  'bubblewrap',
  'lxc',
  'seatbelt',
  'isolation_session',
]);

const U32_MAX = 0xffff_ffff;
const U16_MAX = 0xffff;

function generateContainerId(): string {
  return randomBytes(16).toString('hex');
}

function malformed(message: string): never {
  throw new MxcError('malformed_request', message);
}

function hasSettings(value: object | undefined): boolean {
  return value !== undefined && Object.keys(value).length > 0;
}

function resolveOneShotContainment(config: ContainerConfig): OneShotContainment {
  const containment = config.containment ?? 'process';
  if (!SUPPORTED_ONE_SHOT_CONTAINMENTS.has(containment)) {
    malformed(`containment '${containment}' is not supported by the stable in-process Node SDK`);
  }
  return containment as OneShotContainment;
}

function validateStableConfig(config: ContainerConfig): void {
  if (config.version !== SDK_CONTRACT_VERSION) {
    malformed(
      `the in-process Node binding accepts only the SDK-owned ` +
      `${SDK_CONTRACT_VERSION} contract`,
    );
  }
  if ('appContainer' in config) {
    malformed("appContainer is not supported by the stable 1.0.0 in-process API; use processContainer");
  }
  if ('macos_sandbox' in config) {
    malformed("macos_sandbox is not supported by the stable 1.0.0 in-process API; use seatbelt");
  }
  if (config.processContainer !== undefined && 'name' in config.processContainer) {
    malformed("processContainer.name is not supported by the stable 1.0.0 in-process API; use containerId");
  }
  if (config.lxc !== undefined && 'containerName' in config.lxc) {
    malformed("lxc.containerName is not supported by the stable 1.0.0 in-process API; use containerId");
  }
  if (config.network !== undefined) {
    for (const field of UnsupportedV1NetworkFields) {
      if (field in config.network) {
        malformed(
          `network.${field} is not supported by any registered exact contract; ` +
          'migrate to network.egress/network.ingress, runtimeConfig.networkProxy, ' +
          'or lifecycle.preservePolicy as appropriate',
        );
      }
    }
  }
}

function assertIntegerRange(
  value: number | undefined,
  path: string,
  min: number,
  max: number,
): void {
  if (value === undefined) return;
  if (!Number.isInteger(value) || value < min || value > max) {
    malformed(`${path} must be an integer between ${min} and ${max}`);
  }
}

function validateNetworkPorts(network: NetworkConfig | undefined): void {
  const egress = network?.egress;
  const rules = [...(egress?.allow ?? []), ...(egress?.deny ?? [])];
  for (const [ruleIndex, rule] of rules.entries()) {
    for (const [portIndex, port] of (rule.ports ?? []).entries()) {
      const path = `network.egress rule ${ruleIndex} port ${portIndex}`;
      assertIntegerRange(port.port, `${path}.port`, 1, U16_MAX);
      assertIntegerRange(port.endPort, `${path}.endPort`, 1, U16_MAX);
      if (port.endPort !== undefined) {
        if (port.port === undefined) malformed(`${path}.endPort requires port`);
        if (port.endPort < port.port) {
          malformed(`${path}.endPort must be greater than or equal to port`);
        }
      }
    }
  }
}

function validateNumerics(config: ContainerConfig): void {
  assertIntegerRange(config.process?.timeout, 'process.timeout', 0, U32_MAX);
  validateNetworkPorts(config.network);
  const wslc = config.wslc;
  assertIntegerRange(wslc?.cpuCount, 'wslc.cpuCount', 0, U32_MAX);
  assertIntegerRange(wslc?.memoryMb, 'wslc.memoryMb', 0, Number.MAX_SAFE_INTEGER);
  for (const [index, mapping] of (wslc?.portMappings ?? []).entries()) {
    assertIntegerRange(mapping.windowsPort, `wslc.portMappings[${index}].windowsPort`, 1, U16_MAX);
    assertIntegerRange(mapping.containerPort, `wslc.portMappings[${index}].containerPort`, 1, U16_MAX);
  }
}

function validateBackendSections(
  config: ContainerConfig,
  containment: OneShotContainment,
): void {
  if (containment !== 'processcontainer' && hasSettings(config.processContainer)) {
    malformed("ProcessContainer-specific settings require containment 'processcontainer'");
  }
  if (containment !== 'seatbelt' && hasSettings(config.seatbelt)) {
    malformed("Seatbelt-specific settings require containment 'seatbelt'");
  }
  if (containment !== 'lxc' && hasSettings(config.lxc)) {
    malformed("LXC-specific settings require containment 'lxc'");
  }
  if (containment !== 'wslc' && hasSettings(config.wslc)) {
    malformed("WSLC-specific settings require containment 'wslc'");
  }
  if (
    containment === 'wslc'
    && config.wslc?.portMappings?.some(
      (mapping) => mapping.protocol !== undefined && mapping.protocol !== 'tcp',
    )
  ) {
    malformed("WSLC port mappings support only protocol 'tcp'");
  }
}

function filesystem(config: ContainerConfig): Filesystem {
  return {
    readwritePaths: [...(config.filesystem?.readwritePaths ?? [])],
    readonlyPaths: [...(config.filesystem?.readonlyPaths ?? [])],
    deniedPaths: [...(config.filesystem?.deniedPaths ?? [])],
  };
}

function lifecycle(config: ContainerConfig): NonNullable<OneShotRequest['lifecycle']> {
  if (config.lifecycle?.destroyOnExit === false) {
    malformed('lifecycle.destroyOnExit=false is not supported by one-shot in-process execution');
  }
  const clearPolicy = config.filesystem?.clearPolicyOnExit;
  const preservePolicy = config.lifecycle?.preservePolicy ?? (
    clearPolicy === undefined ? false : !clearPolicy
  );
  return {
    destroyOnExit: true,
    preservePolicy,
  };
}

function processConfig(
  config: ContainerConfig,
  options: OneShotRequestOptions,
): Process {
  const commandLine = config.process?.commandLine;
  if (!commandLine) {
    malformed(
      'script is required. Set process.commandLine on the config or pass a script to spawnSandbox.',
    );
  }
  const process: Process = {
    commandLine,
    timeout: config.process?.timeout ?? 0,
  };
  const cwd = options.workingDirectory ?? config.process?.cwd;
  if (cwd !== undefined) process.cwd = cwd;
  const env = environment(config, options);
  if (env !== undefined) process.env = env;
  if (inheritDefaultEnv(config, options)) process.inheritDefaultEnv = true;
  return process;
}

function parseEnvironmentEntry(entry: string): string {
  if (typeof entry !== 'string') malformed('process.env entries must be strings');
  const separator = entry.indexOf('=');
  if (separator === -1) malformed(`process.env entry '${entry}' must be NAME=value`);
  validateEnvironmentName(entry.slice(0, separator));
  return entry;
}

function validateEnvironmentName(name: string): void {
  if (name.length === 0 || name.includes('=')) {
    malformed(`invalid environment variable name '${name}'`);
  }
}

function environment(
  config: ContainerConfig,
  options: OneShotRequestOptions,
): string[] | undefined {
  const configEntries = (config.process?.env ?? []).map(parseEnvironmentEntry);
  const optionEntries = Object.entries(options.env ?? {})
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(([key, value]) => {
      validateEnvironmentName(key);
      if (typeof value !== 'string') malformed(`environment.${key} must be a string`);
      return `${key}=${value}`;
    });
  const entries = [...configEntries, ...optionEntries];
  if (config.process?.env === undefined && options.env === undefined) return undefined;
  return entries;
}

function inheritDefaultEnv(
  config: ContainerConfig,
  options: OneShotRequestOptions,
): boolean {
  return options.inheritDefaultEnv ?? config.process?.inheritDefaultEnv === true;
}

function network(config: ContainerConfig): Network | undefined {
  if (config.network?.egress === undefined && config.network?.ingress === undefined) {
    return undefined;
  }
  return {
    ...(config.network.egress === undefined ? {} : { egress: config.network.egress }),
    ...(config.network.ingress === undefined ? {} : { ingress: config.network.ingress }),
  };
}

function ui(config: ContainerConfig): Ui | undefined {
  if (config.ui === undefined) return undefined;
  return {
    disable: config.ui.disable,
    clipboard: config.ui.clipboard,
    injection: config.ui.injection,
  };
}

function processContainer(config: ContainerConfig): ProcessContainer | undefined {
  const source = config.processContainer;
  const directionalNetwork = config.network?.egress !== undefined
    || config.network?.ingress !== undefined;
  const output: ProcessContainer = {
    leastPrivilege: false,
    capabilities: directionalNetwork
      ? (source?.capabilities ?? []).filter(
        (capability) =>
          capability !== 'internetClient' &&
          capability !== 'privateNetworkClientServer',
      )
      : [...(source?.capabilities ?? [])],
  };
  if (source?.learningMode === true) output.learningMode = true;
  if (source?.captureDenials !== undefined) output.captureDenials = { ...source.captureDenials };
  if (source?.filesystem?.enumeratePaths !== undefined) {
    output.filesystem = {
      enumeratePaths: [...source.filesystem.enumeratePaths],
    };
  }
  if (source?.network?.allowedProxyPeer !== undefined) {
    output.network = {
      allowedProxyPeer: source.network.allowedProxyPeer,
    };
  }
  if (
    source?.ui !== undefined &&
    (
      source.ui.isolation !== 'container' ||
      source.ui.desktopSystemControl !== false ||
      source.ui.systemSettings !== 'none' ||
      source.ui.ime !== false
    )
  ) {
    output.ui = { ...source.ui };
  }
  return output;
}

function lxc(config: ContainerConfig): Lxc {
  return {
    distribution: config.lxc?.distribution ?? 'alpine',
    release: config.lxc?.release ?? '3.23',
  };
}

function seatbelt(config: ContainerConfig): Seatbelt | undefined {
  if (config.seatbelt === undefined) return undefined;
  return { ...config.seatbelt };
}

function wslcPortMapping(mapping: PortMapping): WirePortMapping {
  return {
    windowsPort: mapping.windowsPort,
    containerPort: mapping.containerPort,
    protocol: 'tcp',
  };
}

function wslc(config: ContainerConfig): OneShotWslc {
  const source: WslcConfig = config.wslc ?? {};
  const output: OneShotWslc = {
    image: source.image ?? 'alpine:latest',
    gpu: source.gpu ?? false,
  };
  if (source.cpuCount !== undefined) output.cpuCount = source.cpuCount;
  if (source.memoryMb !== undefined) output.memoryMb = source.memoryMb;
  if (source.imageTarPath !== undefined) output.imageTarPath = source.imageTarPath;
  if (source.storagePath !== undefined) output.storagePath = source.storagePath;
  if (source.targetOs !== undefined) output.targetOs = source.targetOs;
  if (source.portMappings !== undefined && source.portMappings.length > 0) {
    output.portMappings = source.portMappings.map(wslcPortMapping);
  }
  return output;
}

export function prepareOneShotRequest(
  config: ContainerConfig,
  options: OneShotRequestOptions = {},
): OneShotRequest {
  validateStableConfig(config);
  validateNumerics(config);
  const containment = resolveOneShotContainment(config);
  validateBackendSections(config, containment);

  const request: OneShotRequest = {
    version: SDK_CONTRACT_VERSION,
    containerId: config.containerId ?? generateContainerId(),
    containment,
    lifecycle: lifecycle(config),
    process: processConfig(config, options),
    filesystem: filesystem(config),
  };

  const net = network(config);
  if (net !== undefined) request.network = net;
  if (config.runtimeConfig !== undefined) request.runtimeConfig = { ...config.runtimeConfig };
  if (config.telemetry !== undefined) request.telemetry = { ...config.telemetry };
  const uiConfig = ui(config);
  if (uiConfig !== undefined) request.ui = uiConfig;

  if (containment === 'processcontainer') request.processContainer = processContainer(config);
  if (containment === 'lxc') request.lxc = lxc(config);
  if (containment === 'seatbelt') {
    const seatbeltConfig = seatbelt(config);
    if (seatbeltConfig !== undefined) request.seatbelt = seatbeltConfig;
  }
  if (containment === 'wslc') request.wslc = wslc(config);

  return request;
}
