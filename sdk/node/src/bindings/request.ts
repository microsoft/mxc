// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Adapts the public ContainerConfig model to the private request accepted by
// the native Node binding.

import type {
  ContainerConfig,
  NetworkConfig,
  PortMapping,
  ProcessContainerConfig,
  WslcConfig,
} from '../types.js';
import { LegacyContainmentAliases } from '../types.js';

export interface RequestSpecOptions {
  workingDirectory?: string;
  env?: { [key: string]: string | undefined };
  inheritDefaultEnv?: boolean;
  experimental?: boolean;
}

/**
 * Policy projection accepted by the current `mxc_ffi::RequestSpec`.
 * This private shape is derived from the public ContainerConfig at the native
 * transport boundary.
 */
export interface RequestPolicy {
  version: string;
  filesystem?: ContainerConfig['filesystem'];
  network?: {
    allowOutbound?: boolean;
    allowLocalNetwork?: boolean;
    allowedHosts?: string[];
    blockedHosts?: string[];
    proxy?: NetworkConfig['proxy'];
    egress?: NetworkConfig['egress'];
    ingress?: NetworkConfig['ingress'];
    runtimeConfig?: ContainerConfig['runtimeConfig'];
  };
  ui?: {
    allowWindows: boolean;
    clipboard: NonNullable<ContainerConfig['ui']>['clipboard'];
    allowInputInjection: boolean;
  };
  timeoutMs?: number;
  telemetry?: ContainerConfig['telemetry'];
};

/**
 * Containment variants currently reachable through the native one-shot API.
 * This mirrors the tagged JSON contract consumed by `mxc_ffi::RequestSpec`.
 */
export type RequestContainment =
  | { type: 'process' }
  | ({ type: 'processContainer' } & Omit<ProcessContainerConfig, 'name'>)
  | ({
      type: 'wslc';
    } & Omit<WslcConfig, 'targetOs' | 'portMappings'> & {
      portMappings?: Array<Pick<PortMapping, 'windowsPort' | 'containerPort'>>;
    });

export interface RequestSpec {
  policy: RequestPolicy;
  command: string;
  containment: RequestContainment;
  containerName?: string;
  workingDirectory?: string;
  environment?: Record<string, string>;
  inheritDefaultEnv: boolean;
  experimental: boolean;
}

function hasExplicitProcessContainerSettings(
  config: ProcessContainerConfig,
): boolean {
  const ui = config.ui;
  const hasCustomUi = ui !== undefined && (
    ui.isolation !== 'container'
    || ui.desktopSystemControl !== false
    || ui.systemSettings !== 'none'
    || ui.ime !== false
  );
  const hasCustomCapabilities = config.capabilities?.some(
    (capability) => capability !== 'internetClient'
      && capability !== 'privateNetworkClientServer',
  ) ?? false;
  return config.name !== undefined
    || config.leastPrivilege === true
    || config.learningMode === true
    || config.captureDenials !== undefined
    || config.network?.allowedProxyPeer !== undefined
    || hasCustomUi
    || hasCustomCapabilities;
}

function resolveContainmentName(
  config: ContainerConfig,
  processContainer = config.processContainer ?? config.appContainer,
): string {
  let rawContainment = config.containment;
  if (rawContainment === undefined) {
    rawContainment = 'process';
    if (processContainer !== undefined) {
      rawContainment = 'processcontainer';
    }
  }
  return LegacyContainmentAliases[rawContainment] ?? rawContainment;
}

function hasCustomSeatbeltSettings(config: ContainerConfig): boolean {
  return config.seatbelt !== undefined
    && Object.keys(config.seatbelt).length > 0;
}

export function bindingRequestUnsupportedReason(config: ContainerConfig): string | null {
  if (config.network?.proxy !== undefined && 'builtinTestServer' in config.network.proxy) {
    return 'network.proxy.builtinTestServer is not supported by the in-process Node SDK; use localhost or url';
  }
  const containment = resolveContainmentName(config);
  if (
    containment !== 'process'
    && containment !== 'processcontainer'
    && containment !== 'wslc'
    && containment !== 'bubblewrap'
    && containment !== 'seatbelt'
  ) {
    return `containment '${containment}' is not supported by the in-process Node SDK; use the portable 'process' intent`;
  }
  if (config.processContainer !== undefined && config.appContainer !== undefined) {
    return 'processContainer and its legacy appContainer alias cannot both be specified';
  }
  if (config.lifecycle?.destroyOnExit === false) {
    return 'lifecycle.destroyOnExit=false is not supported by one-shot in-process execution';
  }
  if (
    containment === 'process'
    && config.processContainer !== undefined
    && hasExplicitProcessContainerSettings(config.processContainer)
  ) {
    return "ProcessContainer-specific settings require containment 'processcontainer'";
  }
  // The native RequestSpec has no Seatbelt payload and rejects unknown fields.
  // Refuse custom settings here rather than silently running a weaker policy.
  if (hasCustomSeatbeltSettings(config)) {
    return 'custom seatbelt settings cannot be represented by the native request contract';
  }
  return null;
}

function projectNetwork(config: ContainerConfig): RequestPolicy['network'] {
  if (config.network === undefined && config.runtimeConfig === undefined) {
    return undefined;
  }

  let allowOutbound: boolean | undefined;
  if (config.network?.defaultPolicy !== undefined) {
    allowOutbound = config.network.defaultPolicy === 'allow';
  }

  return {
    allowOutbound,
    allowLocalNetwork: config.network?.allowLocalNetwork,
    allowedHosts: config.network?.allowedHosts,
    blockedHosts: config.network?.blockedHosts,
    proxy: config.network?.proxy,
    egress: config.network?.egress,
    ingress: config.network?.ingress,
    runtimeConfig: config.runtimeConfig,
  };
}

function resolveClearPolicyOnExit(config: ContainerConfig): boolean | undefined {
  if (config.filesystem?.clearPolicyOnExit !== undefined) {
    return config.filesystem.clearPolicyOnExit;
  }
  if (config.network?.removeRulesOnExit !== undefined) {
    return config.network.removeRulesOnExit;
  }
  if (config.lifecycle?.preservePolicy !== undefined) {
    return !config.lifecycle.preservePolicy;
  }
  return undefined;
}

function projectFilesystem(config: ContainerConfig): RequestPolicy['filesystem'] {
  const clearPolicyOnExit = resolveClearPolicyOnExit(config);
  if (config.filesystem === undefined && clearPolicyOnExit === undefined) {
    return undefined;
  }
  return {
    ...(config.filesystem ?? {}),
    clearPolicyOnExit,
  };
}

function projectUi(config: ContainerConfig): RequestPolicy['ui'] {
  if (config.ui === undefined) {
    return undefined;
  }
  return {
    allowWindows: config.ui.disable === false,
    clipboard: config.ui.clipboard,
    allowInputInjection: config.ui.injection,
  };
}

function parseEnvironmentEntry(entry: string): [string, string] {
  const separator = entry.indexOf('=');
  if (separator === -1) {
    return [entry, ''];
  }
  return [entry.slice(0, separator), entry.slice(separator + 1)];
}

function projectEnvironment(
  config: ContainerConfig,
  options: RequestSpecOptions,
  inheritDefaultEnv: boolean,
): Record<string, string> | undefined {
  const hasConfigEnvironment = config.process?.env !== undefined;
  const hasOptionEnvironment = options.env !== undefined;
  if (!hasConfigEnvironment && !hasOptionEnvironment && !inheritDefaultEnv) {
    return undefined;
  }

  const configEntries = (config.process?.env ?? []).map(parseEnvironmentEntry);
  const optionEntries = Object.entries(options.env ?? {})
    .filter((entry): entry is [string, string] => entry[1] !== undefined);
  return Object.fromEntries([...configEntries, ...optionEntries]);
}

function resolveInheritDefaultEnv(
  config: ContainerConfig,
  options: RequestSpecOptions,
): boolean {
  if (options.inheritDefaultEnv !== undefined) {
    return options.inheritDefaultEnv;
  }
  return config.process?.inheritDefaultEnv === true;
}

function projectContainment(
  config: ContainerConfig,
  processContainer: ProcessContainerConfig | undefined,
): RequestContainment {
  const containmentName = resolveContainmentName(config, processContainer);
  if (containmentName === 'wslc') {
    const {
      targetOs: _targetOs,
      portMappings,
      ...wslc
    } = config.experimental?.wslc ?? {};
    return {
      type: 'wslc',
      ...wslc,
      portMappings: portMappings?.map(({ windowsPort, containerPort }) => ({
        windowsPort,
        containerPort,
      })),
    };
  }
  if (containmentName === 'processcontainer') {
    const { name: _legacyName, ...settings } = processContainer ?? {};
    return { type: 'processContainer', ...settings };
  }
  return { type: 'process' };
}

/**
 * Converts the public ContainerConfig into the private, co-versioned request
 * consumed by the native binding.
 * JSON serialization belongs in the Koffi binding, mirroring the .NET SDK.
 */
export function prepareRequestSpec(
  config: ContainerConfig,
  options: RequestSpecOptions = {},
): RequestSpec {
  const unsupported = bindingRequestUnsupportedReason(config);
  if (unsupported !== null) {
    throw new Error(unsupported);
  }

  if (!config.process?.commandLine) {
    throw new Error(
      'script is required. Set process.commandLine on the config or pass a script to a spawn function.',
    );
  }

  const policy: RequestPolicy = {
    version: config.version,
    filesystem: projectFilesystem(config),
    network: projectNetwork(config),
    ui: projectUi(config),
    timeoutMs: config.process.timeout,
    telemetry: config.telemetry,
  };

  const processContainer = config.processContainer ?? config.appContainer;
  const inheritDefaultEnv = resolveInheritDefaultEnv(config, options);

  return {
    policy,
    command: config.process.commandLine,
    containment: projectContainment(config, processContainer),
    containerName: config.containerId,
    workingDirectory: options.workingDirectory ?? config.process.cwd,
    environment: projectEnvironment(config, options, inheritDefaultEnv),
    inheritDefaultEnv,
    experimental: options.experimental ?? false,
  };
}
