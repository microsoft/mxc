// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Adapts the public ContainerConfig model to the private request accepted by
// the native Node binding.

import type {
  ContainerConfig,
  LxcConfig,
  NetworkConfig,
  PortMapping,
  ProcessContainerConfig,
  SandboxPolicy,
  SeatbeltConfig,
  WslcConfig,
} from '../types.js';
import { LegacyContainmentAliases } from '../types.js';
import { MxcError } from '../errors.js';

export interface RequestSpecOptions {
  workingDirectory?: string;
  env?: { [key: string]: string | undefined };
  inheritDefaultEnv?: boolean;
  experimental?: boolean;
}

/**
 * Node's private policy projection inside the shared `mxc_ffi::RequestSpec`.
 * This is transport data derived from the legacy public `ContainerConfig`,
 * not a second public sandbox-policy API.
 */
export interface RequestSpecPolicy {
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
 * Containment variants represented by the shared native request contract.
 * Runtime availability is enforced by `mxc-sdk`; LXC is currently modeled
 * here for parity but rejected by the in-process run API.
 */
export type RequestContainment =
  | { type: 'process' }
  | ({ type: 'processContainer' } & Omit<ProcessContainerConfig, 'name'>)
  | ({ type: 'seatbelt' } & SeatbeltConfig)
  | ({
      type: 'lxc';
    } & Pick<LxcConfig, 'distribution' | 'release'>)
  | { type: 'bubblewrap' }
  | { type: 'isolationSession' }
  | ({
      type: 'wslc';
    } & Omit<WslcConfig, 'targetOs' | 'portMappings'> & {
      portMappings?: Array<Pick<PortMapping, 'windowsPort' | 'containerPort'>>;
    });

export interface RequestSpec {
  policy: RequestSpecPolicy;
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
  // Legacy Node policy construction emits a default ProcessContainer block
  // even for abstract `process` intent. Only non-default settings make that
  // block an explicit backend request that must not be silently discarded.
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
    || Boolean(config.filesystem?.enumeratePaths?.length)
    || config.network?.allowedProxyPeer !== undefined
    || hasCustomUi
    || hasCustomCapabilities;
}

function resolveNodeContainment(
  config: ContainerConfig,
  processContainer = config.processContainer ?? config.appContainer,
): string {
  // The native engine resolves abstract `process` to the host backend. This
  // adapter only preserves Node compatibility aliases and the legacy rule that
  // a direct ProcessContainer block selects ProcessContainer.
  let rawContainment = config.containment;
  if (rawContainment === undefined) {
    rawContainment = 'process';
    if (processContainer !== undefined) {
      rawContainment = 'processcontainer';
    }
  }
  return LegacyContainmentAliases[rawContainment] ?? rawContainment;
}

function hasSettings(value: object | undefined): boolean {
  return value !== undefined && Object.keys(value).length > 0;
}

const SUPPORTED_REQUEST_CONTAINMENTS = new Set<string>([
  'process',
  'processcontainer',
  'wslc',
  'bubblewrap',
  'lxc',
  'seatbelt',
  'isolation_session',
]);

export function validateBindingPolicy(policy: SandboxPolicy): void {
  const enforcementMode = (
    policy.network as Record<string, unknown> | undefined
  )?.enforcementMode;
  if (enforcementMode !== undefined) {
    throw new MxcError(
      'malformed_request',
      'spawnSandboxAsync does not support network.enforcementMode',
    );
  }
}

export function bindingRequestUnsupportedReason(config: ContainerConfig): string | null {
  if (config.network?.proxy !== undefined && 'builtinTestServer' in config.network.proxy) {
    return 'network.proxy.builtinTestServer is not supported by the in-process Node SDK; use localhost or url';
  }
  if (config.network?.enforcementMode !== undefined) {
    return 'network.enforcementMode is not supported by the in-process Node SDK';
  }
  const processContainer = config.processContainer ?? config.appContainer;
  const containment = resolveNodeContainment(config, processContainer);
  if (!SUPPORTED_REQUEST_CONTAINMENTS.has(containment)) {
    return `containment '${containment}' is not supported by the in-process Node SDK`;
  }
  if (config.processContainer !== undefined && config.appContainer !== undefined) {
    return 'processContainer and its legacy appContainer alias cannot both be specified';
  }
  if (config.lifecycle?.destroyOnExit === false) {
    return 'lifecycle.destroyOnExit=false is not supported by one-shot in-process execution';
  }
  if (
    containment !== 'processcontainer'
    && processContainer !== undefined
    && hasExplicitProcessContainerSettings(processContainer)
  ) {
    return "ProcessContainer-specific settings require containment 'processcontainer'";
  }
  if (containment !== 'seatbelt' && hasSettings(config.seatbelt)) {
    return "Seatbelt-specific settings require containment 'seatbelt'";
  }
  if (containment !== 'lxc' && hasSettings(config.lxc)) {
    return "LXC-specific settings require containment 'lxc'";
  }
  if (containment !== 'wslc' && hasSettings(config.wslc)) {
    return "WSLC-specific settings require containment 'wslc'";
  }
  if (containment === 'lxc' && config.lxc?.destroyOnExit === false) {
    return 'lxc.destroyOnExit=false is not supported by one-shot in-process execution';
  }
  if (
    containment === 'wslc'
    && config.wslc?.portMappings?.some(
      mapping => mapping.protocol !== undefined && mapping.protocol !== 'tcp',
    )
  ) {
    return "WSLC port mappings support only protocol 'tcp'";
  }
  return null;
}

function projectNetwork(config: ContainerConfig): RequestSpecPolicy['network'] {
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

function projectFilesystem(config: ContainerConfig): RequestSpecPolicy['filesystem'] {
  const clearPolicyOnExit = resolveClearPolicyOnExit(config);
  if (config.filesystem === undefined && clearPolicyOnExit === undefined) {
    return undefined;
  }
  return {
    ...(config.filesystem ?? {}),
    clearPolicyOnExit,
  };
}

function projectUi(config: ContainerConfig): RequestSpecPolicy['ui'] {
  if (config.ui === undefined) {
    return undefined;
  }
  return {
    allowWindows: config.ui.disable === false,
    clipboard: config.ui.clipboard ?? 'none',
    allowInputInjection: config.ui.injection ?? false,
  };
}

function parseEnvironmentEntry(entry: string): [string, string] {
  // ContainerConfig predates RequestSpec and stores environment entries as
  // `NAME=value` strings. Normalize that Node-specific legacy shape into the
  // shared RequestSpec map at this private binding boundary.
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
  containmentName: string,
): RequestContainment {
  if (containmentName === 'wslc') {
    const {
      targetOs: _targetOs,
      portMappings,
      ...wslc
    } = config.wslc ?? {};
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
  if (containmentName === 'seatbelt') {
    return { type: 'seatbelt', ...(config.seatbelt ?? {}) };
  }
  if (containmentName === 'lxc') {
    return {
      type: 'lxc',
      distribution: config.lxc?.distribution,
      release: config.lxc?.release,
    };
  }
  if (containmentName === 'bubblewrap') {
    return { type: 'bubblewrap' };
  }
  if (containmentName === 'isolation_session') {
    return { type: 'isolationSession' };
  }
  return { type: 'process' };
}

function resolveContainerName(
  config: ContainerConfig,
  processContainer: ProcessContainerConfig | undefined,
  containmentName: string,
): string | undefined {
  if (config.containerId !== undefined) {
    return config.containerId;
  }
  if (containmentName === 'processcontainer') {
    return processContainer?.name;
  }
  if (containmentName === 'lxc') {
    return config.lxc?.containerName;
  }
  return undefined;
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
    throw new MxcError('malformed_request', unsupported);
  }

  if (!config.process?.commandLine) {
    throw new MxcError(
      'malformed_request',
      'script is required. Set process.commandLine on the config or pass a script to spawnSandbox.',
    );
  }

  const policy: RequestSpecPolicy = {
    version: config.version,
    filesystem: projectFilesystem(config),
    network: projectNetwork(config),
    ui: projectUi(config),
    timeoutMs: config.process.timeout,
    telemetry: config.telemetry,
  };

  const processContainer = config.processContainer ?? config.appContainer;
  const containmentName = resolveNodeContainment(config, processContainer);
  const inheritDefaultEnv = resolveInheritDefaultEnv(config, options);

  return {
    policy,
    command: config.process.commandLine,
    containment: projectContainment(config, processContainer, containmentName),
    containerName: resolveContainerName(config, processContainer, containmentName),
    workingDirectory: options.workingDirectory ?? config.process.cwd,
    environment: projectEnvironment(config, options, inheritDefaultEnv),
    inheritDefaultEnv,
    experimental: options.experimental ?? false,
  };
}
