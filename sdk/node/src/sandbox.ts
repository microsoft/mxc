// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import { randomBytes } from 'crypto';
import { parse as semverParse } from 'semver';
import {
    SandboxPolicy,
    ContainerConfig,
    ContainmentType,
    ContainmentBackend,
} from './types.js';
import { applyLinuxNetworkPolicy, diagLogVersion, removedExecutorOptionName } from './helper.js';
import { diagLog } from './diagnostic.js';
import { MxcError } from './errors.js';
import { prepareRequestSpec } from './bindings/request.js';
import { runBindingRequestAsync } from './bindings/run-worker.js';
import { spawnBindingSandboxProcess } from './bindings/streaming.js';
import type { MxcSandboxProcess } from './sandbox-process.js';

const MIN_VERSION = '0.6.0-alpha';
const SUPPORTED_VERSION = '0.9.0-alpha';
const REGISTERED_VERSION_VALUES = [
    '0.6.0-alpha',
    '0.7.0-alpha',
    '0.8.0-alpha',
    '0.9.0-alpha',
];
const REGISTERED_VERSIONS = new Set(REGISTERED_VERSION_VALUES);
const REGISTERED_VERSION_ORDER = new Map(
    REGISTERED_VERSION_VALUES.map((version, index) => [version, index]),
);
const LEGACY_NETWORK_FIELDS = [
    'allowOutbound',
    'defaultPolicy',
    'enforcementMode',
    'allowLocalNetwork',
    'allowedHosts',
    'blockedHosts',
    'proxy',
] as const;

/**
 * Generates a random 8-character alphanumeric string for the app container name.
 */
function generateRandomContainerName(): string {
    return randomBytes(4).toString("hex");
}

function validatePolicyVersion(version: string): void {
    if (!version) {
        throw new Error('Policy version is required');
    }

    const parsed = semverParse(version);
    if (!parsed) {
        throw new Error(
            `Invalid policy version '${version}': must be valid semver` +
            ` (e.g., '0.6.0' or '0.6.0-alpha')`
        );
    }

    const supported = semverParse(SUPPORTED_VERSION);
    const minimum = semverParse(MIN_VERSION);
    if (
        parsed.major < minimum!.major ||
        (parsed.major === minimum!.major &&
            parsed.minor < minimum!.minor)
    ) {
        throw new Error(
            `Policy version '${version}' is older than supported` +
            ` (min: ${minimum!.major}.${minimum!.minor}.x).` +
            ` Update your config.`
        );
    }
    if (
        parsed.major > supported!.major ||
        (parsed.major === supported!.major &&
            parsed.minor > supported!.minor)
    ) {
        throw new Error(
            `Policy version '${version}' is newer than supported` +
            ` (max: ${supported!.major}.${supported!.minor}.x).` +
            ` Upgrade the SDK.`
        );
    }
    if (!REGISTERED_VERSIONS.has(version)) {
        throw new Error(
            `Policy version '${version}' is not a registered schema contract. ` +
            `Use one of: ${REGISTERED_VERSION_VALUES.join(', ')}.`
        );
    }
}

function validateContainmentVersion(
    version: string,
    containment: ContainmentType | ContainmentBackend,
    platform: NodeJS.Platform,
): void {
    const effectiveContainment =
        containment === 'process' && platform === 'darwin' ? 'seatbelt' : containment;
    const minimumVersion =
        effectiveContainment === 'seatbelt'
            ? '0.7.0-alpha'
            : effectiveContainment === 'vm' ||
                effectiveContainment === 'microvm' ||
                effectiveContainment === 'windows_sandbox' ||
                effectiveContainment === 'wslc' ||
                effectiveContainment === 'hyperlight' ||
                effectiveContainment === 'isolation_session'
              ? '0.9.0-alpha'
              : '0.6.0-alpha';

    const versionOrder = REGISTERED_VERSION_ORDER.get(version);
    const minimumOrder = REGISTERED_VERSION_ORDER.get(minimumVersion);
    if (versionOrder === undefined || minimumOrder === undefined || versionOrder < minimumOrder) {
        throw new Error(
            `Schema ${version} does not support containment '${containment}'; ` +
            `use schema ${minimumVersion} or later.`
        );
    }
}

function validateTelemetryVersion(policy: SandboxPolicy): void {
    if (policy.telemetry === undefined) {
        return;
    }

    const minimumVersion = '0.9.0-alpha';
    const versionOrder = REGISTERED_VERSION_ORDER.get(policy.version);
    const minimumOrder = REGISTERED_VERSION_ORDER.get(minimumVersion);
    if (versionOrder === undefined || minimumOrder === undefined || versionOrder < minimumOrder) {
        throw new Error(
            `Schema ${policy.version} does not support telemetry; ` +
            `use schema ${minimumVersion} or later.`
        );
    }
}

function hasLegacyNetworkFields(network: NonNullable<SandboxPolicy['network']>): boolean {
    return LEGACY_NETWORK_FIELDS.some(
        field => (network as Record<string, unknown>)[field] !== undefined,
    );
}

function hasDirectionalNetworkFields(network: NonNullable<SandboxPolicy['network']>): boolean {
    return network.egress !== undefined || network.ingress !== undefined;
}

function usesDirectionalNetwork(policy: SandboxPolicy): boolean {
    const network = policy.network;
    return (network !== undefined && hasDirectionalNetworkFields(network)) ||
        policy.runtimeConfig?.networkProxy !== undefined ||
        policy.processContainer?.network?.allowedProxyPeer !== undefined;
}

function selectDirectionalNetwork(policy: SandboxPolicy): boolean {
    const network = policy.network;
    if (policy.version === '0.9.0-alpha' && network !== undefined) {
        for (const field of LEGACY_NETWORK_FIELDS) {
            if (network !== null && (network as Record<string, unknown>)[field] !== undefined) {
                throw new Error(
                    `Schema 0.9.0-alpha no longer supports network.${field}. ` +
                    'Author network.egress/network.ingress and runtimeConfig.networkProxy explicitly, ' +
                    'or retain schema 0.8.0-alpha for legacy networking. Hostnames are not converted to CIDRs.',
                );
            }
        }
        if (network === null || typeof network !== 'object' || Array.isArray(network)) {
            throw new Error('network must be an object when supplied.');
        }
    }
    const hasLegacy = network !== undefined && hasLegacyNetworkFields(network);
    const hasDirectional = usesDirectionalNetwork(policy);

    if (hasLegacy && hasDirectional) {
        throw new Error(
            'Network configuration cannot mix allowOutbound, allowLocalNetwork, allowedHosts, ' +
            'blockedHosts, or proxy with egress, ingress, runtimeConfig, or processContainer.network.',
        );
    }

    const parsed = semverParse(policy.version)!;
    const supportsDirectional = parsed.major > 0 || parsed.minor >= 8;
    if (hasDirectional && !supportsDirectional) {
        throw new Error(
            `Schema ${policy.version} does not support network.egress, network.ingress, ` +
            'runtimeConfig, or processContainer.network; use schema 0.8.0-alpha or later.',
        );
    }

    return hasDirectional || (supportsDirectional && !hasLegacy);
}


/**
 * Builds the WSLC (WSL Container) portion of a ContainerConfig.
 * WSLC runs Linux containers on Windows via the WSL Container SDK.
 * Config goes under `experimental.wslc` since WSLC is experimental.
 */
function buildWslcContainerConfig(
    config: ContainerConfig,
    policy: SandboxPolicy,
    containerId: string,
): ContainerConfig {
    config.containment = 'wslc';
    config.containerId = containerId;

    config.experimental = {
        wslc: {
            image: 'alpine:latest',
        },
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
    policy: SandboxPolicy,
): ContainerConfig {
    const requested = policy.processContainer;
    const capabilities: string[] = [];
    const allowsInternet =
        policy.network?.allowOutbound ||
        policy.network?.egress?.default === 'allow' ||
        Boolean(policy.network?.egress?.allow?.length);
    if (allowsInternet) {
        capabilities.push("internetClient");
    }
    if (policy.network?.allowLocalNetwork || policy.network?.ingress?.default === 'allow') {
        capabilities.push("privateNetworkClientServer");
    }

    config.processContainer = {
        leastPrivilege: requested?.leastPrivilege ?? false,
        learningMode: requested?.learningMode,
        capabilities: requested?.capabilities ?? capabilities,
        captureDenials: requested?.captureDenials,
        ui: requested?.ui ?? {
            isolation: "container",
            desktopSystemControl: false,
            systemSettings: "none",
            ime: false,
        },
        network: requested?.network?.allowedProxyPeer !== undefined
            ? { allowedProxyPeer: requested.network.allowedProxyPeer }
            : undefined,
    };

    // Network enforcement: use firewall only when host filtering is needed (requires admin)
    if (config.network && policy.version !== '0.9.0-alpha' && !usesDirectionalNetwork(policy)) {
        if (config.network.allowedHosts?.length || config.network.blockedHosts?.length) {
            config.network.enforcementMode = 'both';
        } else {
            config.network.enforcementMode = 'capabilities';
        }
    }

    return config;
}

/**
 * Builds the MicroVM (NanVix) portion of a ContainerConfig.
 * MicroVM is Windows-only and supports isolated or unrestricted networking.
 */
function buildMicroVmConfig(
    config: ContainerConfig,
    policy: SandboxPolicy,
): ContainerConfig {
    if (os.platform() !== 'win32') {
        throw new Error('The microvm backend is only supported on Windows (requires WHP/Hyper-V).');
    }
    if (policy.network && hasLegacyNetworkFields(policy.network)) {
        throw new Error(
            'The microvm backend supports only directional network.egress/network.ingress configuration.'
        );
    }
    if (policy.runtimeConfig?.networkProxy !== undefined ||
        policy.processContainer?.network?.allowedProxyPeer !== undefined) {
        throw new Error('The microvm backend does not support network proxy configuration.');
    }
    if (policy.network?.egress?.allow?.length || policy.network?.egress?.deny?.length) {
        throw new Error(
            'The microvm backend does not support directional network rules. ' +
            'Use fully isolated or explicitly unrestricted networking without rules.'
        );
    }
    if (policy.network !== undefined) {
        const egressDefault = policy.network.egress?.default ?? 'deny';
        const ingressDefault = policy.network.ingress?.default ?? 'deny';
        const hostLoopback = policy.network.ingress?.hostLoopback ?? 'deny';
        if (egressDefault !== ingressDefault || ingressDefault !== hostLoopback) {
            throw new Error(
                'The microvm backend requires network.egress.default, network.ingress.default, ' +
                'and network.ingress.hostLoopback to be all deny or all allow.'
            );
        }
        config.network = {
            egress: policy.network.egress,
            ingress: policy.network.ingress,
        };
    }
    if (policy.filesystem?.readwritePaths?.length ||
        policy.filesystem?.readonlyPaths?.length ||
        policy.filesystem?.deniedPaths?.length) {
        config.filesystem = {
            readwritePaths: policy.filesystem?.readwritePaths,
            readonlyPaths: policy.filesystem?.readonlyPaths,
            deniedPaths: policy.filesystem?.deniedPaths,
        };
    }
    config.containment = 'microvm';
    return config;
}

/**
 * Creates a ContainerConfig from a SandboxPolicy and optional containment type.
 *
 * This is the primary API for translating user-facing security intent (SandboxPolicy)
 * into a backend-specific configuration (ContainerConfig). The returned config
 * can be modified before serializing or comparing the native wire shape.
 *
 * @param policy - The sandbox policy expressing security intent
 * @param containment - Containment backend type (default: "process")
 * @param containerName - Optional container name; auto-generated if omitted
 * @returns A fully populated ContainerConfig ready for modification or serialization
 *
 * @example
 * ```typescript
 * const config = createConfigFromPolicy(
 *   { version: '0.8.0-alpha', network: { allowOutbound: true } },
 *   'wslc',
 * );
 * config.process!.commandLine = 'python app.py';
 * ```
 */
export function createConfigFromPolicy(
    policy: SandboxPolicy,
    containment: ContainmentType | ContainmentBackend = "process",
    containerName?: string,
): ContainerConfig {
    diagLogVersion();
    validatePolicyVersion(policy.version);
    const platform = os.platform();
    validateContainmentVersion(policy.version, containment, platform);
    validateTelemetryVersion(policy);
    const directionalNetwork = selectDirectionalNetwork(policy);

    const containerId = containerName ?? generateRandomContainerName();

    const clearPolicy = policy.filesystem?.clearPolicyOnExit ?? true;
    const config: ContainerConfig = {
        version: policy.version,
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

    // Microvm: delegate to dedicated builder
    if (containment === 'microvm') {
        diagLog(`createConfigFromPolicy: containment=microvm, id=${containerId}`);
        return buildMicroVmConfig(config, policy);
    }

    config.filesystem = {
        readwritePaths: [...(policy.filesystem?.readwritePaths ?? [])],
        readonlyPaths: [...(policy.filesystem?.readonlyPaths ?? [])],
        deniedPaths: [...(policy.filesystem?.deniedPaths ?? [])],
    };

    // Presence matters for backends that cannot enforce UI policy.
    if (policy.ui !== undefined) {
        config.ui = {
            disable: !(policy.ui.allowWindows ?? false),
            clipboard: policy.ui.clipboard ?? "none",
            injection: policy.ui.allowInputInjection ?? false,
        };
    }

    if (directionalNetwork) {
        if ((policy.version === '0.9.0-alpha' && policy.network !== undefined) ||
            policy.network?.egress !== undefined || policy.network?.ingress !== undefined) {
            config.network = {
                egress: policy.network?.egress,
                ingress: policy.network?.ingress,
            };
        }
        if (policy.runtimeConfig?.networkProxy !== undefined) {
            config.runtimeConfig = {
                networkProxy: policy.runtimeConfig.networkProxy,
            };
        }
        if (policy.processContainer?.network?.allowedProxyPeer !== undefined) {
            config.processContainer = {
                network: {
                    allowedProxyPeer: policy.processContainer.network.allowedProxyPeer,
                },
            };
        }
        // Legacy network mapping (cross-platform) — default-deny unless explicitly allowed.
    } else if (policy.network) {
        // Linux: only Bubblewrap supports network.proxy (cooperative env-var
        // proxy, no privilege required). LXC and explicit non-bubblewrap
        // containments do not. Abstract `'process'` on Linux resolves to
        // Bubblewrap server-side so the proxy field is permitted there too.
        if (policy.network.proxy && platform === 'linux') {
            const linuxProxySupported =
                containment === 'bubblewrap' || containment === 'process';
            if (!linuxProxySupported) {
                throw new Error(
                    `Proxy configuration is not supported on Linux containment='${containment}'. ` +
                    `Use containment 'bubblewrap' (or the abstract 'process') for proxy-based host filtering.`,
                );
            }
        }
        // Unix backends accept host lists without allowOutbound. Bubblewrap and
        // LXC enforce them; WSLC does not (per-host filtering is non-functional —
        // no in-kernel iptables + no CAP_NET_ADMIN — and is rejected at parse
        // time); Seatbelt accepts them for SDK compatibility and leaves its
        // limitations to native validation.
        const acceptsHostRulesWithoutOutbound =
            containment === 'wslc' ||
            containment === 'seatbelt' ||
            containment === 'bubblewrap' ||
            containment === 'lxc' ||
            (containment === 'process' && platform === 'linux') ||
            (containment === 'process' && platform === 'darwin');
        if (!acceptsHostRulesWithoutOutbound) {
            if ((policy.network.allowedHosts?.length || policy.network.blockedHosts?.length) && !policy.network.allowOutbound) {
                throw new Error('allowedHosts/blockedHosts require allowOutbound to be true');
            }
        }

        config.network = {
            defaultPolicy: policy.network.allowOutbound ? 'allow' : 'block',
            allowLocalNetwork: policy.network.allowLocalNetwork,
            allowedHosts: policy.network.allowedHosts,
            blockedHosts: policy.network.blockedHosts,
            proxy: policy.network.proxy,
        };
    } else {
        config.network = {
            defaultPolicy: 'block',
        };
    }

    // Backend-specific config based on containment type
    if (containment === 'wslc') {
        return buildWslcContainerConfig(config, policy, containerId);
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

    if (containment === 'processcontainer') {
        config.containment = 'processcontainer';
        return buildProcessBaseContainerConfig(config, policy);
    }

    if (containment === 'process') {
        config.containment = 'process';
        if (platform === 'linux') {
            // Abstract `'process'` on Linux is resolved to Bubblewrap by the
            // native binary (see `wxc_common::config_parser`). The wire-format
            // payload intentionally omits any backend-specific block so the
            // config reflects the abstract intent. Callers who explicitly want
            // LXC must pass `containment: 'lxc'`.
            //
            // Network enforcement still needs the same iptables firewall mode
            // as explicit `'bubblewrap'` when host filtering is in play.
            applyLinuxNetworkPolicy(config);
            diagLog(`createConfigFromPolicy: containment=process (linux, resolves to bubblewrap), id=${containerId}`);
            return config;
        }
        if (platform === 'darwin') {
            // The seatbelt backend has no container abstraction
            // (per-process fork+exec sandbox), so containerId is intentionally
            // not threaded through.
            return buildDarwinProcessConfig(config);
        }
        diagLog(`createConfigFromPolicy: containment=process (BaseContainer), id=${containerId}`);
        const processConfig = buildProcessBaseContainerConfig(config, policy);
        if (policy.processContainer !== undefined) {
            processConfig.containment = 'processcontainer';
        }
        return processConfig;
    }

    throw new Error(`Containment type '${containment}' is not yet supported.`);
}

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
    policy: SandboxPolicy,
    workingDirectory?: string,
    containerName?: string,
    containment: ContainmentType | ContainmentBackend = "process",
): ContainerConfig {
    const config = createConfigFromPolicy(policy, containment, containerName);

    config.process!.commandLine = script;
    config.process!.cwd = workingDirectory;

    return config;
}

/**
 * Options shared by the in-process Node sandbox surfaces.
 */
export interface SandboxSpawnOptions {
  /**
   * Enable experimental backends or features supported by the native runtime.
   */
  experimental?: boolean;

  /**
   * Start from the backend's default environment and layer supplied variables
   * over it instead of replacing the environment (default false).
   */
  inheritDefaultEnv?: boolean;

  /**
   * Optional cancellation signal for live-process APIs.
   */
  signal?: AbortSignal;
}

function removedLegacyOption(options: SandboxSpawnOptions): string | undefined {
  return removedExecutorOptionName(options);
}

/**
 * Returns the signal's reason when provided, or a generic AbortError-style
 * Error when the signal supplied no reason.
 */
function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new Error('Aborted');
}

/**
 * Applies `AbortSignal` cancellation to a live in-process sandbox.
 */
function wireAbortToProcess(
  proc: MxcSandboxProcess,
  options: SandboxSpawnOptions,
): void {
  const signal = options.signal;
  if (!signal) {
    return;
  }
  const onAbort = () => {
    try {
      proc.kill();
    } catch {
      // Best-effort cancellation only.
    }
  };
  if (signal.aborted) {
    onAbort();
    return;
  }
  signal.addEventListener('abort', onAbort, { once: true });
  proc._registerCleanup(() => signal.removeEventListener('abort', onAbort));
}

function spawnConfig(
  config: ContainerConfig,
  options: SandboxSpawnOptions,
  workingDirectory?: string,
  env?: { [key: string]: string | undefined },
): MxcSandboxProcess {
  const unsupportedOption = removedLegacyOption(options);
  if (unsupportedOption !== undefined) {
    throw new MxcError(
      'malformed_request',
      `sandbox execution no longer supports legacy option '${unsupportedOption}'`,
    );
  }
  const proc = spawnBindingSandboxProcess(
    prepareRequestSpec(config, {
      workingDirectory,
      env,
      inheritDefaultEnv: options.inheritDefaultEnv,
      experimental: options.experimental,
    }),
    config.process?.timeout,
  );
  wireAbortToProcess(proc, options);
  return proc;
}

/**
 * Spawn a sandboxed process with pipe-based stdin/stdout/stderr streams.
 *
 * This retains the existing policy-based entry point while replacing its
 * former `IPty` result with {@link MxcSandboxProcess}.
 */
export function spawnSandbox(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
  env?: { [key: string]: string | undefined },
): MxcSandboxProcess {
  return spawnConfig(
    buildSandboxPayload(script, policy, workingDirectory, containerName),
    options,
    workingDirectory,
    env,
  );
}

/**
 * Spawn a sandboxed process from an existing ContainerConfig.
 *
 * The config is converted to the native request contract only at the private
 * binding boundary, so callers can keep using the established config-building
 * and customization flow.
 */
export function spawnSandboxFromConfig(
  config: ContainerConfig,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  env?: { [key: string]: string | undefined },
): MxcSandboxProcess {
  return spawnConfig(config, options, workingDirectory, env);
}

/**
 * Spawn a sandboxed process and return a promise that resolves with output.
 * Runs non-interactive workloads through the native runtime.
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 *
 * @returns Promise that resolves with stdout/stderr and exit code
 *
 * @example
 * ```typescript
 * const policy: SandboxPolicy = {
 *   version: '0.6.0-alpha',
 *   filesystem: { readwritePaths: ['/workspace'] },
 * };
 *
 * const result = await spawnSandboxAsync('echo hello', policy);
 * console.log('Output:', result.stdout);
 * console.log('Exit code:', result.exitCode);
 * ```
 */
export async function spawnSandboxAsync(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const unsupportedOption = removedLegacyOption(options);
  if (unsupportedOption !== undefined) {
    throw new MxcError(
      'malformed_request',
      `spawnSandboxAsync no longer supports legacy option '${unsupportedOption}'`,
    );
  }
  if (options.signal?.aborted) {
    throw abortReason(options.signal);
  }

  const config = buildSandboxPayload(script, policy, workingDirectory, containerName);
  const request = prepareRequestSpec(config, {
    inheritDefaultEnv: options.inheritDefaultEnv,
    experimental: options.experimental,
  });
  const result = await runBindingRequestAsync(request);
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode,
  };
}
