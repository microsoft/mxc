// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as pty from 'node-pty';
import * as os from 'os';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import { randomBytes } from "crypto";
import { parse as semverParse } from 'semver';
import { SandboxPolicy, SandboxingMethod, ContainerConfig, ContainmentType, ExperimentalBackends } from './types';
import { findWxcExecutable, findLxcExecutable, getPlatformSupport } from './platform';

const SUPPORTED_VERSION = '0.5.0-alpha';
const MIN_VERSION = '0.4.0-alpha';

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
            ` (e.g., '0.5.0' or '0.5.0-alpha')`
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
}


/**
 * Builds the Linux process container (LXC) portion of a ContainerConfig.
 */
function buildLinuxProcessConfig(
    config: ContainerConfig,
    containerId: string,
): ContainerConfig {
    config.containment = 'lxc';
    config.lxc = {
        containerName: containerId,
        distribution: 'alpine',
        release: '3.23',
        destroyOnExit: true,
    };

    return config;
}

/**
 * Builds the Windows process container portion of a ContainerConfig.
 */
function buildProcessBaseContainerConfig(
    config: ContainerConfig,
    policy: SandboxPolicy,
    containerId: string,
): ContainerConfig {
    const capabilities: string[] = [];
    if (policy.network?.allowOutbound) {
        capabilities.push("internetClient");
    }
    if (policy.network?.allowLocalNetwork) {
        capabilities.push("privateNetworkClientServer");
    }

    config.appContainer = {
        name: containerId,
        leastPrivilege: false,
        capabilities,
        ui: {
            isolation: "container",
            desktopSystemControl: false,
            systemSettings: "none",
            ime: false,
        },
    };

    // Network enforcement: use firewall only when host filtering is needed (requires admin)
    if (config.network) {
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
 * MicroVM is Windows-only and does not support network or UI policies.
 */
function buildMicroVmConfig(
    config: ContainerConfig,
    policy: SandboxPolicy,
): ContainerConfig {
    if (os.platform() !== 'win32') {
        throw new Error('The microvm backend is only supported on Windows (requires WHP/Hyper-V).');
    }
    if (policy.network) {
        throw new Error(
            'The microvm backend does not support network policy enforcement. ' +
            'Remove policy.network or use a different containment backend.'
        );
    }
    if (policy.filesystem?.readwritePaths?.length ||
        policy.filesystem?.readonlyPaths?.length ||
        policy.filesystem?.deniedPaths?.length) {
        config.filesystem = {
            readwritePaths: policy.filesystem?.readwritePaths,
            readonlyPaths: policy.filesystem?.readonlyPaths,
            deniedPaths: policy.filesystem?.deniedPaths,
            clearPolicyOnExit: policy.filesystem?.clearPolicyOnExit ?? true,
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
 * can be modified before passing to spawnSandboxFromConfig().
 *
 * @param policy - The sandbox policy expressing security intent
 * @param containment - Containment backend type (default: "process")
 * @param containerName - Optional container name; auto-generated if omitted
 * @returns A fully populated ContainerConfig ready for modification or spawning
 *
 * @example
 * ```typescript
 * const policy: SandboxPolicy = {
 *   version: '0.5.0-alpha',
 *   network: { allowOutbound: true },
 *   ui: { allowWindows: true, clipboard: 'read' },
 * };
 *
 * // Simple: use defaults
 * const config = createConfigFromPolicy(policy);
 *
 * // Advanced: tweak backend-specific settings
 * const config = createConfigFromPolicy(policy, "process");
 * config.appContainer!.ui!.isolation = "atoms";
 * ```
 */
export function createConfigFromPolicy(
    policy: SandboxPolicy,
    containment: ContainmentType = "process",
    containerName?: string,
): ContainerConfig {
    validatePolicyVersion(policy.version);

    const platform = os.platform();
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
    };

    // Microvm: delegate to dedicated builder
    if (containment === 'microvm') {
        return buildMicroVmConfig(config, policy);
    }

    config.filesystem = {
        readwritePaths: [...(policy.filesystem?.readwritePaths ?? [])],
        readonlyPaths: [...(policy.filesystem?.readonlyPaths ?? [])],
        deniedPaths: [...(policy.filesystem?.deniedPaths ?? [])],
    };

    // UI mapping (cross-platform)
    config.ui = {
        disable: !(policy.ui?.allowWindows ?? false),
        clipboard: policy.ui?.clipboard ?? "none",
        injection: policy.ui?.allowInputInjection ?? false,
    };

    // Network mapping (cross-platform) — default-deny: block if not explicitly allowed
    if (policy.network) {
        if (policy.network.proxy && platform === 'linux') {
            throw new Error('Proxy configuration is not supported on Linux');
        }

        if ((policy.network.allowedHosts?.length || policy.network.blockedHosts?.length) && !policy.network.allowOutbound) {
            throw new Error('allowedHosts/blockedHosts require allowOutbound to be true');
        }

        config.network = {
            defaultPolicy: policy.network.allowOutbound ? 'allow' : 'block',
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
    if (containment === 'process') {
        if (platform === 'linux') {
            return buildLinuxProcessConfig(config, containerId);
        }
        return buildProcessBaseContainerConfig(config, policy, containerId);
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
    containment: ContainmentType = "process",
): ContainerConfig {
    const config = createConfigFromPolicy(policy, containment, containerName);

    config.process!.commandLine = script;
    config.process!.cwd = workingDirectory;

    return config;
}

/**
 * Options for spawning a sandboxed process
 */
export interface SandboxSpawnOptions {
  /**
   * Enable debug output from wxc-exec
   */
  debug?: boolean;

  /**
   * Enable experimental features
   */
  experimental?: boolean;

  /**
   * Explicit path to the wxc-exec (or lxc-exec) binary.
   * When set, the SDK uses this path directly instead of searching.
   * Useful for packaged apps (e.g., Electron) where the binary
   * is bundled in a known location.
   */
  executablePath?: string;

  /**
   * PTY options to pass to node-pty (only used by spawnSandbox)
   */
  ptyOptions?: pty.IPtyForkOptions;
}

/**
 * Resolves the executable path and builds CLI arguments for a sandbox invocation.
 * Shared setup used by both PTY and non-PTY spawn paths.
 */
function resolveExecutableAndArgs(
  config: ContainerConfig,
  options: SandboxSpawnOptions = {},
): { executablePath: string; args: string[] } {
  if (!config.process?.commandLine) {
    throw new Error('script is required. Set process.commandLine on the config or pass a script to spawnSandbox().');
  }

  const platformSupport = getPlatformSupport();
  if (!platformSupport.isSupported) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  // Validate containment against platform
  if (config.containment) {
    if (config.containment === 'microvm' && os.platform() !== 'win32') {
      throw new Error('The microvm backend is only supported on Windows (requires WHP/Hyper-V).');
    }
    const experimentalList: readonly string[] = ExperimentalBackends;
    if (!experimentalList.includes(config.containment) &&
        !platformSupport.availableMethods.includes(config.containment as SandboxingMethod)) {
      throw new Error(
        `Containment backend '${config.containment}' is not available on this platform. ` +
        `Available methods: ${platformSupport.availableMethods.join(', ')}`
      );
    }
  }

  const platform = os.platform();
  let executablePath: string | null;

  if (options.executablePath) {
    if (!fs.existsSync(options.executablePath)) {
      throw new Error(`File not found: ${options.executablePath}`);
    }
    executablePath = options.executablePath;
  } else if (platform === 'linux') {
    executablePath = findLxcExecutable();
    if (!executablePath) {
      throw new Error(
        'lxc-exec not found. Ensure it is built and available in a standard location.'
      );
    }
  } else {
    executablePath = findWxcExecutable();
    if (!executablePath) {
      throw new Error(
        'wxc-exec.exe not found. Set options.executablePath or ensure it exists in a standard location.'
      );
    }
  }

  const args: string[] = [];
  const configJson = JSON.stringify(config);
  const configBase64 = Buffer.from(configJson, 'utf-8').toString('base64');
  args.push('--config-base64', configBase64);

  if (options.debug) {
    args.push('--debug');
  }

  if (ExperimentalBackends.includes(config.containment as ContainmentType) && !options.experimental) {
    throw new Error(
      `'${config.containment}' containment requires experimental mode. Set 'experimental: true' in SandboxSpawnOptions.`
    );
  }

  if (options.experimental) {
    args.push('--experimental');
  }

  return { executablePath, args };
}

/**
 * Internal helper: resolves the executor binary path and spawns a PTY process.
 */
function spawnWithConfig(
  config: ContainerConfig,
  options: SandboxSpawnOptions,
  workingDirectory?: string,
  env?: { [key: string]: string | undefined },
): pty.IPty {
  const { executablePath, args } = resolveExecutableAndArgs(config, options);

  const ptyOpts: pty.IPtyForkOptions = {
    name: "xterm-color",
    cols: 120,
    rows: 80,
    ...options.ptyOptions,
    cwd: workingDirectory || options.ptyOptions?.cwd || process.cwd(),
    env: env ?? options.ptyOptions?.env,
  };

  return pty.spawn(executablePath, args, ptyOpts);
}

/**
 * Spawn a sandboxed process using wxc-exec with a PTY (node-pty) for
 * interactive terminal I/O (colors, input forwarding).
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @param env Optional environment variables
 * @param containment Optional containment backend
 * @returns IPty object for interacting with the sandboxed process
 * @throws Error if platform is not supported or wxc-exec is not found
 *
 * @example
 * ```typescript
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = { version: '0.4.0-alpha' };
 *
 * const ptyProcess = spawnSandbox(script, policy);
 * ptyProcess.onData((data) => console.log(data));
 * ptyProcess.onExit((e) => console.log('Exit code:', e.exitCode));
 * ```
 */
export function spawnSandbox(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
  env?: { [key: string]: string | undefined },
  containment?: ContainmentType,
): pty.IPty {
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName, containment);
  return spawnWithConfig(config, options, workingDirectory, env);
}

/**
 * Spawn a sandboxed process using child_process.spawn (non-PTY).
 *
 * Returns the `ChildProcess` directly so the caller can manage stdout, stderr,
 * and exit events. Use this for CI/automation where reliable exit codes and
 * separate output streams are required.
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name
 * @param env Optional environment variables
 * @param containment Optional containment backend
 *
 * @returns The spawned ChildProcess
 *
 * @example
 * ```typescript
 * const child = spawnSandboxWithoutPty(
 *   "print('Hello from sandbox!')",
 *   { version: '0.4.0-alpha' },
 *   { experimental: true }
 * );
 * child.stdout?.on('data', (data) => console.log(data.toString()));
 * child.on('close', (code) => console.log('Exit code:', code));
 * ```
 */
export function spawnSandboxWithoutPty(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
  env?: { [key: string]: string | undefined },
  containment?: ContainmentType,
): ChildProcess {
  if (options.ptyOptions) {
    console.warn('Warning: ptyOptions are ignored by spawnSandboxWithoutPty (non-PTY). Use spawnSandbox for PTY support.');
  }
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName, containment);
  const { executablePath, args } = resolveExecutableAndArgs(config, options);

  return spawn(executablePath, args, {
    cwd: workingDirectory || process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
    ...(env ? { env: env as NodeJS.ProcessEnv } : {}),
  });
}

/**
 * Spawn a sandboxed process from a pre-built ContainerConfig.
 *
 * Use with `createConfigFromPolicy()` when you need to modify
 * backend-specific settings before spawning. The config must have
 * `process.commandLine` already set.
 *
 * @param config The container configuration (from createConfigFromPolicy)
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @returns IPty object for interacting with the sandboxed process
 *
 * @example
 * ```typescript
 * const config = createConfigFromPolicy(policy, "process");
 * config.process!.commandLine = 'echo hello';
 * config.appContainer!.ui!.isolation = "atoms";
 * const ptyProcess = spawnSandboxFromConfig(config);
 * ```
 */
export function spawnSandboxFromConfig(
  config: ContainerConfig,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  env?: { [key: string]: string | undefined }
): pty.IPty {
  return spawnWithConfig(config, options, workingDirectory, env);
}
