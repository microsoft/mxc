// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as pty from 'node-pty';
import * as os from 'os';
import { randomBytes } from "crypto";
import { parse as semverParse } from 'semver';
import { SandboxPolicy, ContainerConfig, ContainmentType } from './types';
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
 * Builds the Windows process container (BaseProcessContainer) portion of a ContainerConfig.
 */
function buildWindowsProcessConfig(
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

    // Windows uses both capabilities and firewall for network enforcement
    if (config.network) {
        config.network.enforcementMode = 'both';
    }

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
 *   version: '0.4.0-alpha',
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

    const config: ContainerConfig = {
        version: policy.version,
        containerId,
        lifecycle: {
            destroyOnExit: true,
            preservePolicy: false,
        },
        process: {
            commandLine: '',
            timeout: policy.timeoutMs ?? 0,
        },
        filesystem: {
            readwritePaths: [...(policy.filesystem?.readwritePaths ?? [])],
            readonlyPaths: [...(policy.filesystem?.readonlyPaths ?? [])],
            deniedPaths: [...(policy.filesystem?.deniedPaths ?? [])],
        },
    };

    // UI mapping (cross-platform)
    config.ui = {
        disable: !(policy.ui?.allowWindows ?? false),
        clipboard: policy.ui?.clipboard ?? "none",
        injection: policy.ui?.allowInputInjection ?? false,
    };

    // Network mapping (cross-platform)
    if (policy.network) {
        if (policy.network.proxy && platform === 'linux') {
            throw new Error('Proxy configuration is not supported on Linux');
        }

        config.network = {
            defaultPolicy: policy.network.allowOutbound ? 'allow' : 'block',
            allowedHosts: policy.network.allowedHosts,
            blockedHosts: policy.network.blockedHosts,
            proxy: policy.network.proxy,
        };
    }

    // Backend-specific config based on containment type
    if (containment === 'process') {
        if (platform === 'linux') {
            return buildLinuxProcessConfig(config, containerId);
        }
        return buildWindowsProcessConfig(config, policy, containerId);
    }

    throw new Error(`Containment type '${containment}' is not yet supported.`);
}

/**
 * Builds a sandbox payload JSON object from the sandbox policy.
 * @param script The command line script to execute
 * @param policy The sandbox policy configuration
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @returns The sandbox payload object
 */
export function buildSandboxPayload(
    script: string,
    policy: SandboxPolicy,
    workingDirectory?: string,
    containerName?: string,
): ContainerConfig {
    const config = createConfigFromPolicy(policy, "process", containerName);

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
   * PTY options to pass to node-pty
   */
  ptyOptions?: pty.IPtyForkOptions;
}

/**
 * Internal helper: resolves the executor binary path and spawns a PTY process.
 */
function spawnWithConfig(
  script: string,
  config: ContainerConfig,
  options: SandboxSpawnOptions,
  workingDirectory?: string,
  env?: { [key: string]: string | undefined },
): pty.IPty {
  const platformSupport = getPlatformSupport();
  if (!platformSupport.isSupported) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  const platform = os.platform();
  let executablePath: string | null;

  if (platform === 'linux') {
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
        'wxc-exec.exe not found. Please specify the path or ensure it exists in a standard location.'
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

  if (options.experimental) {
    args.push('--experimental');
  }

  const ptyOpts: pty.IPtyForkOptions = {
    name: "xterm-color",
    cols: 120,
    rows: 80,
    cwd: workingDirectory || process.cwd(),
    env: env
  };

  return pty.spawn(executablePath, args, ptyOpts);
}

/**
 * Spawn a sandboxed process from a SandboxPolicy.
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @returns IPty object for interacting with the sandboxed process
 *
 * @example
 * ```typescript
 * const policy: SandboxPolicy = {
 *   version: '0.4.0-alpha',
 *   network: { allowOutbound: true },
 * };
 * const ptyProcess = spawnSandbox('echo hello', policy);
 * ```
 */
export function spawnSandbox(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
  env?: { [key: string]: string | undefined }
): pty.IPty {
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName);
  return spawnWithConfig(script, config, options, workingDirectory, env);
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
  if (!config.process?.commandLine) {
    throw new Error('ContainerConfig.process.commandLine is required');
  }
  return spawnWithConfig(config.process.commandLine, config, options, workingDirectory, env);
}

/**
 * Spawn a sandboxed process and return a promise that resolves with output.
 * Convenience wrapper around spawnSandbox for non-interactive use cases.
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
 *   version: '0.4.0-alpha',
 *   filesystem: { readwritePaths: ['/workspace'] },
 * };
 *
 * const result = await spawnSandboxAsync('echo hello', policy);
 * console.log('Output:', result.stdout);
 * console.log('Exit code:', result.exitCode);
 * ```
 */
export function spawnSandboxAsync(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    try {
      const ptyProcess = spawnSandbox(script, policy, options, workingDirectory, containerName);
      let output = '';

      ptyProcess.onData((data: string) => {
        output += data;
      });

      ptyProcess.onExit((event: { exitCode: number; signal?: number }) => {
        // Note: wxc-exec doesn't separate stdout/stderr when using PTY
        // All output is combined
        resolve({
          stdout: output,
          stderr: '',
          exitCode: event.exitCode
        });
      });
    } catch (error) {
      reject(error);
    }
  });
}
