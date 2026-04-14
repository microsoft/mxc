// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as pty from 'node-pty';
import * as os from 'os';
import { randomBytes } from "crypto";
import { parse as semverParse } from 'semver';
import { SandboxPolicy, ContainerConfig } from './types';
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
    validatePolicyVersion(policy.version);

    const platform = os.platform();
    const name = containerName ?? generateRandomContainerName();

    const config: ContainerConfig = {
        version: policy.version,
        process: {
            commandLine: script,
            cwd: workingDirectory,
        },
        containerId: name,
        filesystem: {
            readwritePaths: policy.filesystem?.readwritePaths,
            readonlyPaths: policy.filesystem?.readonlyPaths,
            deniedPaths: policy.filesystem?.deniedPaths,
            clearPolicyOnExit: true,
        },
    };

    if (platform === 'linux') {
        config.containment = 'lxc';
        config.lxc = {
            containerName: name,
            // Default Linux distro since SandboxPolicy doesn't expose this
            distribution: 'alpine',
            release: '3.23',
            destroyOnExit: true,
        };

        if (policy.network?.proxy) {
            throw new Error('Proxy configuration is not supported on Linux');
        }

        if (policy.network) {
            config.network = {
                defaultPolicy: policy.network.allowOutbound ? 'allow' : 'block',
                enforcementMode: 'firewall',
            };
        }

        return config;
    }

    // Windows / AppContainer
    const capabilities: string[] = [];
    if (policy.network?.allowOutbound) {
        capabilities.push("internetClient");
    }
    if (policy.network?.allowLocalNetwork) {
        capabilities.push("privateNetworkClientServer");
    }

    config.appContainer = {
        name: name,
        leastPrivilege: false,
        capabilities,
    };

    if (policy.network?.proxy) {
        if (!config.network) {
            config.network = {};
        }
        config.network.proxy = policy.network.proxy;
    }

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
 * Spawn a sandboxed process using wxc-exec and return a node-pty IPty object
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name; if not provided, a random name will be generated
 * @returns IPty object for interacting with the sandboxed process
 * @throws Error if platform is not supported or wxc-exec is not found
 *
 * @example
 * ```typescript
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = {}
 *
 * const result = await spawnSandbox(script, policy);
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
  env?: { [key: string]: string | undefined }
): pty.IPty {
  // Check platform support
  const platformSupport = getPlatformSupport();
  if (!platformSupport.isSupported) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  // Determine executable path based on platform
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

  // Build config
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName);

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

  const ptyProcess = pty.spawn(executablePath, args, ptyOpts);
  return ptyProcess;
}

/**
 * Spawn a sandboxed process and return a promise that resolves with output
 * This is a convenience wrapper around spawnSandbox for non-interactive use cases
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
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = {}
 *
 * const result = await spawnSandboxAsync(script, policy);
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
