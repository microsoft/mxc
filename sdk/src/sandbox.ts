// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as pty from 'node-pty';
import * as os from 'os';
import { spawn, ChildProcess } from 'child_process';
import { randomBytes } from "crypto";
import { parse as semverParse } from 'semver';
import { SandboxPolicy, SandboxingMethod, ContainerConfig } from './types';
import { findWxcExecutable, findLxcExecutable, getPlatformSupport } from './platform';

const SUPPORTED_VERSION = '0.4.0-alpha';

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
            ` (e.g., '0.4.0' or '0.4.0-alpha')`
        );
    }

    const supported = semverParse(SUPPORTED_VERSION);
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
    containment?: SandboxingMethod,
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
    };

    // If an explicit containment backend is requested, set it on the config.
    if (containment) {
        config.containment = containment;
        // microvm and vm don't need platform-specific setup — early return
        if (containment === 'microvm' || containment === 'vm') {
            if (policy.filesystem?.readwritePaths?.length ||
                policy.filesystem?.readonlyPaths?.length ||
                policy.filesystem?.deniedPaths?.length) {
                config.filesystem = {
                    readwritePaths: policy.filesystem?.readwritePaths,
                    readonlyPaths: policy.filesystem?.readonlyPaths,
                    deniedPaths: policy.filesystem?.deniedPaths,
                    clearPolicyOnExit: true,
                };
            }
            return config;
        }
        // Other backends (appcontainer, lxc, etc.) fall through to
        // platform-specific setup below
    }

    // Default path: include filesystem with clearPolicyOnExit
    config.filesystem = {
        readwritePaths: policy.filesystem?.readwritePaths,
        readonlyPaths: policy.filesystem?.readonlyPaths,
        deniedPaths: policy.filesystem?.deniedPaths,
        clearPolicyOnExit: true,
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
   * Override the containment backend (default: auto-detected from platform).
   * Use 'microvm' for Nanvix micro-VM isolation (experimental, requires --experimental).
   */
  containment?: SandboxingMethod;

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
  const { executablePath, args } = prepareSandboxInvocation(
    script, policy, options, workingDirectory, containerName
  );

  const ptyOpts: pty.IPtyForkOptions = {
    name: "xterm-color",
    cols: 120,
    rows: 80,
    ...options.ptyOptions,
    cwd: workingDirectory || options.ptyOptions?.cwd || process.cwd(),
    env: env ?? options.ptyOptions?.env,
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

/**
 * Resolves the executable path and builds CLI arguments for a sandbox invocation.
 * Shared setup used by both PTY and non-PTY spawn paths.
 */
function prepareSandboxInvocation(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
): { executablePath: string; args: string[] } {
  const platformSupport = getPlatformSupport();
  if (!platformSupport.isSupported) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  // Validate containment against available methods (skip experimental backends
  // like microvm/vm/sandbox which aren't reported by platform detection)
  if (options.containment) {
    const experimental = ['microvm', 'vm', 'sandbox', 'wslc'];
    if (!experimental.includes(options.containment) &&
        !platformSupport.availableMethods.includes(options.containment)) {
      throw new Error(
        `Containment backend '${options.containment}' is not available on this platform. ` +
        `Available methods: ${platformSupport.availableMethods.join(', ')}`
      );
    }
  }

  const platform = os.platform();
  let executablePath: string | null;

  if (platform === 'linux') {
    executablePath = findLxcExecutable();
    if (!executablePath) {
      throw new Error('lxc-exec not found. Ensure it is built and available in a standard location.');
    }
  } else {
    executablePath = findWxcExecutable();
    if (!executablePath) {
      throw new Error('wxc-exec.exe not found. Please specify the path or ensure it exists in a standard location.');
    }
  }

  const config = buildSandboxPayload(script, policy, workingDirectory, containerName, options.containment);

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

  return { executablePath, args };
}

/**
 * Execute a sandboxed process using child_process.spawn (non-PTY).
 *
 * Unlike `spawnSandbox` (which uses node-pty for interactive terminal I/O),
 * this function uses `child_process.spawn` for reliable exit code propagation
 * and separate stdout/stderr streams. Use this for programmatic/CI scenarios
 * where correct exit codes matter more than terminal features.
 *
 * @param script The command line script to execute
 * @param policy The sandbox policy
 * @param options - Spawn options
 * @param workingDirectory Optional working directory path
 * @param containerName Optional container name
 *
 * @returns Promise resolving with stdout, stderr, and exit code
 *
 * @example
 * ```typescript
 * const result = await execSandbox(
 *   "print('Hello from sandbox!')",
 *   { version: '0.4.0-alpha' },
 *   { containment: 'microvm', experimental: true }
 * );
 * console.log(result.stdout);    // "Hello from sandbox!"
 * console.log(result.exitCode);  // 0
 * ```
 */
export function execSandbox(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
  env?: { [key: string]: string | undefined },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const { executablePath, args } = prepareSandboxInvocation(
    script, policy, options, workingDirectory, containerName
  );

  return new Promise((resolve, reject) => {
    const child: ChildProcess = spawn(executablePath, args, {
      cwd: workingDirectory || process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
      ...(env ? { env: env as NodeJS.ProcessEnv } : {}),
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    child.stdout?.on('data', (data: Buffer) => {
      stdoutChunks.push(data);
    });

    child.stderr?.on('data', (data: Buffer) => {
      stderrChunks.push(data);
    });

    child.on('error', (error: Error) => {
      reject(new Error(`Failed to spawn sandbox process: ${error.message}`));
    });

    child.on('close', (code: number | null) => {
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString(),
        stderr: Buffer.concat(stderrChunks).toString(),
        exitCode: code ?? -1,
      });
    });
  });
}
