// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as pty from 'node-pty';
import * as os from 'os';
import { spawn, ChildProcess } from 'child_process';
import { execFileSync } from "child_process";
import * as fs from 'fs';
import { randomBytes } from "crypto";
import { parse as semverParse } from 'semver';
import { SandboxPolicy, SandboxPolicySpec, SandboxPolicyCookie, SandboxingMethod, ContainerConfig, ContainmentType, ExperimentalBackends } from './types';
import { findWxcExecutable, findLxcExecutable, getPlatformSupport } from './platform';

const SUPPORTED_VERSION = '0.5.0-alpha';
const MIN_VERSION = '0.4.0-alpha';

const AEGIS_MANAGED_MODE_KEY = "HKLM\\Software\\Policies\\Aegis";

let _managedModeCache: boolean | undefined;

/**
 * Checks whether AEGIS managed mode is active via the HKLM registry.
 * When managed mode is on, all sandbox spawns must provide a cookie.
 * Result is cached for the lifetime of the process (managed mode
 * doesn't change at runtime).
 *
 * Returns false on non-Windows platforms or if the registry key is absent.
 */
export function isAegisManagedMode(): boolean {
  if (_managedModeCache !== undefined) return _managedModeCache;
  if (os.platform() !== 'win32') { _managedModeCache = false; return false; }

  try {
    const stdout = execFileSync("reg.exe", [
      "query", AEGIS_MANAGED_MODE_KEY, "/v", "ManagedMode"
    ], { encoding: "utf8", windowsHide: true, timeout: 3000 });

    const match = stdout.match(/ManagedMode\s+REG_DWORD\s+0x(\d+)/i);
    _managedModeCache = match !== null && parseInt(match[1], 16) !== 0;
  } catch {
    _managedModeCache = false;
  }
  return _managedModeCache;
}

/** Type guard: is this policy a cookie-based policy? */
function isCookiePolicy(policy: SandboxPolicy): policy is SandboxPolicyCookie {
  return 'cookie' in policy;
}

/**
 * Resolve a SandboxPolicy to a SandboxPolicySpec. If the policy is a cookie,
 * redeem it with the AEGIS daemon to obtain the execution envelope.
 */
async function resolvePolicy(policy: SandboxPolicy, cwd?: string): Promise<SandboxPolicySpec> {
  if (!isCookiePolicy(policy)) {
    if (isAegisManagedMode()) {
      throw new Error(
        'AEGIS managed mode is active — sandbox policy must include a governance cookie.'
      );
    }
    return policy;
  }

  const { redeemCookie } = await import('./cookieRedeemer');
  const result = await redeemCookie(policy.cookie, policy.toolName, policy.toolArgsJson, cwd);

  if (!result.valid || !result.envelope) {
    throw new Error(
      `AEGIS cookie redemption failed: ${result.error || 'no envelope returned'}`
    );
  }

  const envelope = result.envelope;
  const spec: SandboxPolicySpec = {
    version: SUPPORTED_VERSION,
    filesystem: {
      readwritePaths: envelope.readwritePaths,
      readonlyPaths: envelope.readonlyPaths,
      deniedPaths: envelope.deniedPaths,
    },
    network: envelope.networkEnabled !== undefined ? {
      allowOutbound: envelope.networkEnabled,
      allowLocalNetwork: envelope.allowLocalNetwork,
    } : undefined,
    timeoutMs: envelope.timeoutSeconds ? envelope.timeoutSeconds * 1000 : undefined,
  };

  // Validate the resolved policy — a malformed daemon response should not
  // silently produce an invalid sandbox config.
  try {
    validatePolicyVersion(spec.version);
  } catch (err) {
    throw new Error(`AEGIS daemon returned an invalid policy: ${(err as Error).message}`);
  }

  return spec;
}

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
    // the network.defaultPolicy field — no firewall enforcement needed.

    return config;
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
    policy: SandboxPolicySpec,
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
    policy: SandboxPolicySpec,
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
    policy: SandboxPolicySpec,
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

        // WSLC supports block + allowedHosts via iptables (Bridged networking
        // with per-host filtering). Other backends require allowOutbound for
        // host filtering since it maps to AppContainer capabilities.
        if (containment !== 'wslc') {
            if ((policy.network.allowedHosts?.length || policy.network.blockedHosts?.length) && !policy.network.allowOutbound) {
                throw new Error('allowedHosts/blockedHosts require allowOutbound to be true');
            }
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
    if (containment === 'wslc') {
        return buildWslcContainerConfig(config, policy, containerId);
    }

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
    policy: SandboxPolicySpec,
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
    if (!(ExperimentalBackends as readonly string[]).includes(config.containment) &&
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
    cwd: workingDirectory || process.cwd(),
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
  if (isCookiePolicy(policy)) {
    throw new Error(
      'Cookie-based policy requires async resolution. Use spawnSandboxAsync() instead.'
    );
  }
  if (isAegisManagedMode()) {
    throw new Error(
      'AEGIS managed mode is active — pass a { cookie } policy to spawnSandboxAsync().'
    );
  }
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
  if (isCookiePolicy(policy)) {
    throw new Error(
      'Cookie-based policy requires async resolution. Use spawnSandboxAsync() instead.'
    );
  }
  if (isAegisManagedMode()) {
    throw new Error(
      'AEGIS managed mode is active — pass a { cookie } policy to spawnSandboxAsync().'
    );
  }
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
  if (isAegisManagedMode()) {
    throw new Error(
      'AEGIS managed mode is active — pass a { cookie } policy to spawnSandboxAsync().'
    );
  }
  return spawnWithConfig(config, options, workingDirectory, env);
}

/**
 * Async spawn that accepts both policy specs and cookie-based policies,
 * returning an IPty for interactive terminal I/O.
 *
 * When a cookie policy is provided, the cookie is redeemed with the AEGIS
 * daemon to obtain the execution envelope before spawning. The caller
 * never sees the envelope.
 */
export async function spawnSandboxPty(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
  env?: { [key: string]: string | undefined },
  containment?: ContainmentType,
): Promise<pty.IPty> {
  const spec = await resolvePolicy(policy, workingDirectory);
  const config = buildSandboxPayload(script, spec, workingDirectory, containerName, containment);
  return spawnWithConfig(config, options, workingDirectory, env);
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
export async function spawnSandboxAsync(
  script: string,
  policy: SandboxPolicy,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  containerName?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const spec = await resolvePolicy(policy, workingDirectory);
  return new Promise((resolve, reject) => {
    try {
      const config = buildSandboxPayload(script, spec, workingDirectory, containerName);
      const ptyProcess = spawnWithConfig(config, options, workingDirectory);
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
