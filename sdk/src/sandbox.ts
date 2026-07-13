// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import pty from 'node-pty';
import * as os from 'os';
import { spawn, ChildProcess } from 'child_process';
import { randomBytes } from "crypto";
import { parse as semverParse } from 'semver';
import { SandboxPolicy, ContainerConfig, ContainmentType, ContainmentBackend } from './types.js';
import { prepareSpawn, diagLogVersion, applyLinuxNetworkPolicy } from './helper.js';
import { diagLog } from './diagnostic.js';
import { MxcError, mxcErrorFromCode } from './errors.js';

const SUPPORTED_VERSION = '0.8.0-alpha';
const MIN_VERSION = '0.6.0-alpha';

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
    const capabilities: string[] = [];
    if (policy.network?.allowOutbound) {
        capabilities.push("internetClient");
    }
    if (policy.network?.allowLocalNetwork) {
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
 *   version: '0.6.0-alpha',
 *   network: { allowOutbound: true },
 *   ui: { allowWindows: true, clipboard: 'read' },
 * };
 *
 * // Simple: use defaults
 * const config = createConfigFromPolicy(policy);
 *
 * // Advanced: tweak backend-specific settings
 * const config = createConfigFromPolicy(policy, "process");
 * config.processContainer!.ui!.isolation = "atoms";
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
        diagLog(`createConfigFromPolicy: containment=microvm, id=${containerId}`);
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
        if (policy.network.proxy && platform === 'darwin') {
            throw new Error('Proxy configuration is not supported on macOS');
        }

        // WSLC supports block + allowedHosts via iptables (Bridged networking
        // with per-host filtering). macOS sandbox supports it natively via
        // per-host Seatbelt rules. Bubblewrap and LXC support it via iptables.
        // Abstract `'process'` on Linux resolves to Bubblewrap server-side, and
        // on macOS resolves to Seatbelt, so treat both the same as their
        // explicit backend counterparts here.
        // Other backends require allowOutbound for host filtering since it
        // maps to AppContainer capabilities.
        const resolvesToHostFilteringBackend =
            containment === 'wslc' ||
            containment === 'seatbelt' ||
            containment === 'bubblewrap' ||
            containment === 'lxc' ||
            (containment === 'process' && platform === 'linux') ||
            (containment === 'process' && platform === 'darwin');
        if (!resolvesToHostFilteringBackend) {
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
        return buildProcessBaseContainerConfig(config, policy);
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
   * Allow testing-only, deliberately-permissive features that must never run
   * in production — currently `network.proxy.builtinTestServer` (a bundled
   * test HTTP proxy with no auth, no body limits, minimal hop-by-hop header
   * handling). This is a distinct axis from {@link experimental}: a policy
   * that requests such a feature is rejected unless this is explicitly set,
   * keeping the gate fail-closed at the SDK boundary (it maps to the native
   * `--allow-testing-features` flag).
   */
  allowTestingFeatures?: boolean;

  /**
   * Explicit path to the wxc-exec (or lxc-exec) binary.
   * When set, the SDK uses this path directly instead of searching.
   * Useful for packaged apps (e.g., Electron) where the binary
   * is bundled in a known location.
   */
  executablePath?: string;

  /**
   * Skip platform support check. Use when you know the platform
   * is compatible and want to bypass build version validation.
   */
  skipPlatformCheck?: boolean;

  /**
   * PTY options to pass to node-pty (only used by spawnSandbox)
   */
  ptyOptions?: pty.IPtyForkOptions;

  /**
   * Dry run mode: parse and validate config without executing.
   * The native binary validates the config then exits.
   */
  dryRun?: boolean;

  /**
   * Directory for diagnostic log files
   */
  logDir?: string;

  /**
   * When false, uses child_process.spawn instead of node-pty.
   * Provides reliable exit codes and separate stdout/stderr streams.
   * Defaults to true (uses PTY).
   */
  usePty?: boolean;

  /**
   * Optional cancellation signal. When it aborts, the SDK kills the
   * spawned executor process and rejects any pending result promise with
   * the signal's reason. Honored by the state-aware lifecycle functions;
   * one-shot spawn currently ignores it (kill the returned IPty /
   * ChildProcess directly instead).
   *
   * Cancellation is best-effort: killing the executor mid-call leaves
   * any backend-side state (e.g. a partially-provisioned IsolationSession)
   * wherever it landed. Callers may need a follow-up `deprovisionSandbox`
   * (or its equivalent) to clean up an orphaned sandbox after an abort.
   */
  signal?: AbortSignal;
}

/**
 * Inject environment variables into the config's `process.env` field as
 * `KEY=VALUE` strings.  This is the explicit channel for passing env vars
 * to the sandboxed child -- the parent process environment is NOT inherited
 * by the sandbox (security: prevents secret leakage).
 */
function injectEnvIntoConfig(
  config: ContainerConfig,
  env: { [key: string]: string | undefined },
): void {
  if (!config.process) {
    config.process = { commandLine: '' };
  }
  const entries: string[] = config.process.env ? [...config.process.env] : [];
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      entries.push(`${key}=${value}`);
    }
  }
  config.process.env = entries;
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
  // Inject env vars into config.process.env so they are passed explicitly to
  // the sandboxed child via the JSON config (not via process inheritance).
  if (env) {
    injectEnvIntoConfig(config, env);
  }

  const { executablePath, args, logger, startTime } = prepareSpawn(config, options);

  try {
    const ptyOpts: pty.IPtyForkOptions = {
      name: "xterm-color",
      cols: 120,
      rows: 80,
      ...options.ptyOptions,
      cwd: workingDirectory || process.cwd(),
    };

    diagLog(`spawnWithConfig: spawning PTY process, cwd=${ptyOpts.cwd}`);

    const ptyProcess = pty.spawn(executablePath, args, ptyOpts);

    ptyProcess.onExit((event) => {
      logger?.log('info', 'mxc.spawn.exit', {
        exitCode: event.exitCode,
        durationMs: Date.now() - startTime,
      });
      logger?.close();
    });

    return ptyProcess;
  } catch (err) {
    logger?.close();
    throw err;
  }
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
 * @returns IPty object for interacting with the sandboxed process
 * @throws Error if platform is not supported or wxc-exec is not found
 *
 * @example
 * ```typescript
 * const script = 'python -c "import sys; print(sys.version)"';
 * const policy: SandboxPolicy = { version: '0.6.0-alpha' };
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
): pty.IPty {
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName);
  return spawnWithConfig(config, options, workingDirectory, env);
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
 * @returns IPty when usePty is true or unset; ChildProcess when usePty is false
 *
 * @example
 * ```typescript
 * const config = createConfigFromPolicy(policy, "process");
 * config.process!.commandLine = 'echo hello';
 * config.processContainer!.ui!.isolation = "atoms";
 *
 * // PTY mode (default) — returns IPty:
 * const ptyProcess = spawnSandboxFromConfig(config);
 *
 * // Non-PTY mode — returns ChildProcess with reliable exit codes:
 * const child = spawnSandboxFromConfig(config, { usePty: false });
 * child.stdout?.on('data', (data) => console.log(data.toString()));
 * ```
 */
export function spawnSandboxFromConfig(
  config: ContainerConfig,
  options: SandboxSpawnOptions & { usePty: false },
  workingDirectory?: string,
  env?: { [key: string]: string | undefined }
): ChildProcess;
export function spawnSandboxFromConfig(
  config: ContainerConfig,
  options?: SandboxSpawnOptions,
  workingDirectory?: string,
  env?: { [key: string]: string | undefined }
): pty.IPty;
export function spawnSandboxFromConfig(
  config: ContainerConfig,
  options: SandboxSpawnOptions = {},
  workingDirectory?: string,
  env?: { [key: string]: string | undefined }
): pty.IPty | ChildProcess {
  if (options.usePty === false) {
    // Inject env vars into config.process.env so they are passed explicitly to
    // the sandboxed child via the JSON config (not via process inheritance).
    if (env) {
      injectEnvIntoConfig(config, env);
    }

    const { executablePath, args, logger, startTime } = prepareSpawn(config, options);
    try {
      const child = spawn(executablePath, args, {
        cwd: workingDirectory || process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      child.on('close', (code) => {
        logger?.log('info', 'mxc.spawn.exit', {
          exitCode: code ?? -1,
          durationMs: Date.now() - startTime,
        });
        logger?.close();
      });
      child.on('error', () => {
        logger?.close();
      });
      return child;
    } catch (err) {
      logger?.close();
      throw err;
    }
  }

  diagLogVersion();
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
 *   version: '0.6.0-alpha',
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
        //
        // Check for structured error envelopes from wxc-exec on failure.
        if (event.exitCode !== 0) {
          const mxcError = tryParseErrorEnvelopeFromLines(output);
          if (mxcError) {
            reject(mxcError);
            return;
          }
        }
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
 * Scans a multi-line string for a JSON error envelope emitted by wxc-exec
 * on stderr. Returns the first matching envelope, or null if none found.
 * The envelope format is: `{"error": {"code": "...", "message": "...", ...}}`
 */
function tryParseErrorEnvelopeFromLines(output: string): MxcError | null {
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && 'error' in parsed) {
        const env = parsed.error;
        if (env && typeof env.code === 'string' && typeof env.message === 'string') {
          return mxcErrorFromCode(env.code, env.message, env.details);
        }
      }
    } catch {
      // Not valid JSON on this line, continue scanning.
    }
  }
  return null;
}
