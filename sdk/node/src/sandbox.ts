// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import pty from 'node-pty';
import * as os from 'os';
import { spawn, ChildProcess } from 'child_process';
import { randomBytes } from "crypto";
import {
    SandboxPolicy,
    ContainerConfig,
    SandboxContainment,
} from './types.js';
import { prepareSpawn, diagLogVersion, applyLinuxNetworkPolicy } from './helper.js';
import { diagLog } from './diagnostic.js';
import { MxcError } from './errors.js';
import { prepareRequestSpec } from './bindings/request.js';
import {
  runBindingRequestAsync,
  type BindingRunResult,
} from './bindings/run.js';

const SDK_CONTRACT_VERSION = '1.0.0';
const LEGACY_POLICY_NETWORK_FIELDS = [
    'allowOutbound',
    'defaultPolicy',
    'enforcementMode',
    'allowLocalNetwork',
    'allowedHosts',
    'blockedHosts',
    'proxy',
] as const;
const V1_CONTAINMENTS = new Set<SandboxContainment>([
    'process',
    'processcontainer',
    'wslc',
    'lxc',
    'seatbelt',
    'isolation_session',
    'bubblewrap',
]);

/**
 * Generates a random 8-character alphanumeric string for the app container name.
 */
function generateRandomContainerName(): string {
    return randomBytes(4).toString("hex");
}

function validateV1Policy(policy: SandboxPolicy, containment: SandboxContainment): void {
    if ('version' in policy) {
        throw new Error(
            'SandboxPolicy no longer accepts a caller-selected version; '
            + 'the v1 SDK targets exact contract 1.0.0. '
            + 'Use ContainerConfig for raw exact-version configuration.',
        );
    }
    if (!V1_CONTAINMENTS.has(containment)) {
        throw new Error(
            `Containment '${String(containment)}' is not available in the v1.0 high-level SDK. `
            + 'Use an exact-version ContainerConfig for development-only containment.',
        );
    }
    if (policy.network !== undefined) {
        for (const field of LEGACY_POLICY_NETWORK_FIELDS) {
            if (field in policy.network) {
                throw new Error(
                    `SandboxPolicy.network.${field} is not part of the v1 API; `
                    + 'use directional network.egress/network.ingress and '
                    + 'runtimeConfig.networkProxy.',
                );
            }
        }
    }
}

function hasProcessContainerPolicy(policy: SandboxPolicy): boolean {
    return Boolean(policy.processContainer?.filesystem?.enumeratePaths?.length) ||
        policy.processContainer?.network?.allowedProxyPeer !== undefined;
}


/**
 * Builds the WSLC (WSL Container) portion of a ContainerConfig.
 * WSLC runs Linux containers on Windows via the WSL Container SDK.
 * The exact contract location is independent of the runtime experimental gate.
 */
function buildWslcContainerConfig(
    config: ContainerConfig,
    policy: SandboxPolicy,
    containerId: string,
): ContainerConfig {
    config.containment = 'wslc';
    config.containerId = containerId;

    config.wslc = {
        image: 'alpine:latest',
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
    const capabilities: string[] = [];
    const allowsInternet =
        policy.network?.egress?.default === 'allow' ||
        Boolean(policy.network?.egress?.allow?.length);
    if (allowsInternet) {
        capabilities.push("internetClient");
    }
    if (policy.network?.ingress?.default === 'allow') {
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
        filesystem: policy.processContainer?.filesystem?.enumeratePaths?.length
            ? { enumeratePaths: [...policy.processContainer.filesystem.enumeratePaths] }
            : undefined,
        network: policy.processContainer?.network?.allowedProxyPeer !== undefined
            ? { allowedProxyPeer: policy.processContainer.network.allowedProxyPeer }
            : undefined,
    };

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
    containment: SandboxContainment = "process",
    containerName?: string,
): ContainerConfig {
    diagLogVersion();
    validateV1Policy(policy, containment);
    const platform = os.platform();
    const enumeratePaths = policy.processContainer?.filesystem?.enumeratePaths;

    const containerId = containerName ?? generateRandomContainerName();

    const clearPolicy = policy.filesystem?.clearPolicyOnExit ?? true;
    const config: ContainerConfig = {
        version: SDK_CONTRACT_VERSION,
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

    if (enumeratePaths?.length) {
        const targetsWindowsProcessContainer =
            platform === 'win32' && (containment === 'process' || containment === 'processcontainer');
        if (!targetsWindowsProcessContainer) {
            throw new Error(
                'processContainer.filesystem.enumeratePaths is supported only by the Windows ' +
                'ProcessContainer backend.'
            );
        }
    }

    config.filesystem = {
        readwritePaths: [...(policy.filesystem?.readwritePaths ?? [])],
        readonlyPaths: [...(policy.filesystem?.readonlyPaths ?? [])],
        deniedPaths: [...(policy.filesystem?.deniedPaths ?? [])],
    };
    if (enumeratePaths?.length) {
        config.processContainer = {
            filesystem: {
                enumeratePaths: [...enumeratePaths],
            },
        };
    }

    // SandboxPolicy defaults are fail-closed, so omission still emits lockdown.
    config.ui = {
        disable: !(policy.ui?.allowWindows ?? false),
        clipboard: policy.ui?.clipboard ?? "none",
        injection: policy.ui?.allowInputInjection ?? false,
    };

    if (policy.network !== undefined) {
        config.network = {
            egress: policy.network.egress,
            ingress: policy.network.ingress,
        };
    }
    if (policy.runtimeConfig?.networkProxy !== undefined) {
        config.runtimeConfig = {
            networkProxy: policy.runtimeConfig.networkProxy,
        };
    }
    if (policy.processContainer?.network?.allowedProxyPeer !== undefined) {
        config.processContainer = {
            ...config.processContainer,
            network: {
                allowedProxyPeer: policy.processContainer.network.allowedProxyPeer,
            },
        };
    }

    // Backend-specific config based on containment type
    if (containment === 'wslc') {
        return buildWslcContainerConfig(config, policy, containerId);
    }

    if (containment === 'isolation_session') {
        config.containment = 'isolation_session';
        diagLog(`createConfigFromPolicy: containment=isolation_session, id=${containerId}`);
        return config;
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

    if (containment === 'seatbelt') {
        config.containment = 'seatbelt';
        diagLog(`createConfigFromPolicy: containment=seatbelt, id=${containerId}`);
        return buildDarwinProcessConfig(config);
    }

    if (containment === 'processcontainer') {
        config.containment = 'processcontainer';
        diagLog(`createConfigFromPolicy: containment=processcontainer, id=${containerId}`);
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
        if (hasProcessContainerPolicy(policy)) {
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
    containment: SandboxContainment = "process",
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
   * Start from the backend's default environment and layer the supplied
   * environment variables on top of it, rather than replacing it
   * (default false).
   *
   * Without this, an environment you supply is used verbatim — which on the
   * Windows process container means a sparse environment is missing the
   * variables Windows requires to be present, and the launch fails. Use this
   * to express "the usual environment, plus these": the default is the user's
   * profile block, which only the OS can produce.
   *
   * This is a different, smaller set than the calling process's `process.env`,
   * which you can still pass explicitly as the `env` argument if you want your
   * own variables handed to the child.
   *
   * Maps to `process.inheritDefaultEnv` in the JSON config.
   */
  inheritDefaultEnv?: boolean;

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
   * Optional cancellation signal for promise-returning state-aware lifecycle
   * functions, including `execInSandboxAsync`. Live `execInSandbox` uses
   * `StateAwareStreamingOptions`; call `kill()` on its returned process.
   *
   * Cancellation is best-effort: cancelling a call may leave
   * any backend-side state (e.g. a partially-provisioned IsolationSession)
   * wherever it landed. Callers may need a follow-up `deprovisionSandbox`
   * (or its equivalent) to clean up an orphaned sandbox after an abort.
   */
  signal?: AbortSignal;
}

function unsupportedInProcessRunOption(options: SandboxSpawnOptions): string | undefined {
  if (options.debug === true) return 'debug';
  if (options.allowTestingFeatures === true) return 'allowTestingFeatures';
  if (options.skipPlatformCheck === true) return 'skipPlatformCheck';
  if (options.executablePath !== undefined) return 'executablePath';
  if (options.ptyOptions !== undefined) return 'ptyOptions';
  if (options.dryRun === true) return 'dryRun';
  if (options.logDir !== undefined) return 'logDir';
  if (options.usePty === true) return 'usePty';
  if (options.signal !== undefined) return 'signal';
  return undefined;
}

function appendDiagnosticLine(output: string, line: string): string {
  const prefix = output.length === 0 || output.endsWith('\n') ? output : `${output}\n`;
  return `${prefix}${line}\n`;
}

// Preserve diagnostics that the executor CLI previously emitted on stderr.
function bufferedStderr(result: BindingRunResult): string {
  let stderr = result.stderr;
  for (const warning of result.warnings) {
    stderr = appendDiagnosticLine(stderr, warning);
  }

  if (
    result.outputMetadata !== null
    && typeof result.outputMetadata === 'object'
    && !Array.isArray(result.outputMetadata)
  ) {
    const captureDenials = (result.outputMetadata as Record<string, unknown>).captureDenials;
    if (captureDenials !== undefined) {
      stderr = appendDiagnosticLine(stderr, JSON.stringify(captureDenials));
    }
  }
  return stderr;
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
 * Apply {@link SandboxSpawnOptions.inheritDefaultEnv} to the config, so the
 * environment is layered on the backend's default rather than replacing it.
 * An option left unset does not clobber a value the caller already put in the
 * config; an explicit boolean overrides it.
 */
function applyInheritDefaultEnv(config: ContainerConfig, options: SandboxSpawnOptions): void {
  if (options.inheritDefaultEnv === undefined) {
    return;
  }
  if (!options.inheritDefaultEnv) {
    if (config.process) {
      delete config.process.inheritDefaultEnv;
    }
    return;
  }
  if (!config.process) {
    config.process = { commandLine: '' };
  }
  config.process.inheritDefaultEnv = true;
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
  applyInheritDefaultEnv(config, options);

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
 * const policy: SandboxPolicy = {};
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
    applyInheritDefaultEnv(config, options);

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
  const unsupportedOption = unsupportedInProcessRunOption(options);
  if (unsupportedOption !== undefined) {
    throw new MxcError(
      'malformed_request',
      `spawnSandboxAsync does not support executor-only option '${unsupportedOption}'`,
    );
  }
  const config = buildSandboxPayload(script, policy, workingDirectory, containerName);
  const request = prepareRequestSpec(config, {
    inheritDefaultEnv: options.inheritDefaultEnv,
    experimental: options.experimental,
  });
  const result = await runBindingRequestAsync(request);
  if (result.timedOut) {
    throw new MxcError('backend_error', 'sandbox execution timed out', {
      timedOut: true,
    });
  }
  return {
    stdout: result.stdout,
    stderr: bufferedStderr(result),
    exitCode: result.exitCode,
  };
}
