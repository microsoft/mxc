// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { FileLogger } from './logger.js';
import { ContainerConfig, ContainmentBackend, ContainmentTypes, ExperimentalBackends, LegacyContainmentAliases } from './types.js';
import { findWxcExecutable, findLxcExecutable, findSeatbeltExecutable, getPlatformSupport } from './platform.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { diagLog } from './diagnostic.js';

/** SDK version read from package.json at module load time. */
export const SDK_VERSION: string = (() => {
    try {
        const pkgPath = require.resolve('@microsoft/mxc-sdk/package.json');
        return require(pkgPath).version as string;
    } catch {
        try {
            return require(path.resolve(__dirname, '..', 'package.json')).version as string;
        } catch {
            return 'unknown';
        }
    }
})();

let sdkVersionLogged = false;

/** Log the SDK version to the diagnostic console (once per process). */
export function diagLogVersion(): void {
    if (!sdkVersionLogged) {
        sdkVersionLogged = true;
        diagLog(`mxc-sdk v${SDK_VERSION} (PID ${process.pid})`);
    }
}

/**
 * Result of preparing a sandbox spawn — includes the resolved binary,
 * CLI arguments, and optional diagnostic logger.
 */
export interface PrepareSpawnResult {
  /** Absolute path to the wxc-exec or lxc-exec binary. */
  executablePath: string;
  /** CLI arguments to pass to the binary. */
  args: string[];
  /** Diagnostic logger, created when logDir is set or debug is enabled. */
  logger?: FileLogger;
  /** Path to the diagnostic log file (if logger is active). */
  logFile?: string;
  /** Timestamp when spawn preparation started (for duration tracking). */
  startTime: number;
}

/**
 * Generate a timestamped log file path in the given directory.
 */
export function makeLogFilePath(dir: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace(/Z$/, '');
  const suffix = randomBytes(3).toString('hex');
  return path.join(dir, `mxc-diag-${ts}-${suffix}.log`);
}

/**
 * Apply Linux network-policy defaults to a `ContainerConfig`.
 *
 * Linux enforces per-host filtering in one of two ways:
 *   1. **iptables firewall** (`enforcementMode: 'firewall'`) — LXC's
 *      privileged enforcement path. Requires root / CAP_NET_ADMIN.
 *   2. **Cooperative HTTP proxy** (`network.proxy` set) — Bubblewrap's
 *      unprivileged enforcement path. The proxy applies the host policy
 *      for cooperating HTTP clients; raw-socket clients bypass it.
 *
 * This helper auto-promotes `enforcementMode` to `'firewall'` when host
 * lists are present without a proxy — without it, the parser would leave
 * the mode unset and the runtime would silently ignore `allowedHosts` /
 * `blockedHosts`.
 *
 * If the caller explicitly passes `enforcementMode: 'capabilities'` we
 * warn: `'capabilities'` is a Windows/AppContainer concept (a token
 * capability mask) and has no Linux equivalent — the Linux runner will
 * not enforce anything and the field is silently dropped.
 *
 * Shared between the explicit `'bubblewrap'` / `'lxc'` builders and the
 * abstract `'process'` branch on Linux (which resolves to Bubblewrap
 * server-side).
 *
 * NOTE: when `network.proxy` is configured on Bubblewrap, host filtering
 * is enforced at the proxy layer (unprivileged, no CAP_NET_ADMIN). The
 * Rust config parser explicitly rejects `bubblewrap + proxy + firewall`
 * since the iptables path requires privilege the bwrap backend
 * deliberately avoids. Callers in that mode must leave enforcementMode
 * at its default.
 */
export function applyLinuxNetworkPolicy(config: ContainerConfig): void {
  if (!config.network) {
    return;
  }
  if (config.network.enforcementMode === 'capabilities') {
    console.warn(
      "mxc-sdk: network.enforcementMode='capabilities' has no effect on Linux " +
      "(it is a Windows AppContainer / ProcessContainer concept). The Linux " +
      "runner will not enforce host filtering via capabilities. Use the " +
      "default mode (auto-promotes to 'firewall' for LXC, or use network.proxy " +
      "for unprivileged Bubblewrap enforcement)."
    );
  }
  const hasProxy = !!config.network.proxy;
  const hasHostRules =
    !!(config.network.allowedHosts?.length || config.network.blockedHosts?.length);
  if (hasHostRules && !hasProxy) {
    config.network.enforcementMode = 'firewall';
  }
}

/**
 * Resolves the executor binary and builds the common CLI arguments for any
 * MXC request envelope (one-shot or state-aware). Performs platform support
 * and binary-presence checks; does not validate envelope contents — callers
 * apply request-specific validation before delegating to this helper.
 */
export function resolveBinaryAndCommonArgs(
  envelopeJson: string,
  options: SandboxSpawnOptions,
): { executablePath: string; args: string[] } {
  const platformSupport = getPlatformSupport();
  if (!platformSupport.isSupported && !options.skipPlatformCheck) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  const platform = os.platform();
  let executablePath: string;

  if (options.executablePath) {
    if (!fs.existsSync(options.executablePath)) {
      throw new Error(`File not found: ${options.executablePath}`);
    }
    executablePath = options.executablePath;
  } else if (platform === 'linux') {
    const p = findLxcExecutable();
    if (!p) {
      throw new Error(
        'lxc-exec not found. Ensure it is built and available in a standard location.'
      );
    }
    executablePath = p;
  } else if (platform === 'darwin') {
    const p = findSeatbeltExecutable();
    if (!p) {
      throw new Error(
        'mxc-exec-mac not found. Ensure it is built and available in a standard location.'
      );
    }
    executablePath = p;
  } else {
    const p = findWxcExecutable();
    if (!p) {
      throw new Error(
        'wxc-exec.exe not found. Set options.executablePath or ensure it exists in a standard location.'
      );
    }
    executablePath = p;
  }

  const args: string[] = [];
  const envelopeBase64 = Buffer.from(envelopeJson, 'utf-8').toString('base64');
  args.push('--config-base64', envelopeBase64);

  if (options.dryRun) args.push('--dry-run');
  if (options.debug) args.push('--debug');
  if (options.experimental) args.push('--experimental');

  return { executablePath, args };
}

/**
 * Resolves the executable path and builds CLI arguments for a one-shot
 * sandbox invocation. Validates one-shot-specific invariants (commandLine
 * required, experimental gating, containment-vs-platform compatibility)
 * before delegating to the shared `resolveBinaryAndCommonArgs`.
 */
export function resolveExecutableAndArgs(
  config: ContainerConfig,
  options: SandboxSpawnOptions = {},
): { executablePath: string; args: string[] } {
  if (!config.process?.commandLine) {
    throw new Error('script is required. Set process.commandLine on the config or pass a script to spawnSandbox().');
  }

  // Check experimental mode before anything else so the caller gets a clear
  // message about the missing flag rather than a platform/binary error.
  if (config.containment && ExperimentalBackends.includes(config.containment) && !options.experimental) {
    throw new Error(
      `'${config.containment}' containment requires experimental mode. Set 'experimental: true' in SandboxSpawnOptions.`
    );
  }

  const platformSupport = getPlatformSupport();
  const isExperimental = !!config.containment &&
    (ExperimentalBackends as readonly string[]).includes(config.containment);
  if (!platformSupport.isSupported && !isExperimental && !options.skipPlatformCheck) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  // Hard platform requirement: microvm needs WHP/Hyper-V on Windows. This guard
  // runs even when `skipPlatformCheck` is set because it's not a build-version
  // check — the backend literally cannot run on non-Windows hosts.
  if (config.containment === 'microvm' && os.platform() !== 'win32') {
    throw new Error('The microvm backend is only supported on Windows (requires WHP/Hyper-V).');
  }

  // Validate containment against platform
  if (config.containment && !options.skipPlatformCheck) {
    // Abstract intents (process, microvm) are resolved by the native binary
    // at run time, so the SDK accepts them without checking against the
    // host's concrete backend list.
    const isIntent = (ContainmentTypes as readonly string[]).includes(config.containment);
    // Legacy wire values accepted by the native binary via serde aliases
    // (e.g. "appcontainer" → processcontainer, "macos_sandbox" → seatbelt).
    const resolved = LegacyContainmentAliases[config.containment];
    const isAvailable = platformSupport.availableMethods.includes(
      (resolved ?? config.containment) as ContainmentBackend
    );
    if (!isIntent && !isExperimental && !isAvailable) {
      throw new Error(
        `Containment backend '${config.containment}' is not available on this platform. ` +
        `Available methods: ${platformSupport.availableMethods.join(', ')}`
      );
    }
  }

  return resolveBinaryAndCommonArgs(JSON.stringify(config), options);
}

/**
 * Sets up logging and resolves the executable path + args.
 * Shared by both PTY and non-PTY spawn paths.
 *
 * If resolveExecutableAndArgs throws, any open logger is closed
 * before the error propagates.
 *
 * @param config - The container configuration
 * @param options - Spawn options (debug, logDir, etc.)
 */
export function prepareSpawn(
  config: ContainerConfig,
  options: SandboxSpawnOptions,
): PrepareSpawnResult {
  let logger: FileLogger | undefined;
  let logFile: string | undefined;
  const logDir = options.logDir ?? (options.debug ? path.join(os.tmpdir(), 'mxc-logs') : undefined);
  if (logDir) {
    logFile = makeLogFilePath(logDir);
    logger = new FileLogger(logFile);
    logger.log('info', 'mxc.log.created', { logFile });
  }

  const startTime = Date.now();
  logger?.log('info', 'mxc.spawn.start', {
    platform: os.platform(),
    arch: os.arch(),
    containment: config.containment,
  });

  try {
    const { executablePath, args } = resolveExecutableAndArgs(config, options);
    // Pass the SDK log file to wxc-exec so Rust-side diagnostics go to the same file.
    if (logFile) {
      args.push('--log-file', logFile);
    }
    logger?.log('info', 'mxc.binary.resolved', { resolved: !!executablePath });
    return { executablePath, args, logger, logFile, startTime };
  } catch (err) {
    logger?.close();
    throw err;
  }
}
