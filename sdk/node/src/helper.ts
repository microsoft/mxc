// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { FileLogger } from './logger.js';
import { ContainerConfig, ContainmentBackend, ContainmentTypes } from './types.js';
import { findWxcExecutable, findLxcExecutable, findSeatbeltExecutable, getPlatformSupport } from './platform.js';
import { SandboxSpawnOptions } from './sandbox.js';
import { diagLog } from './diagnostic.js';
import { ContainmentRegistry, judge, Verdict } from './version-registry.js';

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

const legacyContainmentWarned = new Set<string>();

/**
 * Emit a one-shot deprecation hint via the diagnostic console when a caller
 * uses a legacy containment wire value. Dedup'd per legacy value per process
 * so the message doesn't flood the diag stream on repeated spawns.
 *
 * The verdict carries the rename target and version metadata sourced from
 * `ContainmentRegistry`, so the message stays in sync with the registry
 * without further plumbing.
 *
 * Exposed for tests so the latch can be reset between describes.
 */
export function warnLegacyContainmentOnce(
    legacy: string,
    verdict: Extract<Verdict, { kind: 'ok-deprecated' }>,
): void {
    if (!legacyContainmentWarned.has(legacy)) {
        legacyContainmentWarned.add(legacy);
        const removalNote = verdict.removeIn
            ? ` and will be removed in ${verdict.removeIn}`
            : '';
        diagLog(
            `Containment value '${legacy}' is deprecated since schema ${verdict.deprecatedSince}${removalNote}; ` +
            `use '${verdict.canonical}' instead. The legacy spelling is accepted via a ` +
            `backward-compatibility alias.`
        );
    }
}

/** @internal Reset the legacy-containment dedup latch. Intended for unit tests. */
export function _resetLegacyContainmentWarnedForTesting(): void {
    legacyContainmentWarned.clear();
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

  // Consult the version registry once. The verdict carries the canonical
  // value (with renames resolved), the entry's experimental/abstract
  // flags, and version metadata for the deprecation message. The native
  // binary accepts legacy spellings via serde aliases, so the wire
  // payload is forwarded unchanged below — `judge` is purely for SDK-side
  // validation. Without this resolution, legacy values bypass the
  // experimental-mode gate and produce confusing platform errors.
  const rawContainment = config.containment;
  let effectiveContainment: string | undefined = rawContainment;
  let isExperimental = false;
  let isIntent = false;
  if (rawContainment) {
    const verdict = judge(ContainmentRegistry, rawContainment, config.version);
    switch (verdict.kind) {
      case 'ok-deprecated':
        warnLegacyContainmentOnce(rawContainment, verdict);
        effectiveContainment = verdict.canonical;
        isExperimental = !!verdict.entry.experimental;
        isIntent = !!verdict.entry.abstract;
        break;
      case 'ok':
      case 'too-new':
        effectiveContainment = verdict.canonical;
        isExperimental = !!verdict.entry.experimental;
        isIntent = !!verdict.entry.abstract;
        break;
      case 'removed':
        throw new Error(
          `Containment value '${rawContainment}' was removed in schema ${verdict.removedIn}; ` +
          `use '${verdict.canonical}' instead.`
        );
      case 'unknown':
        // Value not in registry; preserve raw and fall back to the
        // static `ContainmentTypes` check + platform-availability gate
        // below. The TS union is still the entry gate for unknown values.
        effectiveContainment = rawContainment;
        isIntent = (ContainmentTypes as readonly string[]).includes(rawContainment);
        break;
    }
  }

  // Check experimental mode before anything else so the caller gets a clear
  // message about the missing flag rather than a platform/binary error.
  if (effectiveContainment && isExperimental && !options.experimental) {
    throw new Error(
      `'${rawContainment}' containment requires experimental mode. Set 'experimental: true' in SandboxSpawnOptions.`
    );
  }

  const platformSupport = getPlatformSupport();
  if (!platformSupport.isSupported && !isExperimental && !options.skipPlatformCheck) {
    throw new Error(`MXC is not supported on this platform: ${platformSupport.reason}`);
  }

  // Hard platform requirement: microvm needs WHP/Hyper-V on Windows. This guard
  // runs even when `skipPlatformCheck` is set because it's not a build-version
  // check — the backend literally cannot run on non-Windows hosts.
  if (effectiveContainment === 'microvm' && os.platform() !== 'win32') {
    throw new Error('The microvm backend is only supported on Windows (requires WHP/Hyper-V).');
  }

  // Validate containment against platform. Abstract intents (process, vm,
  // microvm) are resolved by the native binary at run time, so the SDK
  // accepts them without checking against the host's concrete backend list.
  if (effectiveContainment && !options.skipPlatformCheck) {
    const isAvailable = platformSupport.availableMethods.includes(
      effectiveContainment as ContainmentBackend
    );
    if (!isIntent && !isExperimental && !isAvailable) {
      throw new Error(
        `Containment backend '${rawContainment}' is not available on this platform. ` +
        `Available methods: ${platformSupport.availableMethods.join(', ')}`
      );
    }
  }

  // `network.proxy.builtinTestServer` is testing-only, deliberately-permissive
  // scaffolding that the native binary gates behind `--allow-testing-features`.
  // Mirror that fail-closed posture at the SDK boundary: the caller must opt in
  // explicitly via `allowTestingFeatures` (a distinct axis from `experimental`).
  // Forwarding the flag automatically whenever the policy used the feature would
  // make the gate meaningless — requesting the dangerous feature would silently
  // enable the gate that is supposed to guard it.
  const proxy = config.network?.proxy as { builtinTestServer?: boolean } | undefined;
  const usesBuiltinTestServer = proxy?.builtinTestServer === true;
  if (usesBuiltinTestServer && !options.allowTestingFeatures) {
    throw new Error(
      "network.proxy.builtinTestServer is a testing-only feature. Set " +
      "'allowTestingFeatures: true' in SandboxSpawnOptions to enable it. For " +
      "production, point network.proxy at a real HTTP proxy via 'localhost' or 'url'.",
    );
  }

  const resolved = resolveBinaryAndCommonArgs(JSON.stringify(config), options);
  if (usesBuiltinTestServer) {
    resolved.args.push('--allow-testing-features');
  }
  return resolved;
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
