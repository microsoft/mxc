// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { FileLogger } from './logger';
import { ContainerConfig, ContainmentType, ExperimentalBackends, SandboxingMethod } from './types';
import { findWxcExecutable, findLxcExecutable, getPlatformSupport } from './platform';
import { SandboxSpawnOptions } from './sandbox';

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
 * Resolves the executable path and builds CLI arguments for a sandbox invocation.
 * Shared setup used by both PTY and non-PTY spawn paths.
 */
export function resolveExecutableAndArgs(
  config: ContainerConfig,
  options: SandboxSpawnOptions = {},
): { executablePath: string; args: string[] } {
  if (!config.process?.commandLine) {
    throw new Error('script is required. Set process.commandLine on the config or pass a script to spawnSandbox().');
  }

  const platformSupport = getPlatformSupport();
  // Experimental backends (microvm, wslc) have their own platform validation below,
  // so they bypass the general platform support check.
  const isExperimental = config.containment &&
    (ExperimentalBackends as readonly string[]).includes(config.containment);
  if (!platformSupport.isSupported && !isExperimental) {
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
