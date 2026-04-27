// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as os from 'os';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { FileLogger } from './logger';
import { ContainerConfig } from './types';
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
 * Sets up logging and resolves the executable path + args.
 * Shared by both PTY and non-PTY spawn paths.
 *
 * @param config - The container configuration
 * @param options - Spawn options (debug, logDir, etc.)
 * @param resolveExecutableAndArgs - Function to resolve the binary path and build CLI args
 */
export function prepareSpawn(
  config: ContainerConfig,
  options: SandboxSpawnOptions,
  resolveExecutableAndArgs: (config: ContainerConfig, options: SandboxSpawnOptions) => { executablePath: string; args: string[] },
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

  const { executablePath, args } = resolveExecutableAndArgs(config, options);

  logger?.log('info', 'mxc.binary.resolved', { resolved: !!executablePath });

  return { executablePath, args, logger, logFile, startTime };
}
