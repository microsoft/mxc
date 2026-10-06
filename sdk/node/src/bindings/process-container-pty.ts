// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import type {
  IDisposable,
  IPty,
} from 'node-pty';
import type { OneShotRequest } from '../generated/v1_0_0/wire.js';
import {
  MxcProcess,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
  type WaitResult,
} from '../v1/container-process.js';
import {
  MxcError,
  type ErrorCode,
} from '../v1/errors.js';
import { MxcPtyProcess } from '../v1/mxc-pty-process.js';
import { findWxcExecutable } from '../v1/platform.js';
import type { ExecutionMetadata } from '../v1/types.js';
import {
  parseExecutionMetadata,
  parseStringArray,
} from './native-error.js';

interface ProcessContainerPtyDependencies {
  loadNodePty: () => Promise<typeof import('node-pty')>;
  findExecutable: typeof findWxcExecutable;
  platform: () => NodeJS.Platform;
}

const defaultDependencies: ProcessContainerPtyDependencies = {
  loadNodePty: () => import('node-pty'),
  findExecutable: findWxcExecutable,
  platform: () => process.platform,
};

let dependencies = defaultDependencies;

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

interface WxcPtyResult {
  exitCode: number;
  timedOut: boolean;
  warnings: string[];
  outputMetadata?: ExecutionMetadata;
  errorCode: ErrorCode;
  errorMessage: string;
  extendedError: string;
  failurePhase: string;
}

const errorCodes = new Set<ErrorCode>([
  'malformed_request',
  'unsupported_containment',
  'unsupported_phase',
  'backend_unavailable',
  'malformed_id',
  'stale_id',
  'not_provisioned',
  'not_started',
  'already_started',
  'already_stopped',
  'policy_validation',
  'backend_error',
]);

function parseWxcPtyResult(resultFile: string): WxcPtyResult {
  const value: unknown = JSON.parse(readFileSync(resultFile, 'utf8'));
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('result must be a JSON object');
  }

  const result = value as Record<string, unknown>;
  if (!Number.isInteger(result.exitCode)) {
    throw new Error('result.exitCode must be an integer');
  }
  if (typeof result.timedOut !== 'boolean') {
    throw new Error('result.timedOut must be a boolean');
  }
  if (
    typeof result.errorCode !== 'string'
    || !errorCodes.has(result.errorCode as ErrorCode)
    || typeof result.errorMessage !== 'string'
    || typeof result.extendedError !== 'string'
    || typeof result.failurePhase !== 'string'
  ) {
    throw new Error('result error fields are invalid');
  }

  return {
    exitCode: result.exitCode as number,
    timedOut: result.timedOut,
    warnings: parseStringArray(
      JSON.stringify(result.warnings),
      'wxc-exec returned malformed ProcessContainer PTY warnings',
    ),
    outputMetadata: result.outputMetadata === null
      ? undefined
      : parseExecutionMetadata(JSON.stringify(result.outputMetadata)),
    errorCode: result.errorCode as ErrorCode,
    errorMessage: result.errorMessage,
    extendedError: result.extendedError,
    failurePhase: result.failurePhase,
  };
}

function resultError(result: WxcPtyResult): MxcError | undefined {
  if (!result.errorMessage || result.timedOut) {
    return undefined;
  }

  return new MxcError({
    code: result.errorCode,
    message: result.extendedError
      ? `${result.errorMessage}: ${result.extendedError}`
      : result.errorMessage,
    details: { failurePhase: result.failurePhase },
  });
}

class NodePtyLifecycleDriver implements NativeLifecycleDriver {
  readonly id = 0;
  readonly standardInput: Writable;
  readonly standardOutput = new PassThrough();
  readonly standardError = null;

  private status: NativeLifecycleStatus = {
    exitCode: 0,
    running: true,
    timedOut: false,
  };
  private readonly exitPromise: Promise<WaitResult>;
  private readonly dataSubscription: IDisposable;
  private readonly exitSubscription: IDisposable;
  private resolveExit!: (result: WaitResult) => void;
  private rejectExit!: (error: Error) => void;
  private warningsValue: readonly string[] = [];
  private outputMetadataValue: ExecutionMetadata | undefined;
  private killRequested = false;

  constructor(
    private readonly pty: IPty,
    private readonly resultDirectory: string,
    private readonly resultFile: string,
  ) {
    this.standardInput = new Writable({
      write: (chunk: Buffer, _encoding, callback) => {
        try {
          this.pty.write(chunk);
          callback();
        } catch (error) {
          callback(asError(error));
        }
      },
    });
    this.exitPromise = new Promise<WaitResult>((resolve, reject) => {
      this.resolveExit = resolve;
      this.rejectExit = reject;
    });
    void this.exitPromise.catch(() => {});
    this.dataSubscription = pty.onData((data) => {
      if (!this.standardOutput.write(data)) {
        this.pty.pause();
      }
    });
    this.standardOutput.on('drain', () => {
      if (this.status.running) {
        this.pty.resume();
      }
    });
    this.exitSubscription = pty.onExit(({ exitCode }) => {
      if (!this.status.running) return;
      try {
        const result = parseWxcPtyResult(this.resultFile);
        this.status = {
          exitCode: result.exitCode,
          running: false,
          timedOut: result.timedOut,
        };
        this.warningsValue = result.warnings;
        this.outputMetadataValue = result.outputMetadata;
        this.standardOutput.end();
        const error = resultError(result);
        if (error === undefined) {
          this.resolveExit({
            exitCode: result.exitCode,
            timedOut: result.timedOut,
          });
        } else {
          this.rejectExit(error);
        }
      } catch (error) {
        this.status = {
          exitCode,
          running: false,
          timedOut: false,
        };
        this.standardOutput.end();
        if (this.killRequested) {
          this.resolveExit({ exitCode, timedOut: false });
        } else {
          this.rejectExit(new MxcError({
            code: 'backend_error',
            message: 'wxc-exec did not produce a valid ProcessContainer PTY result',
            details: { cause: asError(error).message },
          }));
        }
      }
    });
  }

  poll(): NativeLifecycleStatus {
    return { ...this.status };
  }

  wait(): Promise<WaitResult> {
    return this.exitPromise;
  }

  warnings(): readonly string[] {
    return this.warningsValue;
  }

  outputMetadata(): ExecutionMetadata | undefined {
    return this.outputMetadataValue;
  }

  kill(): void {
    if (this.status.running) {
      this.killRequested = true;
      this.pty.kill();
    }
  }

  killForTimeout(): void {
    this.kill();
  }

  async free(): Promise<void> {
    this.dataSubscription.dispose();
    this.exitSubscription.dispose();
    if (!this.standardInput.destroyed) {
      this.standardInput.end();
    }
    if (!this.standardOutput.destroyed && !this.standardOutput.readableEnded) {
      this.standardOutput.end();
    }
    rmSync(this.resultDirectory, { recursive: true, force: true });
  }
}

/** @internal Creates the public process wrapper around a node-pty handle. */
export function createNodePtyProcess(
  pty: IPty,
  resultDirectory: string,
  resultFile: string,
): MxcPtyProcess {
  const driver = new NodePtyLifecycleDriver(
    pty,
    resultDirectory,
    resultFile,
  );
  return new MxcPtyProcess(
    driver,
    ({ rows, columns }) => pty.resize(columns, rows),
  );
}

export function isProcessContainerExecutablePtySupported(): boolean {
  return dependencies.platform() === 'win32';
}

// Work around the in-process PTY binding's lack of ProcessContainer support by
// launching the same exact one-shot request through wxc-exec under node-pty.
async function spawnWithWxcExecutablePty(
  request: OneShotRequest,
  experimental: boolean,
  rows: number,
  columns: number,
): Promise<MxcPtyProcess> {
  const executable = dependencies.findExecutable();
  if (executable === null) {
    throw new MxcError({
      code: 'backend_error',
      message: 'wxc-exec.exe was not found for ProcessContainer PTY execution',
      remediation: 'Install the MXC native binaries or set MXC_BIN_DIR.',
    });
  }

  const requestJson = JSON.stringify(request);
  const resultDirectory = mkdtempSync(join(tmpdir(), 'mxc-node-pty-'));
  const resultFile = join(resultDirectory, 'result.json');
  const args = [
    '--config-base64',
    Buffer.from(requestJson, 'utf8').toString('base64'),
    '--sdk-result-file',
    resultFile,
  ];
  if (experimental) {
    args.push('--experimental');
  }

  let pty: IPty | undefined;
  try {
    const nodePty = await dependencies.loadNodePty();
    pty = nodePty.spawn(executable, args, {
      name: 'xterm-256color',
      cols: columns,
      rows,
      cwd: process.cwd(),
      env: process.env,
      useConpty: true,
    });
    return createNodePtyProcess(pty, resultDirectory, resultFile);
  } catch (error) {
    if (pty !== undefined) {
      try {
        pty.kill();
      } catch {
        // Preserve the original construction failure.
      }
    }
    rmSync(resultDirectory, { recursive: true, force: true });
    throw new MxcError(
      'backend_error',
      `failed to launch ProcessContainer PTY: ${asError(error).message}`,
    );
  }
}

type SpawnExecutablePtyImplementation = typeof spawnWithWxcExecutablePty;

let implementation = spawnWithWxcExecutablePty;

/** @internal Replaces node-pty dependencies for unit tests. */
export function _setProcessContainerPtyDependencies(
  overrides?: Partial<ProcessContainerPtyDependencies>,
): void {
  dependencies = overrides === undefined
    ? defaultDependencies
    : { ...defaultDependencies, ...overrides };
}

/** @internal Replaces ProcessContainer PTY creation for unit tests. */
export function _setSpawnProcessContainerWithPtyImplementation(
  replacement?: SpawnExecutablePtyImplementation,
): void {
  implementation = replacement ?? spawnWithWxcExecutablePty;
}

export function spawnProcessContainerWithPty(
  request: OneShotRequest,
  experimental: boolean,
  rows: number,
  columns: number,
): Promise<MxcPtyProcess> {
  return implementation(request, experimental, rows, columns);
}
