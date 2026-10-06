// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
import { MxcError } from '../v1/errors.js';
import { MxcPtyProcess } from '../v1/mxc-pty-process.js';
import { findWxcExecutable } from '../v1/platform.js';
import type { ExecutionMetadata } from '../v1/types.js';

interface ProcessContainerPtyDependencies {
  loadNodePty: () => Promise<typeof import('node-pty')>;
  findExecutable: typeof findWxcExecutable;
}

const defaultDependencies: ProcessContainerPtyDependencies = {
  loadNodePty: () => import('node-pty'),
  findExecutable: findWxcExecutable,
};

let dependencies = defaultDependencies;

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

class NodePtyLifecycleDriver implements NativeLifecycleDriver {
  readonly id: number;
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

  constructor(private readonly pty: IPty) {
    this.id = pty.pid;
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
    this.exitPromise = new Promise<WaitResult>((resolve) => {
      this.resolveExit = resolve;
    });
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
      this.status = {
        exitCode,
        running: false,
        timedOut: false,
      };
      this.standardOutput.end();
      this.resolveExit({ exitCode, timedOut: false });
    });
  }

  poll(): NativeLifecycleStatus {
    return { ...this.status };
  }

  wait(): Promise<WaitResult> {
    return this.exitPromise;
  }

  warnings(): readonly string[] {
    // The legacy executor-backed IPty contract merges diagnostics into output.
    return [];
  }

  outputMetadata(): ExecutionMetadata | undefined {
    return undefined;
  }

  kill(): void {
    if (this.status.running) {
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
  }
}

/** @internal Creates the public process wrapper around a node-pty handle. */
export function createNodePtyProcess(
  pty: IPty,
): MxcPtyProcess {
  const driver = new NodePtyLifecycleDriver(pty);
  return new MxcPtyProcess(
    driver,
    ({ rows, columns }) => pty.resize(columns, rows),
  );
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
  const args = [
    '--config-base64',
    Buffer.from(requestJson, 'utf8').toString('base64'),
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
    return createNodePtyProcess(pty);
  } catch (error) {
    if (pty !== undefined) {
      try {
        pty.kill();
      } catch {
        // Preserve the original construction failure.
      }
    }
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
