// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable, Writable } from 'node:stream';

export interface SandboxWaitResult {
  exitCode: number;
  timedOut: boolean;
}

export interface NativeLifecycleStatus extends SandboxWaitResult {
  running: boolean;
}

export interface NativeLifecycleDriver {
  readonly id: number;
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
  poll(): NativeLifecycleStatus;
  wait(): Promise<SandboxWaitResult>;
  warnings(): readonly string[];
  outputMetadata(): unknown | undefined;
  kill(): void;
  free(): Promise<void>;
}

const POLL_INTERVAL_MS = 10;

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function isExpectedStdinClosure(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === 'EPIPE' ||
    code === 'ECONNRESET' ||
    code === 'ERR_STREAM_DESTROYED';
}

function destroyStream(stream: Readable | Writable | null): void {
  if (stream !== null && !stream.destroyed) stream.destroy();
}

/**
 * A sandbox process whose stdio is backed by native Node streams.
 *
 * Rust retains lifecycle ownership; Node owns the transferred stdio
 * descriptors and provides their normal buffering and backpressure.
 */
export class MxcSandboxProcess {
  readonly id: number;

  private readonly input: Writable | null;
  private readonly output: Readable | null;
  private readonly errorOutput: Readable | null;
  private inputTaken = false;
  private outputTaken = false;
  private errorTaken = false;
  private outputDrained = false;
  private errorDrained = false;
  private disposed = false;
  private terminal = false;
  private cleanupStarted = false;
  private warningsValue: readonly string[];
  private metadataValue: unknown | undefined;
  private readonly cleanups: Array<() => void> = [];
  private resolveWait!: (result: SandboxWaitResult) => void;
  private rejectWait!: (error: Error) => void;
  private readonly waitPromise: Promise<SandboxWaitResult>;
  private pollTimer: NodeJS.Timeout | undefined;
  private readonly deadline: number | undefined;

  private constructor(
    private readonly driver: NativeLifecycleDriver,
    timeoutMs?: number,
  ) {
    this.id = driver.id;
    this.input = driver.standardInput;
    this.output = driver.standardOutput;
    this.errorOutput = driver.standardError;
    this.warningsValue = driver.warnings();
    this.deadline = timeoutMs !== undefined && timeoutMs > 0
      ? performance.now() + timeoutMs
      : undefined;
    this.waitPromise = new Promise<SandboxWaitResult>((resolve, reject) => {
      this.resolveWait = resolve;
      this.rejectWait = reject;
    });
    void this.waitPromise.catch(() => {});
    this.input?.on('error', (error) => {
      if (!isExpectedStdinClosure(error)) {
        void this.finish(undefined, asError(error));
      }
    });
    this.output?.on('error', (error) => void this.finish(undefined, asError(error)));
    this.errorOutput?.on('error', (error) => void this.finish(undefined, asError(error)));
    this.poll();
  }

  static create(
    driver: NativeLifecycleDriver,
    timeoutMs?: number,
  ): MxcSandboxProcess {
    return new MxcSandboxProcess(driver, timeoutMs);
  }

  get standardInput(): Writable | null {
    this.throwIfDisposed();
    this.inputTaken = true;
    return this.input;
  }

  get standardOutput(): Readable | null {
    this.throwIfDisposed();
    if (this.outputDrained) {
      throw new Error('standard output is being drained internally');
    }
    this.outputTaken = true;
    return this.output;
  }

  get standardError(): Readable | null {
    this.throwIfDisposed();
    if (this.errorDrained) {
      throw new Error('standard error is being drained internally');
    }
    this.errorTaken = true;
    return this.errorOutput;
  }

  get warnings(): readonly string[] {
    return this.warningsValue;
  }

  get outputMetadata(): unknown | undefined {
    return this.metadataValue;
  }

  waitAsync(): Promise<SandboxWaitResult> {
    this.throwIfDisposed();
    if (!this.inputTaken && this.input !== null && !this.input.destroyed) {
      this.input.end();
    }
    if (!this.outputTaken) this.drainOutput();
    if (!this.errorTaken) this.drainError();
    return this.waitPromise;
  }

  kill(): void {
    this.throwIfDisposed();
    if (!this.terminal) this.driver.kill();
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    let firstError: Error | undefined;
    if (!this.terminal) {
      try {
        this.driver.kill();
      } catch (error) {
        firstError = asError(error);
      }
    }
    this.stopPolling();
    destroyStream(this.input);
    destroyStream(this.output);
    destroyStream(this.errorOutput);
    const cleanupError = this.runCleanups();
    firstError ??= cleanupError;
    void this.driver.free().catch(() => {});
    if (!this.terminal) {
      this.terminal = true;
      this.rejectWait(new Error('sandbox process was disposed before completion'));
    }
    if (firstError !== undefined) throw firstError;
  }

  /** @internal Registers state-aware cleanup tied to process completion. */
  _registerCleanup(cleanup: () => void): void {
    if (this.cleanupStarted) {
      cleanup();
      return;
    }
    this.cleanups.push(cleanup);
  }

  private poll(): void {
    if (this.disposed || this.terminal) return;
    let status: NativeLifecycleStatus;
    try {
      status = this.driver.poll();
    } catch (error) {
      void this.finish(undefined, asError(error));
      return;
    }
    if (!status.running) {
      this.finishAfterWait();
      return;
    }
    if (this.deadline !== undefined && performance.now() >= this.deadline) {
      this.finishAfterTimeout();
      return;
    }
    this.pollTimer = setTimeout(() => this.poll(), POLL_INTERVAL_MS);
  }

  private finishAfterWait(): void {
    void this.waitForTerminalResult(false);
  }

  private finishAfterTimeout(): void {
    try {
      const status = this.driver.poll();
      if (!status.running) {
        void this.waitForTerminalResult(false);
        return;
      }
      this.driver.kill();
      void this.waitForTerminalResult(true);
    } catch (error) {
      void this.finish(undefined, asError(error));
    }
  }

  private async waitForTerminalResult(timedOut: boolean): Promise<void> {
    try {
      const result = await this.driver.wait();
      await this.finish({
        exitCode: result.exitCode,
        timedOut: timedOut || result.timedOut,
      });
    } catch (error) {
      await this.finish(undefined, asError(error));
    }
  }

  private async finish(
    result: SandboxWaitResult | undefined,
    initialError?: Error,
  ): Promise<void> {
    if (this.terminal) return;
    this.terminal = true;
    this.stopPolling();

    let error = initialError;
    if (error === undefined) {
      try {
        this.warningsValue = this.driver.warnings();
        this.metadataValue = this.driver.outputMetadata();
      } catch (cause) {
        error = asError(cause);
      }
    }
    const cleanupError = this.runCleanups();
    error ??= cleanupError;

    try {
      await this.driver.free();
    } catch (cause) {
      error ??= asError(cause);
    }

    if (error !== undefined) {
      this.rejectWait(error);
    } else {
      this.resolveWait(result!);
    }
  }

  private runCleanups(): Error | undefined {
    if (this.cleanupStarted) return undefined;
    this.cleanupStarted = true;
    let firstError: Error | undefined;
    while (this.cleanups.length > 0) {
      const cleanup = this.cleanups.shift()!;
      try {
        cleanup();
      } catch (error) {
        firstError ??= asError(error);
      }
    }
    return firstError;
  }

  private stopPolling(): void {
    if (this.pollTimer !== undefined) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  private drainOutput(): void {
    this.outputDrained = true;
    this.output?.resume();
  }

  private drainError(): void {
    this.errorDrained = true;
    this.errorOutput?.resume();
  }

  private throwIfDisposed(): void {
    if (this.disposed) throw new Error('sandbox process has been disposed');
  }
}

/** @internal Creates a process around a test or native lifecycle driver. */
export function _createMxcSandboxProcess(
  driver: NativeLifecycleDriver,
  timeoutMs?: number,
): MxcSandboxProcess {
  return MxcSandboxProcess.create(driver, timeoutMs);
}
