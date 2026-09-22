// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type { Readable, Writable } from 'node:stream';
import { destroyNativeStream } from './bindings/native-stdio.js';

export interface SandboxWaitResult {
  exitCode: number;
  timedOut: boolean;
}

export interface NativeLifecycleStatus extends SandboxWaitResult {
  running: boolean;
}

export interface NativeLifecycleDriver {
  /** OS process ID for process-based backends; `0` when none is exposed. */
  readonly id: number;
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
  poll(): NativeLifecycleStatus;
  wait(): Promise<SandboxWaitResult>;
  warnings(): readonly string[];
  outputMetadata(): unknown | undefined;
  kill(): void;
  killForTimeout(): void;
  free(): Promise<void>;
}

const POLL_INTERVAL_MS = 100;
type ProcessPhase = 'active' | 'settling' | 'terminal' | 'disposed';

export interface LifecycleScheduler {
  now(): number;
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
}

const defaultScheduler: LifecycleScheduler = {
  now: () => performance.now(),
  schedule: (callback, delayMs) => setTimeout(callback, delayMs),
  cancel: (handle) => clearTimeout(handle as NodeJS.Timeout),
};

type BackgroundErrorReporter = (error: Error) => void;

const defaultBackgroundErrorReporter: BackgroundErrorReporter = (error) => {
  process.emitWarning(
    `native sandbox cleanup failed: ${error.message}`,
    {
      code: 'MXC_NATIVE_CLEANUP_FAILED',
      detail: error.stack,
    },
  );
};

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function isExpectedStdinClosure(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === 'EPIPE' ||
    code === 'ECONNRESET' ||
    code === 'ERR_STREAM_DESTROYED' ||
    code === 'EOF';
}

/**
 * A sandbox process whose stdio is backed by native Node streams.
 *
 * Rust retains lifecycle ownership; Node owns the transferred native stdio
 * endpoints and provides their normal buffering and backpressure.
 *
 * Access each output stream before calling {@link waitAsync}. Waiting drains
 * any untaken output internally, and subsequent access to that stream throws.
 * Output metadata is populated only after terminal settling completes.
 */
export class MxcSandboxProcess {
  /**
   * OS process ID for process-based backends.
   *
   * Returns `0` for backends that do not expose a meaningful host process ID.
   */
  readonly id: number;

  private readonly input: Writable | null;
  private readonly output: Readable | null;
  private readonly errorOutput: Readable | null;
  private inputTaken = false;
  private outputTaken = false;
  private errorTaken = false;
  private outputDrained = false;
  private errorDrained = false;
  private phase: ProcessPhase = 'active';
  private warningsValue: readonly string[];
  private metadataValue: unknown | undefined;
  private resolveWait!: (result: SandboxWaitResult) => void;
  private rejectWait!: (error: Error) => void;
  private readonly waitPromise: Promise<SandboxWaitResult>;
  private pollTimer: unknown;
  private readonly deadline: number | undefined;

  constructor(
    private readonly driver: NativeLifecycleDriver,
    timeoutMs?: number,
    private readonly scheduler: LifecycleScheduler = defaultScheduler,
    private readonly reportBackgroundError: BackgroundErrorReporter =
      defaultBackgroundErrorReporter,
  ) {
    this.id = driver.id;
    this.input = driver.standardInput;
    this.output = driver.standardOutput;
    this.errorOutput = driver.standardError;
    this.warningsValue = driver.warnings();
    this.deadline = timeoutMs !== undefined && timeoutMs > 0
      ? this.scheduler.now() + timeoutMs
      : undefined;
    this.waitPromise = new Promise<SandboxWaitResult>((resolve, reject) => {
      this.resolveWait = resolve;
      this.rejectWait = reject;
    });
    void this.waitPromise.catch(() => {});
    this.input?.on('error', (error) => {
      if (!isExpectedStdinClosure(error)) {
        this.handleStreamError(asError(error));
      }
    });
    this.output?.on('error', (error) => this.handleStreamError(asError(error)));
    this.errorOutput?.on('error', (error) => this.handleStreamError(asError(error)));
    this.poll();
  }

  /**
   * Returns stdin and transfers responsibility for closing it to the caller.
   * Returns `null` when the selected backend does not expose stdin.
   */
  get standardInput(): Writable | null {
    this.throwIfDisposed();
    this.inputTaken = true;
    return this.input;
  }

  /**
   * Returns stdout unless {@link waitAsync} already began draining it
   * internally.
   */
  get standardOutput(): Readable | null {
    this.throwIfDisposed();
    if (this.outputDrained) {
      throw new Error(
        'standard output is unavailable because waitAsync() began draining it; ' +
        'access the stream before awaiting process completion',
      );
    }
    this.outputTaken = true;
    return this.output;
  }

  /**
   * Returns stderr unless {@link waitAsync} already began draining it
   * internally.
   */
  get standardError(): Readable | null {
    this.throwIfDisposed();
    if (this.errorDrained) {
      throw new Error(
        'standard error is unavailable because waitAsync() began draining it; ' +
        'access the stream before awaiting process completion',
      );
    }
    this.errorTaken = true;
    return this.errorOutput;
  }

  /** Warnings collected during spawn and refreshed after terminal settling. */
  get warnings(): readonly string[] {
    return this.warningsValue;
  }

  /** Structured output populated only after terminal settling completes. */
  get outputMetadata(): unknown | undefined {
    return this.metadataValue;
  }

  /**
   * Waits for process completion. Untaken stdin is closed and untaken output
   * streams are drained internally to prevent pipe-buffer deadlocks.
   */
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
    if (this.phase === 'active') this.driver.kill();
  }

  dispose(): void {
    if (this.isDisposed()) return;
    const previousPhase = this.phase;
    this.phase = 'disposed';
    let firstError: Error | undefined;
    if (previousPhase === 'active') {
      try {
        this.driver.kill();
      } catch (error) {
        firstError = asError(error);
      }
    }
    this.stopPolling();
    destroyNativeStream(this.input);
    destroyNativeStream(this.output);
    destroyNativeStream(this.errorOutput);
    if (previousPhase === 'active') {
      void this.cleanupDisposedProcess(firstError === undefined);
    }
    if (previousPhase !== 'terminal') {
      this.rejectWait(new Error('sandbox process was disposed before completion'));
    }
    if (firstError !== undefined) throw firstError;
  }

  private poll(): void {
    if (this.phase !== 'active') return;
    let status: NativeLifecycleStatus;
    try {
      status = this.driver.poll();
    } catch (error) {
      this.fail(asError(error));
      return;
    }
    if (!status.running) {
      this.settle(false);
      return;
    }
    if (this.deadline !== undefined && this.scheduler.now() >= this.deadline) {
      this.finishAfterTimeout();
      return;
    }
    const now = this.scheduler.now();
    const remaining = this.deadline === undefined
      ? undefined
      : Math.max(0, this.deadline - now);
    const delay = remaining === undefined
      ? POLL_INTERVAL_MS
      : Math.min(POLL_INTERVAL_MS, remaining);
    this.pollTimer = this.scheduler.schedule(() => this.poll(), delay);
  }

  private finishAfterTimeout(): void {
    let status: NativeLifecycleStatus;
    try {
      status = this.driver.poll();
    } catch (error) {
      this.fail(asError(error));
      return;
    }
    if (!status.running) {
      this.settle(false);
      return;
    }
    if (!this.beginSettling()) return;
    try {
      this.driver.killForTimeout();
    } catch (killError) {
      try {
        if (!this.driver.poll().running) {
          void this.finalize(true);
          return;
        }
      } catch {
        // Preserve the timeout-kill failure; freeing the handle still kills.
      }
      void this.finalize(undefined, asError(killError));
      return;
    }
    void this.finalize(true);
  }

  private beginSettling(): boolean {
    if (this.phase !== 'active') return false;
    this.phase = 'settling';
    this.stopPolling();
    return true;
  }

  private async finalize(
    timedOut?: boolean,
    initialError?: Error,
  ): Promise<void> {
    let result: SandboxWaitResult | undefined;
    let error = initialError;
    if (error === undefined) {
      try {
        const nativeResult = await this.driver.wait();
        result = {
          exitCode: nativeResult.exitCode,
          timedOut: timedOut === true || nativeResult.timedOut,
        };
      } catch (cause) {
        error = asError(cause);
      }
    }
    try {
      this.warningsValue = this.driver.warnings();
    } catch (cause) {
      error ??= asError(cause);
    }
    try {
      this.metadataValue = this.driver.outputMetadata();
    } catch (cause) {
      error ??= asError(cause);
    }

    try {
      await this.driver.free();
    } catch (cause) {
      error ??= asError(cause);
    }

    if (this.isDisposed()) return;
    this.phase = 'terminal';
    if (error !== undefined) {
      this.rejectWait(error);
    } else {
      this.resolveWait(result!);
    }
  }

  private stopPolling(): void {
    if (this.pollTimer !== undefined) {
      this.scheduler.cancel(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  private async cleanupDisposedProcess(waitForExit: boolean): Promise<void> {
    if (waitForExit) {
      try {
        await this.driver.wait();
      } catch {
        // Freeing the handle still performs final process-tree cleanup.
      }
    }
    try {
      await this.driver.free();
    } catch (error) {
      try {
        this.reportBackgroundError(asError(error));
      } catch {
        // Diagnostics must not make synchronous disposal fail later.
      }
    }
  }

  private isDisposed(): boolean {
    return this.phase === 'disposed';
  }

  private handleStreamError(error: Error): void {
    this.fail(error);
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
    if (this.phase === 'disposed') {
      throw new Error('sandbox process has been disposed');
    }
  }

  private settle(timedOut: boolean): void {
    if (this.beginSettling()) {
      void this.finalize(timedOut);
    }
  }

  private fail(error: Error): void {
    if (this.beginSettling()) {
      void this.finalize(undefined, error);
    }
  }
}
