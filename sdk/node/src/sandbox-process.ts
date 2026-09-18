// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Readable, Writable } from 'node:stream';

export interface SandboxWaitResult {
  exitCode: number;
  timedOut: boolean;
}

export type NativeStreamingEvent =
  | { type: 'stdout'; data: Buffer }
  | { type: 'stderr'; data: Buffer }
  | { type: 'stdout-eof' }
  | { type: 'stderr-eof' }
  | { type: 'stdin-complete'; operation: number; written: number; succeeded: boolean }
  | { type: 'exit'; result: SandboxWaitResult }
  | { type: 'error'; error: Error }
  | { type: 'shutdown' };

export interface NativeStreamingDriver {
  readonly id: number;
  readonly hasStdin: boolean;
  readonly hasStdout: boolean;
  readonly hasStderr: boolean;
  setEventHandler(handler: (event: NativeStreamingEvent) => void): void;
  warnings(): readonly string[];
  outputMetadata(): unknown | undefined;
  requestRead(stream: 'stdout' | 'stderr'): void;
  startWrite(buffer: Buffer): number;
  startFlush(): number;
  closeStdin(): void;
  closeOutput(stream: 'stdout' | 'stderr'): void;
  kill(): void;
  shutdown(): void;
}

const OUTPUT_DRAIN_GRACE_MS = 250;
const MIN_RETRY_MS = 1;
const MAX_RETRY_MS = 25;
const MAX_WRITE_CHUNK = 64 * 1024;

class NativeReadable extends Readable {
  private requested = false;
  private ended = false;
  private completed = false;
  private activityVersion = 0;
  private readonly completedPromise: Promise<void>;
  private complete!: () => void;

  constructor(
    private readonly driver: NativeStreamingDriver,
    private readonly stream: 'stdout' | 'stderr',
  ) {
    super({ autoDestroy: true });
    this.on('error', () => {});
    this.completedPromise = new Promise((resolve) => {
      this.complete = resolve;
    });
    this.once('end', () => this.finish());
    this.once('close', () => this.finish());
  }

  get completion(): Promise<void> {
    return this.completedPromise;
  }

  get activity(): number {
    return this.activityVersion;
  }

  override _read(): void {
    if (this.requested || this.ended || this.destroyed) return;
    this.requested = true;
    try {
      this.driver.requestRead(this.stream);
    } catch (error) {
      this.requested = false;
      this.destroy(error as Error);
    }
  }

  deliver(data: Buffer): void {
    if (this.ended || this.destroyed) return;
    this.requested = false;
    this.activityVersion += 1;
    this.push(data);
  }

  endNative(): void {
    if (this.ended || this.destroyed) return;
    this.requested = false;
    this.ended = true;
    this.activityVersion += 1;
    this.push(null);
  }

  override _destroy(
    error: Error | null,
    callback: (error?: Error | null) => void,
  ): void {
    this.ended = true;
    try {
      this.driver.closeOutput(this.stream);
    } catch (closeError) {
      error ??= closeError as Error;
    }
    this.finish();
    callback(error);
  }

  private finish(): void {
    if (this.completed) return;
    this.completed = true;
    this.complete();
  }
}

type WriteCompletion = (error?: Error | null) => void;
type NativeCompletion = (error: Error | undefined, written: number) => void;

class NativeWritable extends Writable {
  private readonly pending = new Map<number, NativeCompletion>();
  private closedNative = false;

  constructor(private readonly driver: NativeStreamingDriver) {
    super({ autoDestroy: true });
    this.on('error', () => {});
  }

  override _write(
    chunk: string | Buffer,
    encoding: BufferEncoding,
    callback: WriteCompletion,
  ): void {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    if (buffer.length === 0) {
      callback();
      return;
    }
    this.writeChunk(buffer, 0, callback);
  }

  override _final(callback: WriteCompletion): void {
    this.enqueue(() => this.driver.startFlush(), (error) => {
      this.closeNative();
      callback(error);
    });
  }

  complete(operation: number, written: number, succeeded: boolean): void {
    const callback = this.pending.get(operation);
    if (callback === undefined) return;
    this.pending.delete(operation);
    callback(
      succeeded ? undefined : new Error('sandbox stdin operation failed'),
      written,
    );
  }

  fail(error: Error): void {
    for (const callback of this.pending.values()) callback(error, 0);
    this.pending.clear();
    this.destroy(error);
  }

  override _destroy(
    error: Error | null,
    callback: (error?: Error | null) => void,
  ): void {
    this.closeNative();
    for (const pending of this.pending.values()) {
      pending(
        error ?? new Error('sandbox stdin closed before the write completed'),
        0,
      );
    }
    this.pending.clear();
    callback(error);
  }

  private writeChunk(
    buffer: Buffer,
    offset: number,
    callback: WriteCompletion,
  ): void {
    if (offset >= buffer.length) {
      callback();
      return;
    }
    const chunk = buffer.subarray(offset, offset + MAX_WRITE_CHUNK);
    this.enqueue(() => this.driver.startWrite(chunk), (error, written) => {
      if (error !== undefined) {
        callback(error);
      } else if (written <= 0) {
        callback(new Error('sandbox stdin accepted no bytes'));
      } else {
        this.writeChunk(buffer, offset + written, callback);
      }
    });
  }

  private enqueue(start: () => number, callback: NativeCompletion): void {
    let delayMs = MIN_RETRY_MS;
    const attempt = () => {
      if (this.destroyed || this.closedNative) {
        callback(new Error('sandbox stdin is closed'), 0);
        return;
      }
      try {
        const operation = start();
        if (operation === 0) {
          setTimeout(attempt, delayMs);
          delayMs = Math.min(delayMs * 2, MAX_RETRY_MS);
        } else {
          this.pending.set(operation, callback);
        }
      } catch (error) {
        callback(error as Error, 0);
      }
    };
    attempt();
  }

  private closeNative(): void {
    if (this.closedNative) return;
    this.closedNative = true;
    this.driver.closeStdin();
  }
}

type ReadState = 'untaken' | 'owned' | 'draining' | 'missing';

/** Internal live process returned by the native Node binding. */
export class MxcSandboxProcess {
  private warningsValue: readonly string[];
  private outputMetadataValue?: unknown;
  private outputMetadataReady = false;
  private stdinValue?: NativeWritable | null;
  private stdinTaken = false;
  private stdoutValue?: NativeReadable | null;
  private stdoutState: ReadState = 'untaken';
  private stderrValue?: NativeReadable | null;
  private stderrState: ReadState = 'untaken';
  private waitPromise?: Promise<SandboxWaitResult>;
  private waitResolve?: (result: SandboxWaitResult) => void;
  private waitReject?: (error: Error) => void;
  private nativeExitResult?: SandboxWaitResult;
  private failure?: Error;
  private waitResult?: SandboxWaitResult;
  private readonly cleanupCallbacks = new Set<() => void>();
  private disposed = false;
  private finalizing = false;
  private shutdownRequested = false;

  private constructor(private readonly driver: NativeStreamingDriver) {
    this.warningsValue = driver.warnings();
    driver.setEventHandler((event) => this.onNativeEvent(event));
  }

  /** @internal */
  static create(driver: NativeStreamingDriver): MxcSandboxProcess {
    try {
      return new MxcSandboxProcess(driver);
    } catch (error) {
      driver.shutdown();
      throw error;
    }
  }

  get id(): number {
    return this.driver.id;
  }

  get warnings(): readonly string[] {
    return this.warningsValue;
  }

  get standardInput(): Writable | null {
    this.ensureAvailable('standard input');
    if (this.stdinTaken) return this.stdinValue ?? null;
    this.stdinTaken = true;
    this.stdinValue = this.driver.hasStdin
      ? new NativeWritable(this.driver)
      : null;
    return this.stdinValue;
  }

  get standardOutput(): Readable | null {
    return this.takeReadable('stdout');
  }

  get standardError(): Readable | null {
    return this.takeReadable('stderr');
  }

  get outputMetadata(): unknown | undefined {
    return this.outputMetadataReady ? this.outputMetadataValue : undefined;
  }

  waitAsync(): Promise<SandboxWaitResult> {
    if (this.failure !== undefined) return Promise.reject(this.failure);
    if (this.waitResult !== undefined) return Promise.resolve(this.waitResult);
    if (this.disposed) return Promise.reject(new Error('sandbox process disposed'));
    if (this.waitPromise !== undefined) return this.waitPromise;

    this.closeUntakenStdin();
    this.ensureDrain('stdout');
    this.ensureDrain('stderr');
    this.waitPromise = new Promise((resolve, reject) => {
      this.waitResolve = resolve;
      this.waitReject = reject;
    });
    if (this.nativeExitResult !== undefined) {
      void this.finishWait(this.nativeExitResult);
    }
    return this.waitPromise;
  }

  kill(): void {
    this.ensureAvailable('process');
    this.driver.kill();
  }

  /** @internal Register cleanup tied to terminal completion or disposal. */
  _registerCleanup(callback: () => void): void {
    if (this.disposed || this.waitResult !== undefined) {
      callback();
      return;
    }
    this.cleanupCallbacks.add(callback);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.waitReject?.(new Error('sandbox process disposed'));
    this.waitReject = undefined;
    this.stdinValue?.destroy();
    this.stdoutValue?.destroy();
    this.stderrValue?.destroy();
    this.runCleanups();
    this.shutdown();
  }

  private onNativeEvent(event: NativeStreamingEvent): void {
    if (event.type === 'shutdown') return;
    if (this.disposed && event.type !== 'error') return;
    switch (event.type) {
      case 'stdout':
        this.stdoutValue?.deliver(event.data);
        break;
      case 'stderr':
        this.stderrValue?.deliver(event.data);
        break;
      case 'stdout-eof':
        this.stdoutValue?.endNative();
        break;
      case 'stderr-eof':
        this.stderrValue?.endNative();
        break;
      case 'stdin-complete':
        this.stdinValue?.complete(
          event.operation,
          event.written,
          event.succeeded,
        );
        break;
      case 'exit':
        this.nativeExitResult = event.result;
        if (this.waitPromise !== undefined) void this.finishWait(event.result);
        break;
      case 'error':
        this.fail(event.error);
        break;
    }
  }

  private async finishWait(result: SandboxWaitResult): Promise<void> {
    if (this.finalizing || this.waitResult !== undefined) return;
    this.finalizing = true;
    try {
      await this.finishOutputStreams();
      this.stdinValue?.destroy();
      if (this.disposed || this.failure !== undefined) return;
      this.outputMetadataValue = this.driver.outputMetadata();
      this.outputMetadataReady = true;
      this.warningsValue = this.driver.warnings();
      this.waitResult = result;
      this.waitResolve?.(result);
    } catch (error) {
      this.fail(error as Error);
    } finally {
      this.waitResolve = undefined;
      this.waitReject = undefined;
      this.finalizing = false;
      this.runCleanups();
      this.shutdown();
    }
  }

  private fail(error: Error): void {
    if (this.failure !== undefined) return;
    this.failure = error;
    this.stdinValue?.fail(error);
    this.stdoutValue?.destroy(error);
    this.stderrValue?.destroy(error);
    this.waitReject?.(error);
    this.waitReject = undefined;
    this.runCleanups();
    this.shutdown();
  }

  private closeUntakenStdin(): void {
    if (this.stdinTaken) return;
    this.stdinTaken = true;
    this.stdinValue = null;
    if (this.driver.hasStdin) this.driver.closeStdin();
  }

  private takeReadable(which: 'stdout' | 'stderr'): Readable | null {
    const state = which === 'stdout' ? this.stdoutState : this.stderrState;
    const existing = which === 'stdout' ? this.stdoutValue : this.stderrValue;
    if (state === 'owned') return existing ?? null;
    if (state === 'missing') return null;
    if (state === 'draining') {
      throw new Error(`sandbox ${which} is being drained internally by waitAsync()`);
    }
    this.ensureAvailable(which);
    const available = which === 'stdout'
      ? this.driver.hasStdout
      : this.driver.hasStderr;
    const stream = available ? new NativeReadable(this.driver, which) : null;
    this.setReadable(which, stream === null ? 'missing' : 'owned', stream);
    return stream;
  }

  private ensureDrain(which: 'stdout' | 'stderr'): void {
    const state = which === 'stdout' ? this.stdoutState : this.stderrState;
    if (state !== 'untaken') return;
    const available = which === 'stdout'
      ? this.driver.hasStdout
      : this.driver.hasStderr;
    if (!available) {
      this.setReadable(which, 'missing', null);
      return;
    }
    const stream = new NativeReadable(this.driver, which);
    stream.on('error', () => {});
    stream.resume();
    this.setReadable(which, 'draining', stream);
  }

  private setReadable(
    which: 'stdout' | 'stderr',
    state: ReadState,
    stream: NativeReadable | null,
  ): void {
    if (which === 'stdout') {
      this.stdoutState = state;
      this.stdoutValue = stream;
    } else {
      this.stderrState = state;
      this.stderrValue = stream;
    }
  }

  private async finishOutputStreams(): Promise<void> {
    const streams = [this.stdoutValue, this.stderrValue].filter(
      (stream): stream is NativeReadable => stream !== null && stream !== undefined,
    );
    await Promise.all(streams.map((stream) => this.finishOutputStream(stream)));
  }

  private async finishOutputStream(stream: NativeReadable): Promise<void> {
    for (;;) {
      const activity = stream.activity;
      let timer: NodeJS.Timeout | undefined;
      const completed = await Promise.race([
        stream.completion.then(() => true),
        new Promise<false>((resolve) => {
          timer = setTimeout(() => resolve(false), OUTPUT_DRAIN_GRACE_MS);
        }),
      ]);
      if (timer !== undefined) clearTimeout(timer);
      if (completed) return;
      if (stream.activity !== activity) continue;
      stream.destroy();
      await stream.completion;
      return;
    }
  }

  private shutdown(): void {
    if (this.shutdownRequested) return;
    this.shutdownRequested = true;
    this.driver.shutdown();
  }

  private runCleanups(): void {
    for (const callback of this.cleanupCallbacks) callback();
    this.cleanupCallbacks.clear();
  }

  private ensureAvailable(stream: string): void {
    if (this.disposed) throw new Error('sandbox process disposed');
    if (this.finalizing) {
      throw new Error(`sandbox ${stream} is unavailable while terminal completion is finalizing`);
    }
    if (this.shutdownRequested || this.waitResult !== undefined) {
      throw new Error(`sandbox ${stream} is unavailable after terminal completion`);
    }
  }
}

export function _createMxcSandboxProcess(
  driver: NativeStreamingDriver,
): MxcSandboxProcess {
  return MxcSandboxProcess.create(driver);
}
