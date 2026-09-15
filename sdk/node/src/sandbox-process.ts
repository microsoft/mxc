// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { performance } from 'node:perf_hooks';
import { Readable, Writable } from 'node:stream';
import { MxcError } from './errors.js';

export interface SandboxProcessWaitResult {
  exitCode: number;
  timedOut: boolean;
}

export interface SandboxReadableBinding {
  read(buffer: Buffer): Promise<number>;
  close(): void;
  free(): void;
}

export interface SandboxWritableBinding {
  write(buffer: Buffer): Promise<number>;
  flush(): Promise<void>;
  free(): void;
}

export interface SandboxProcessBinding {
  readonly id: number;
  readonly warnings: readonly string[];
  takeStdin(): SandboxWritableBinding | null;
  takeStdout(): SandboxReadableBinding | null;
  takeStderr(): SandboxReadableBinding | null;
  tryWait(): SandboxProcessWaitResult & { running: boolean };
  wait(): SandboxProcessWaitResult;
  outputMetadata(): unknown | undefined;
  kill(): void;
  free(): void;
}

type ReadState = 'untaken' | 'owned' | 'draining' | 'missing';

const MIN_POLL_MS = 1;
const MAX_POLL_MS = 50;

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

class ReadPipe extends Readable {
  private closing = false;
  private reading = false;
  private freed = false;

  constructor(private readonly binding: SandboxReadableBinding) {
    super({ autoDestroy: true });
  }

  override _read(size: number): void {
    if (this.closing || this.reading || this.freed) return;
    this.reading = true;
    const buffer = Buffer.allocUnsafe(Math.max(size, 16 * 1024));
    void this.binding.read(buffer).then((count) => {
      this.reading = false;
      if (this.closing) return this.finishClose();
      if (count === 0) {
        this.closing = true;
        this.push(null);
        return;
      }
      this.push(buffer.subarray(0, count));
    }, (error) => {
      this.reading = false;
      if (this.closing) return this.finishClose();
      this.destroy(asError(error));
    });
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.closing = true;
    let failure = error;
    try {
      this.binding.close();
    } catch (closeError) {
      failure ??= asError(closeError);
    }
    this.finishClose();
    callback(failure);
  }

  private finishClose(): void {
    if (this.reading || this.freed) return;
    this.freed = true;
    this.binding.free();
  }
}

class WritePipe extends Writable {
  private closing = false;
  private busy = false;
  private freed = false;

  constructor(private readonly binding: SandboxWritableBinding) {
    super({ autoDestroy: true });
  }

  override _write(
    chunk: string | Buffer,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    this.busy = true;
    const write = (offset: number) => {
      void this.binding.write(buffer.subarray(offset)).then((written) => {
        if (written <= 0) {
          throw new MxcError('backend_error', 'sandbox stdin accepted no bytes');
        }
        if (offset + written >= buffer.length) {
          this.busy = false;
          this.finishClose();
          callback();
          return;
        }
        write(offset + written);
      }).catch((error) => {
        this.busy = false;
        this.finishClose();
        callback(asError(error));
      });
    };
    write(0);
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.closing) return callback();
    this.busy = true;
    void this.binding.flush().then(() => {
      this.busy = false;
      this.finishClose();
      callback();
    }, (error) => {
      this.busy = false;
      this.finishClose();
      callback(asError(error));
    });
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.closing = true;
    this.finishClose();
    callback(error);
  }

  private finishClose(): void {
    if (!this.closing || this.busy || this.freed) return;
    this.freed = true;
    this.binding.free();
  }
}

/**
 * Live pipe-based sandbox process spawned by `spawnSandboxProcess()`.
 *
 * If you take `stdout` or `stderr`, keep draining them while the sandbox runs.
 * Untaken output streams are drained internally during `wait()` so a child that
 * writes heavily cannot deadlock on a full pipe.
 */
export class MxcSandboxProcess {
  private readonly startedAt = performance.now();
  private readonly timeoutMs?: number;
  private readonly binding: SandboxProcessBinding;
  private waitTimer?: NodeJS.Timeout;
  private waitPromise?: Promise<SandboxProcessWaitResult>;
  private waitReject?: (reason?: unknown) => void;
  private waitResult?: SandboxProcessWaitResult;
  private outputMetadataValue?: unknown;
  private outputMetadataReady = false;
  private stdinValue?: WritePipe | null;
  private stdinTaken = false;
  private stdoutValue?: ReadPipe | null;
  private stdoutState: ReadState = 'untaken';
  private stderrValue?: ReadPipe | null;
  private stderrState: ReadState = 'untaken';
  private readonly cleanupCallbacks = new Set<() => void>();
  private disposed = false;

  private constructor(binding: SandboxProcessBinding, timeoutMs?: number) {
    this.binding = binding;
    this.timeoutMs = timeoutMs && timeoutMs > 0 ? timeoutMs : undefined;
  }

  /** @internal */
  static createFromBinding(
    binding: SandboxProcessBinding,
    timeoutMs?: number,
  ): MxcSandboxProcess {
    return new MxcSandboxProcess(binding, timeoutMs);
  }

  get id(): number {
    return this.binding.id;
  }

  get warnings(): readonly string[] {
    return this.binding.warnings;
  }

  get stdin(): Writable | null {
    if (!this.stdinTaken) {
      this.stdinTaken = true;
      const stream = this.binding.takeStdin();
      this.stdinValue = stream === null ? null : new WritePipe(stream);
    }
    return this.stdinValue ?? null;
  }

  get stdout(): Readable | null {
    return this.takeReadable('stdout');
  }

  get stderr(): Readable | null {
    return this.takeReadable('stderr');
  }

  get outputMetadata(): unknown | undefined {
    return this.outputMetadataReady ? this.outputMetadataValue : undefined;
  }

  /** Wait for terminal completion. */
  wait(): Promise<SandboxProcessWaitResult> {
    if (this.waitResult !== undefined) return Promise.resolve(this.waitResult);
    if (this.disposed) return Promise.reject(new Error('sandbox process disposed'));
    if (this.waitPromise !== undefined) return this.waitPromise;

    this.ensureDrain('stdout');
    this.ensureDrain('stderr');
    this.waitPromise = new Promise((resolve, reject) => {
      this.waitReject = reject;
      let pollMs = MIN_POLL_MS;
      const step = () => {
        try {
          if (this.disposed) throw new Error('sandbox process disposed');
          const status = this.binding.tryWait();
          if (!status.running) {
            resolve(this.finishWait(this.binding.wait()));
            return;
          }
          if (this.timeoutMs !== undefined && performance.now() - this.startedAt >= this.timeoutMs) {
            this.binding.kill();
            resolve(this.finishWait({ ...this.binding.wait(), timedOut: true }));
            return;
          }
          this.waitTimer = setTimeout(step, pollMs);
          pollMs = Math.min(pollMs * 2, MAX_POLL_MS);
        } catch (error) {
          reject(error);
        }
      };
      queueMicrotask(step);
    });
    return this.waitPromise;
  }

  kill(): void {
    if (this.disposed) throw new Error('sandbox process disposed');
    this.binding.kill();
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
    if (this.waitTimer !== undefined) {
      clearTimeout(this.waitTimer);
      this.waitTimer = undefined;
    }
    this.waitReject?.(new Error('sandbox process disposed'));
    this.waitReject = undefined;
    this.runCleanups();
    try {
      this.binding.free();
    } finally {
      this.stdinValue?.destroy();
      this.stdoutValue?.destroy();
      this.stderrValue?.destroy();
    }
  }

  private finishWait(result: SandboxProcessWaitResult): SandboxProcessWaitResult {
    this.waitTimer = undefined;
    this.waitReject = undefined;
    this.waitResult = result;
    try {
      this.outputMetadataValue = this.binding.outputMetadata();
      this.outputMetadataReady = true;
    } finally {
      this.runCleanups();
    }
    return result;
  }

  private runCleanups(): void {
    for (const callback of this.cleanupCallbacks) {
      callback();
    }
    this.cleanupCallbacks.clear();
  }

  private takeReadable(which: 'stdout' | 'stderr'): Readable | null {
    const state = which === 'stdout' ? this.stdoutState : this.stderrState;
    const slot = which === 'stdout' ? this.stdoutValue : this.stderrValue;
    if (state === 'owned') return slot ?? null;
    if (state === 'missing') return null;
    if (state === 'draining') {
      throw new Error(`sandbox ${which} is being drained internally by wait()`);
    }
    const binding = which === 'stdout' ? this.binding.takeStdout() : this.binding.takeStderr();
    const stream = binding === null ? null : new ReadPipe(binding);
    if (which === 'stdout') {
      this.stdoutState = stream === null ? 'missing' : 'owned';
      this.stdoutValue = stream;
    } else {
      this.stderrState = stream === null ? 'missing' : 'owned';
      this.stderrValue = stream;
    }
    return stream;
  }

  private ensureDrain(which: 'stdout' | 'stderr'): void {
    const state = which === 'stdout' ? this.stdoutState : this.stderrState;
    if (state !== 'untaken') return;
    const binding = which === 'stdout' ? this.binding.takeStdout() : this.binding.takeStderr();
    if (binding === null) {
      if (which === 'stdout') this.stdoutState = 'missing';
      else this.stderrState = 'missing';
      return;
    }
    const stream = new ReadPipe(binding);
    stream.on('error', () => {});
    stream.resume();
    if (which === 'stdout') {
      this.stdoutState = 'draining';
      this.stdoutValue = stream;
    } else {
      this.stderrState = 'draining';
      this.stderrValue = stream;
    }
  }
}

export function _createMxcSandboxProcess(
  binding: SandboxProcessBinding,
  timeoutMs?: number,
): MxcSandboxProcess {
  return MxcSandboxProcess.createFromBinding(binding, timeoutMs);
}
