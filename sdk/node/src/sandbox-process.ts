// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { performance } from 'node:perf_hooks';
import { Readable, Writable } from 'node:stream';
import { MxcError } from './errors.js';
import type {
  SandboxProcessBinding,
  SandboxWaitResult,
  SandboxReadableBinding,
  SandboxWritableBinding,
} from './bindings/streaming-types.js';

export type {
  SandboxProcessBinding,
  SandboxWaitResult,
  SandboxReadableBinding,
  SandboxWritableBinding,
} from './bindings/streaming-types.js';

type ReadState = 'untaken' | 'owned' | 'draining' | 'missing';

const MIN_POLL_MS = 1;
const MAX_POLL_MS = 50;
// A descendant can inherit an output handle after the direct child exits.
// Bound terminal draining so that inherited handles cannot stall wait forever.
const OUTPUT_DRAIN_GRACE_MS = 250;

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

class ReadPipe extends Readable {
  private closing = false;
  private reading = false;
  private freed = false;
  private readonly completedPromise: Promise<void>;
  private complete!: () => void;

  constructor(private readonly binding: SandboxReadableBinding) {
    super({ autoDestroy: true });
    this.completedPromise = new Promise((resolve) => {
      this.complete = resolve;
    });
  }

  get completed(): Promise<void> {
    return this.completedPromise;
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
    try {
      this.binding.free();
    } finally {
      this.complete();
    }
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
    if (buffer.length === 0) {
      callback();
      return;
    }
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
 * Streaming pipe-based sandbox process returned by `spawnSandbox()` and
 * `spawnSandboxFromConfig()`.
 *
 * If you take `standardOutput` or `standardError`, keep draining them while the
 * sandbox runs. Untaken output streams are drained internally during
 * `waitAsync()` so a child that writes heavily cannot deadlock on a full pipe.
 */
export class MxcSandboxProcess {
  private readonly startedAt = performance.now();
  private readonly timeoutMs?: number;
  private readonly binding: SandboxProcessBinding;
  private readonly idValue: number;
  private warningsValue: readonly string[];
  private waitTimer?: NodeJS.Timeout;
  private waitPromise?: Promise<SandboxWaitResult>;
  private waitReject?: (reason?: unknown) => void;
  private waitResult?: SandboxWaitResult;
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
  private handleFreed = false;
  private finalizing = false;

  private constructor(binding: SandboxProcessBinding, timeoutMs?: number) {
    this.binding = binding;
    this.idValue = binding.id;
    this.warningsValue = binding.warnings();
    this.timeoutMs = timeoutMs && timeoutMs > 0 ? timeoutMs : undefined;
  }

  /** @internal */
  static createFromBinding(
    binding: SandboxProcessBinding,
    timeoutMs?: number,
  ): MxcSandboxProcess {
    try {
      return new MxcSandboxProcess(binding, timeoutMs);
    } catch (error) {
      binding.free();
      throw error;
    }
  }

  get id(): number {
    return this.idValue;
  }

  get warnings(): readonly string[] {
    return this.warningsValue;
  }

  get standardInput(): Writable | null {
    this.ensureNotDisposed();
    if (this.stdinTaken) return this.stdinValue ?? null;
    this.ensureHandleAvailable('standard input');
    this.stdinTaken = true;
    const stream = this.binding.takeStdin();
    this.stdinValue = stream === null ? null : new WritePipe(stream);
    return this.stdinValue ?? null;
  }

  get standardOutput(): Readable | null {
    this.ensureNotDisposed();
    return this.takeReadable('stdout');
  }

  get standardError(): Readable | null {
    this.ensureNotDisposed();
    return this.takeReadable('stderr');
  }

  get outputMetadata(): unknown | undefined {
    return this.outputMetadataReady ? this.outputMetadataValue : undefined;
  }

  /** Wait asynchronously for terminal completion. */
  waitAsync(): Promise<SandboxWaitResult> {
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
            void this.finishWait(this.binding.wait()).then(resolve, reject);
            return;
          }
          if (this.timeoutMs !== undefined && performance.now() - this.startedAt >= this.timeoutMs) {
            const deadlineStatus = this.binding.tryWait();
            if (!deadlineStatus.running) {
              void this.finishWait(this.binding.wait()).then(resolve, reject);
              return;
            }
            try {
              this.binding.kill();
            } catch (error) {
              const racedStatus = this.binding.tryWait();
              if (!racedStatus.running) {
                void this.finishWait(this.binding.wait()).then(resolve, reject);
                return;
              }
              throw error;
            }
            void this.finishWait({ ...this.binding.wait(), timedOut: true }).then(resolve, reject);
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
    this.ensureHandleAvailable('process');
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
    this.stdinValue?.destroy();
    this.stdoutValue?.destroy();
    this.stderrValue?.destroy();
    if (!this.finalizing) this.freeHandle();
  }

  private freeHandle(): void {
    if (this.handleFreed) return;
    this.handleFreed = true;
    this.binding.free();
  }

  private async finishWait(result: SandboxWaitResult): Promise<SandboxWaitResult> {
    this.waitTimer = undefined;
    this.finalizing = true;
    try {
      await this.finishOutputStreams();
      this.stdinValue?.destroy();
      if (!this.disposed) {
        this.outputMetadataValue = this.binding.outputMetadata();
        this.outputMetadataReady = true;
        this.warningsValue = this.binding.warnings();
        this.waitResult = result;
      }
      return result;
    } finally {
      this.waitReject = undefined;
      this.finalizing = false;
      this.runCleanups();
      this.freeHandle();
    }
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
      throw new Error(`sandbox ${which} is being drained internally by waitAsync()`);
    }

    this.ensureHandleAvailable(which);
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

  private async finishOutputStreams(): Promise<void> {
    const streams = [this.stdoutValue, this.stderrValue].filter(
      (stream): stream is ReadPipe => stream !== null && stream !== undefined,
    );
    await Promise.all(streams.map((stream) => this.finishOutputStream(stream)));
  }

  private async finishOutputStream(stream: ReadPipe): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      stream.completed,
      new Promise<void>((resolve) => {
        timer = setTimeout(() => {
          stream.destroy();
          void stream.completed.then(resolve);
        }, OUTPUT_DRAIN_GRACE_MS);
      }),
    ]);
    if (timer !== undefined) clearTimeout(timer);
  }

  private ensureNotDisposed(): void {
    if (this.disposed) throw new Error('sandbox process disposed');
  }

  private ensureHandleAvailable(stream: string): void {
    this.ensureNotDisposed();
    if (this.handleFreed) {
      throw new Error(`sandbox ${stream} is unavailable after terminal completion`);
    }
  }
}

export function _createMxcSandboxProcess(
  binding: SandboxProcessBinding,
  timeoutMs?: number,
): MxcSandboxProcess {
  return MxcSandboxProcess.createFromBinding(binding, timeoutMs);
}
