// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { EventEmitter } from 'node:events';
import type { Readable, Writable } from 'node:stream';
import type { IDisposable, IEvent, IPty, IPtyForkOptions } from 'node-pty';
import type { MxcSandboxProcess } from './sandbox-process.js';

type ExitEvent = { exitCode: number; signal?: number };

function asText(data: string | Buffer): string {
  return Buffer.isBuffer(data) ? data.toString('utf8') : data;
}

/**
 * Pipe-backed compatibility adapter for consumers that expect `node-pty`.
 *
 * This preserves the `IPty` programming model, not terminal semantics. The
 * sandboxed process still receives separate pipes, so TTY detection, terminal
 * resize, line discipline, and job control are unavailable.
 */
export class MxcPtyAdapter implements IPty {
  private readonly events = new EventEmitter();
  private readonly stdin: Writable | null;
  private readonly stdout: Readable | null;
  private readonly stderr: Readable | null;
  private colsValue: number;
  private rowsValue: number;
  private exited = false;

  handleFlowControl = false;

  constructor(
    private readonly sandbox: MxcSandboxProcess,
    options: IPtyForkOptions = {},
  ) {
    this.colsValue = options.cols ?? 120;
    this.rowsValue = options.rows ?? 80;
    this.stdin = sandbox.standardInput;
    this.stdout = sandbox.standardOutput;
    this.stderr = sandbox.standardError;

    this.stdout?.setEncoding('utf8');
    this.stderr?.setEncoding('utf8');
    this.stdout?.on('data', (data: string | Buffer) => {
      this.events.emit('data', asText(data));
    });
    this.stderr?.on('data', (data: string | Buffer) => {
      this.events.emit('data', asText(data));
    });
    const reportStreamError = (error: Error) => {
      this.events.emit('data', `${error.message}\r\n`);
    };
    this.stdout?.on('error', reportStreamError);
    this.stderr?.on('error', reportStreamError);
    this.stdin?.on('error', reportStreamError);
    void sandbox.waitAsync().then(
      ({ exitCode }) => {
        this.exited = true;
        this.events.emit('exit', { exitCode });
      },
      (error: unknown) => {
        this.exited = true;
        const message = error instanceof Error ? error.message : String(error);
        this.events.emit('data', `${message}\r\n`);
        this.events.emit('exit', { exitCode: 1 });
      },
    );
  }

  get pid(): number {
    return this.sandbox.id;
  }

  get cols(): number {
    return this.colsValue;
  }

  get rows(): number {
    return this.rowsValue;
  }

  get process(): string {
    return 'mxc-sandbox';
  }

  readonly onData: IEvent<string> = (listener): IDisposable => {
    this.events.on('data', listener);
    return { dispose: () => this.events.off('data', listener) };
  };

  readonly onExit: IEvent<ExitEvent> = (listener): IDisposable => {
    this.events.on('exit', listener);
    return { dispose: () => this.events.off('exit', listener) };
  };

  resize(columns: number, rows: number): void {
    this.colsValue = columns;
    this.rowsValue = rows;
  }

  clear(): void {
    // Pipes have no terminal buffer to clear.
  }

  write(data: string | Buffer): void {
    if (this.exited) {
      throw new Error('sandbox process has exited');
    }
    if (this.stdin === null) {
      throw new Error('sandbox standard input is unavailable');
    }
    this.stdin.write(data);
  }

  kill(_signal?: string): void {
    this.sandbox.kill();
  }

  pause(): void {
    this.stdout?.pause();
    this.stderr?.pause();
  }

  resume(): void {
    this.stdout?.resume();
    this.stderr?.resume();
  }
}

export function createPtyAdapter(
  sandbox: MxcSandboxProcess,
  options?: IPtyForkOptions,
): IPty {
  return new MxcPtyAdapter(sandbox, options);
}
