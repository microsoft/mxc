// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import { describe, it } from 'node:test';
import type {
  IDisposable,
  IPty,
  IWindowsPtyForkOptions,
} from 'node-pty';
import {
  _setProcessContainerPtyDependencies,
  createNodePtyProcess,
  spawnProcessContainerWithPty,
} from '../../src/bindings/process-container-pty.js';

class FakePty implements IPty {
  readonly pid = 42;
  readonly process = 'wxc-exec.exe';
  cols = 80;
  rows = 24;
  handleFlowControl = false;
  readonly writes: Array<string | Buffer> = [];
  readonly resizes: Array<[number, number]> = [];
  killCount = 0;
  pauseCount = 0;
  resumeCount = 0;

  private readonly dataListeners = new Set<(data: string) => unknown>();
  private readonly exitListeners =
    new Set<(event: { exitCode: number; signal?: number }) => unknown>();

  readonly onData = (listener: (data: string) => unknown): IDisposable => {
    this.dataListeners.add(listener);
    return { dispose: () => this.dataListeners.delete(listener) };
  };

  readonly onExit = (
    listener: (event: { exitCode: number; signal?: number }) => unknown,
  ): IDisposable => {
    this.exitListeners.add(listener);
    return { dispose: () => this.exitListeners.delete(listener) };
  };

  resize(columns: number, rows: number): void {
    this.cols = columns;
    this.rows = rows;
    this.resizes.push([columns, rows]);
  }

  clear(): void {}

  write(data: string | Buffer): void {
    this.writes.push(data);
  }

  kill(): void {
    this.killCount += 1;
  }

  pause(): void {
    this.pauseCount += 1;
  }

  resume(): void {
    this.resumeCount += 1;
  }

  emitData(data: string): void {
    for (const listener of this.dataListeners) listener(data);
  }

  exit(exitCode: number): void {
    for (const listener of this.exitListeners) listener({ exitCode });
  }
}

describe('ProcessContainer node-pty binding', () => {
  it('wraps IPty input, output, resize, wait, and kill operations', async () => {
    const pty = new FakePty();
    const terminal = createNodePtyProcess(pty);
    const output = once(terminal.output, 'data');

    assert.strictEqual(terminal.id, pty.pid);
    terminal.input.write('echo hello\r\n');
    pty.emitData('hello\r\n');
    terminal.resize({ rows: 40, columns: 120 });

    assert.strictEqual((await output)[0].toString(), 'hello\r\n');
    assert.deepStrictEqual(pty.writes, [Buffer.from('echo hello\r\n')]);
    assert.deepStrictEqual(pty.resizes, [[120, 40]]);

    terminal.kill();
    assert.strictEqual(pty.killCount, 1);
    pty.exit(7);
    assert.deepStrictEqual(await terminal.wait(), {
      exitCode: 7,
      timedOut: false,
    });
  });

  it('launches wxc-exec with the exact one-shot request as base64 JSON', async () => {
    const pty = new FakePty();
    let executable = '';
    let args: string[] = [];
    let options: IWindowsPtyForkOptions | undefined;
    _setProcessContainerPtyDependencies({
      findExecutable: () => 'C:\\mxc\\wxc-exec.exe',
      loadNodePty: async () => ({
        spawn: (file, spawnArgs, spawnOptions) => {
          executable = file;
          args = [...spawnArgs];
          options = spawnOptions as IWindowsPtyForkOptions;
          return pty;
        },
      }) as typeof import('node-pty'),
    });

    const request = {
      version: '1.0.0',
      containment: 'processcontainer',
      process: {
        commandLine: 'cmd.exe',
        timeout: 5000,
      },
    } as const;

    try {
      const terminal = await spawnProcessContainerWithPty(
        request,
        true,
        30,
        100,
      );
      assert.strictEqual(executable, 'C:\\mxc\\wxc-exec.exe');
      assert.deepStrictEqual(args.slice(0, 1), ['--config-base64']);
      assert.deepStrictEqual(
        JSON.parse(Buffer.from(args[1], 'base64').toString('utf8')),
        request,
      );
      assert.strictEqual(args[2], '--experimental');
      assert.strictEqual(options?.rows, 30);
      assert.strictEqual(options?.cols, 100);
      assert.strictEqual(options?.useConpty, true);
      terminal.dispose();
      pty.exit(0);
    } finally {
      _setProcessContainerPtyDependencies();
    }
  });

  it('fails with remediation when wxc-exec is unavailable', async () => {
    _setProcessContainerPtyDependencies({
      findExecutable: () => null,
      loadNodePty: async () => assert.fail(
        'node-pty must not load without wxc-exec',
      ),
    });

    try {
      await assert.rejects(
        spawnProcessContainerWithPty(
          {
            version: '1.0.0',
            containment: 'processcontainer',
            process: { commandLine: 'cmd.exe' },
          },
          false,
          24,
          80,
        ),
        (error: unknown) =>
          error instanceof Error
          && error.message.includes('wxc-exec.exe was not found'),
      );
    } finally {
      _setProcessContainerPtyDependencies();
    }
  });
});
