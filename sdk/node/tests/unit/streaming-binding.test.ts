// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';
import {
  createNodeStreamFactory,
  supportsNativeStdio,
  type NodeStreamDependencies,
} from '../../src/bindings/native-stdio.js';

describe('native Node stream construction', () => {
  it('constructs owning Windows streams from the full native handle', () => {
    const calls: Array<{
      readonly direction: 'readable' | 'writable';
      readonly path: string;
      readonly options: unknown;
    }> = [];
    const dependencies: NodeStreamDependencies = {
      createReadStream(path, options) {
        calls.push({ direction: 'readable', path, options });
        return new PassThrough();
      },
      createWriteStream(path, options) {
        calls.push({ direction: 'writable', path, options });
        return new PassThrough();
      },
      createSocket() {
        throw new Error('Windows must not construct fd-backed sockets');
      },
    };
    const factory = createNodeStreamFactory('win32', dependencies);

    factory.writable(0x100000001n);
    factory.readable(0x100000002);

    assert.deepStrictEqual(calls, [
      {
        direction: 'writable',
        path: '',
        options: { autoClose: true, windowsHandle: 0x100000001n },
      },
      {
        direction: 'readable',
        path: '',
        options: { autoClose: true, windowsHandle: 0x100000002n },
      },
    ]);
  });

  it('constructs directional owning Unix sockets from validated descriptors', () => {
    const socketOptions: unknown[] = [];
    const dependencies: NodeStreamDependencies = {
      createReadStream() {
        throw new Error('Unix must not construct Windows read streams');
      },
      createWriteStream() {
        throw new Error('Unix must not construct Windows write streams');
      },
      createSocket(options) {
        socketOptions.push(options);
        return new PassThrough();
      },
    };
    const factory = createNodeStreamFactory('linux', dependencies);

    factory.writable(11n);
    factory.readable(12);

    assert.deepStrictEqual(socketOptions, [
      { fd: 11, readable: false, writable: true },
      { fd: 12, readable: true, writable: false },
    ]);
    assert.throws(
      () => factory.readable(Number.MAX_SAFE_INTEGER + 1),
      /invalid file descriptor/,
    );
  });
});

describe('native streaming Node version support', () => {
  it('enforces the platform-specific native stdio runtime ranges', () => {
    assert.strictEqual(supportsNativeStdio('win32', '24.20.9'), false);
    assert.strictEqual(supportsNativeStdio('win32', '24.21.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '24.21.1'), true);
    assert.strictEqual(supportsNativeStdio('win32', '25.0.0'), false);
    assert.strictEqual(supportsNativeStdio('win32', '25.9.0'), false);
    assert.strictEqual(supportsNativeStdio('win32', '26.7.0'), false);
    assert.strictEqual(supportsNativeStdio('win32', '26.8.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '27.0.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '23.99.99'), false);
    assert.strictEqual(supportsNativeStdio('win32', 'v24.21.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', 'v26.8.0'), true);
    assert.strictEqual(supportsNativeStdio('win32', '26.8'), false);
    assert.strictEqual(supportsNativeStdio('win32', 'invalid'), false);
    assert.strictEqual(supportsNativeStdio('win32', '24.21beta'), false);
    assert.strictEqual(supportsNativeStdio('win32', '24.21.0.1'), false);
    assert.strictEqual(supportsNativeStdio('linux', '23.99.99'), false);
    assert.strictEqual(supportsNativeStdio('linux', '24.0.0'), true);
    assert.strictEqual(supportsNativeStdio('linux', '25.0.0'), true);
    assert.strictEqual(supportsNativeStdio('darwin', '23.99.99'), false);
    assert.strictEqual(supportsNativeStdio('darwin', '24.0.0'), true);
  });
});
