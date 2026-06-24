// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createConnection } from 'node:net';
import * as os from 'os';
import { createDenialPipeServer } from '../../src/denial-channel/transports/named-pipe.js';

// All tests in this file require Windows named-pipe semantics. The
// module itself throws on non-Windows, and a Unix host has no
// equivalent we can substitute for the test, so we skip the whole
// suite when not on win32.
const isWindows = os.platform() === 'win32';

describe('createDenialPipeServer', { skip: !isWindows ? 'Windows-only' : false }, () => {
  it('produces a unique randomised pipe name on each call', () => {
    const a = createDenialPipeServer();
    const b = createDenialPipeServer();
    // Neither server gets a client; swallow the close()-before-connect
    // rejection so it doesn't surface as an unhandled rejection.
    void a.denialStream.catch(() => {});
    void b.denialStream.catch(() => {});
    try {
      assert.match(a.pipeName, /^mxc-denials-[0-9a-f]{16}$/);
      assert.match(b.pipeName, /^mxc-denials-[0-9a-f]{16}$/);
      assert.notStrictEqual(a.pipeName, b.pipeName);
    } finally {
      a.close();
      b.close();
    }
  });

  it('resolves denialStream when a client connects, end-to-end bytes round-trip', async () => {
    const server = createDenialPipeServer();
    try {
      const fullPath = `\\\\.\\pipe\\${server.pipeName}`;
      // Spin up a fake "wxc-exec writer" that opens the pipe and
      // writes a single 0x1E-prefixed JSON envelope + newline,
      // exactly like the Rust side would.
      const writerSocket = createConnection(fullPath);
      await new Promise<void>((resolve, reject) => {
        writerSocket.once('connect', resolve);
        writerSocket.once('error', reject);
      });
      const writePayload = Buffer.from('\x1e{"type":"denial","path":"C:\\\\a.txt"}\n', 'utf8');
      writerSocket.write(writePayload);
      writerSocket.end();

      const reader = await server.denialStream;
      const received: Buffer[] = [];
      reader.on('data', (c) => received.push(c));
      await new Promise<void>((resolve) => reader.once('end', () => resolve()));

      assert.deepStrictEqual(Buffer.concat(received), writePayload);
    } finally {
      server.close();
    }
  });

  it('close() is idempotent', () => {
    const s = createDenialPipeServer();
    void s.denialStream.catch(() => {});
    s.close();
    // Second close must not throw.
    s.close();
    s.close();
  });

  it('close() before any client connects rejects denialStream and refuses connections', async () => {
    const s = createDenialPipeServer();
    // close() before a client connects must settle denialStream
    // (rejecting) so awaiters observe shutdown instead of hanging.
    const rejected = assert.rejects(
      s.denialStream,
      /closed before a client connected/,
    );
    s.close();
    await rejected;
    // And an attempt to connect after close should fail.
    await new Promise<void>((resolve) => {
      const sock = createConnection(`\\\\.\\pipe\\${s.pipeName}`);
      sock.once('error', () => resolve());
      sock.once('connect', () => {
        sock.destroy();
        assert.fail('connection should not succeed after close()');
      });
    });
  });
});

describe('createDenialPipeServer on non-Windows', { skip: isWindows ? 'Windows-only test' : false }, () => {
  it('throws with an actionable error message', () => {
    assert.throws(
      () => createDenialPipeServer(),
      /Windows named pipes only/,
    );
  });
});
