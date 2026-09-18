// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { mkdtempSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  attachedStderr,
  readPayload,
} from '../../src/pty-worker.js';
import type { RequestSpec } from '../../src/bindings/request.js';

describe('PTY worker', () => {
  it('reads and removes its private request payload', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'mxc-pty-worker-test-'));
    const payloadFile = path.join(directory, 'request.json');
    const request = {
      policy: { version: '0.9.0-alpha' },
      containment: { type: 'process' },
      command: 'echo hello',
    } as RequestSpec;
    writeFileSync(payloadFile, JSON.stringify(request));

    assert.deepStrictEqual(
      readPayload(['--payload-file', payloadFile]),
      request,
    );
    assert.strictEqual(existsSync(directory), false);
  });

  it('rejects a missing payload argument', () => {
    assert.throws(() => readPayload([]), /Missing --payload-file/);
  });

  it('renders warnings and capture-denials metadata for the PTY stream', () => {
    assert.strictEqual(
      attachedStderr(
        ['first warning', 'second warning'],
        { captureDenials: { path: 'denials.json' } },
      ),
      'first warning\nsecond warning\n{"path":"denials.json"}\n',
    );
  });
});
