// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  _setExecStateAwareBindingSandboxWithPtyImplementation,
  _setSpawnBindingSandboxWithPtyImplementation,
} from '../../src/bindings/pty.js';
import { spawnWithPty } from '../../src/v1/container.js';
import { spawnInContainerWithPty } from '../../src/v1/lifecycle.js';
import type { ContainerId } from '../../src/v1/lifecycle-types.js';

const captured = new Error('PTY dimensions captured by test binding');

describe('initial PTY dimensions in operation options', () => {
  it('forwards custom and default one-shot dimensions to the native binding', async () => {
    let dimensions: [number, number] | undefined;
    let telemetry: unknown;
    _setSpawnBindingSandboxWithPtyImplementation(
      (request, _experimental, rows, columns) => {
        dimensions = [rows, columns];
        telemetry = request.telemetry;
        return Promise.reject(captured);
      },
    );

    try {
      await assert.rejects(
        spawnWithPty(
          { command: 'echo test' },
          { size: { rows: 40, columns: 120 }, telemetry: { enabled: true } },
        ),
        captured,
      );
      assert.deepStrictEqual(dimensions, [40, 120]);
      assert.deepStrictEqual(telemetry, { enabled: true });

      await assert.rejects(spawnWithPty({ command: 'echo test' }), captured);
      assert.deepStrictEqual(dimensions, [24, 80]);
      assert.strictEqual(telemetry, undefined);
      await assert.rejects(
        spawnWithPty({ command: 'echo test' }, { telemetry: { enabled: false } }),
        captured,
      );
      assert.deepStrictEqual(telemetry, { enabled: false });
    } finally {
      _setSpawnBindingSandboxWithPtyImplementation();
    }
  });

  it('forwards custom and default existing-container dimensions to the native binding', async () => {
    let dimensions: [number, number] | undefined;
    _setExecStateAwareBindingSandboxWithPtyImplementation(
      (_request, _experimental, rows, columns) => {
        dimensions = [rows, columns];
        return Promise.reject(captured);
      },
    );

    const id = 'iso:test' as ContainerId<'isolation_session'>;
    try {
      await assert.rejects(
        spawnInContainerWithPty(
          id,
          { command: 'echo test' },
          { size: { rows: 40, columns: 120 } },
        ),
        captured,
      );
      assert.deepStrictEqual(dimensions, [40, 120]);

      await assert.rejects(
        spawnInContainerWithPty(id, { command: 'echo test' }),
        captured,
      );
      assert.deepStrictEqual(dimensions, [24, 80]);
    } finally {
      _setExecStateAwareBindingSandboxWithPtyImplementation();
    }
  });
});
