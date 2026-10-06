// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  _setExecStateAwareBindingSandboxWithPtyImplementation,
  _setSpawnBindingSandboxWithPtyImplementation,
} from '../../src/bindings/pty.js';
import {
  _setSpawnProcessContainerWithPtyImplementation,
} from '../../src/bindings/process-container-pty.js';
import type { OneShotRequest } from '../../src/generated/v1_0_0/wire.js';
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

  it('routes Windows ProcessContainer requests through the wxc-exec PTY binding', {
    skip: process.platform !== 'win32',
  }, async () => {
    let preparedRequest: OneShotRequest | undefined;
    let dimensions: [number, number] | undefined;
    _setSpawnBindingSandboxWithPtyImplementation(() => {
      assert.fail('ProcessContainer PTY must not use the FFI binding');
    });
    _setSpawnProcessContainerWithPtyImplementation(
      (request, _experimental, rows, columns) => {
        preparedRequest = request;
        dimensions = [rows, columns];
        return Promise.reject(captured);
      },
    );

    try {
      await assert.rejects(
        spawnWithPty(
          {
            containment: { type: 'processcontainer' },
            command: 'cmd.exe',
            workingDirectory: 'C:\\work',
            environment: { SAMPLE: 'value' },
          },
          {
            size: { rows: 35, columns: 110 },
            telemetry: { enabled: true },
          },
        ),
        captured,
      );
      assert.strictEqual(preparedRequest?.version, '1.0.0');
      assert.strictEqual(preparedRequest?.containment, 'processcontainer');
      assert.strictEqual(preparedRequest?.process.commandLine, 'cmd.exe');
      assert.strictEqual(preparedRequest?.process.cwd, 'C:\\work');
      assert.deepStrictEqual(preparedRequest?.process.env, ['SAMPLE=value']);
      assert.deepStrictEqual(preparedRequest?.telemetry, { enabled: true });
      assert.deepStrictEqual(dimensions, [35, 110]);
    } finally {
      _setSpawnBindingSandboxWithPtyImplementation();
      _setSpawnProcessContainerWithPtyImplementation();
    }
  });

  it('keeps non-Windows ProcessContainer requests on the native path', {
    skip: process.platform === 'win32',
  }, async () => {
    let preparedRequest: OneShotRequest | undefined;
    _setSpawnProcessContainerWithPtyImplementation(() => {
      assert.fail('non-Windows ProcessContainer PTY must not launch wxc-exec');
    });
    _setSpawnBindingSandboxWithPtyImplementation((request) => {
      preparedRequest = request;
      return Promise.reject(captured);
    });

    try {
      await assert.rejects(
        spawnWithPty({
          containment: { type: 'processcontainer' },
          command: 'echo test',
        }),
        captured,
      );
      assert.strictEqual(preparedRequest?.containment, 'processcontainer');
    } finally {
      _setSpawnProcessContainerWithPtyImplementation();
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
