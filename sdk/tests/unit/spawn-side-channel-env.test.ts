// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as os from 'os';
import {
  createConfigFromPolicy,
  spawnSandboxWithSideChannel,
} from '../../src/index.js';

const isWindows = os.platform() === 'win32';

describe(
  'spawnSandboxWithSideChannel — env-injection regression (PTY 203)',
  { skip: !isWindows ? 'Windows-only (named-pipe transport)' : false },
  () => {
    // Regression test for the PTY + captureDenials = error 203 bug.
    //
    // The bug: `spawnSandboxWithSideChannel` previously routed the
    // runtime hint MXC_DENIALS_PIPE through the `env` parameter of
    // `spawnSandboxFromConfig`, which `injectEnvIntoConfig` pushed
    // into `config.process.env`. That replaced the workload's
    // default env block with a one-entry block (just
    // MXC_DENIALS_PIPE, missing PATH/SystemRoot/etc), and
    // Experimental_CreateProcessInSandbox rejected it with Win32
    // error 203 (ERROR_ENVVAR_NOT_FOUND).
    //
    // The fix: MXC_DENIALS_PIPE goes to wxc-exec via the SDK
    // process's own process.env (which the spawn inherits), NOT via
    // the workload-env channel. This test locks that in.
    it('does not leak MXC_DENIALS_PIPE into config.process.env', () => {
      const policy = {
        version: '0.5.0-alpha',
        filesystem: { readwritePaths: [], readonlyPaths: [] },
        captureDenials: true,
      };
      const config = createConfigFromPolicy(policy, 'process');
      config.captureDenials = true;
      config.process = { commandLine: 'cmd /c exit 0', env: [] };

      // The spawn will fail in unit-test environments (wxc-exec
      // isn't necessarily on the path). We don't care — we just want
      // to inspect the config AFTER the SDK has done its work.
      try {
        const result = spawnSandboxWithSideChannel(config);
        // Best-effort cleanup if the spawn somehow succeeded.
        result.close();
        if ('kill' in result.process) {
          (result.process as { kill: () => void }).kill();
        }
      } catch {
        // Expected: wxc-exec ENOENT or similar. The env-injection
        // step happens before the spawn syscall.
      }

      const workloadEnv = config.process?.env ?? [];
      const leaks = workloadEnv.filter((kv) => kv.startsWith('MXC_DENIALS_PIPE='));
      assert.deepStrictEqual(
        leaks,
        [],
        `MXC_DENIALS_PIPE leaked into the workload env block: ${JSON.stringify(leaks)}`,
      );
    });

    // Caller-provided env should still reach the workload — the fix
    // only removed the SDK's injection of MXC_DENIALS_PIPE, not the
    // generic env-passing channel.
    it('still forwards caller-provided env into config.process.env', () => {
      const policy = {
        version: '0.5.0-alpha',
        filesystem: { readwritePaths: [], readonlyPaths: [] },
        captureDenials: true,
      };
      const config = createConfigFromPolicy(policy, 'process');
      config.captureDenials = true;
      config.process = { commandLine: 'cmd /c exit 0', env: [] };

      try {
        const result = spawnSandboxWithSideChannel(
          config,
          { usePty: false },
          undefined,
          { MY_TEST_VAR: 'hello' },
        );
        result.close();
        if ('kill' in result.process) {
          (result.process as { kill: () => void }).kill();
        }
      } catch {
        // ignore spawn failures
      }

      const workloadEnv = config.process?.env ?? [];
      const myVarEntry = workloadEnv.find((kv) => kv.startsWith('MY_TEST_VAR='));
      assert.strictEqual(
        myVarEntry,
        'MY_TEST_VAR=hello',
        `expected MY_TEST_VAR=hello in workload env, got ${workloadEnv.join(', ')}`,
      );
    });

    // The SDK process's own env must be left clean after the spawn.
    // MXC_DENIALS_PIPE is temporarily set during spawnSandboxWithSideChannel
    // (so the child inherits it) but must be restored in the finally
    // block — otherwise a subsequent unrelated spawn would inherit a
    // stale pipe name.
    it('restores process.env.MXC_DENIALS_PIPE after spawn', () => {
      const before = process.env.MXC_DENIALS_PIPE;
      const policy = {
        version: '0.5.0-alpha',
        filesystem: { readwritePaths: [], readonlyPaths: [] },
        captureDenials: true,
      };
      const config = createConfigFromPolicy(policy, 'process');
      config.captureDenials = true;
      config.process = { commandLine: 'cmd /c exit 0', env: [] };

      try {
        const result = spawnSandboxWithSideChannel(config);
        result.close();
        if ('kill' in result.process) {
          (result.process as { kill: () => void }).kill();
        }
      } catch {
        // ignore
      }

      assert.strictEqual(
        process.env.MXC_DENIALS_PIPE,
        before,
        'process.env.MXC_DENIALS_PIPE was not restored after spawn',
      );
    });
  },
);
