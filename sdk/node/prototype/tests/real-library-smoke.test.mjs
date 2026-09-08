// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { describe, it } from 'node:test';

import {
  BindingError,
  discover,
  exec,
  execAsync,
  execAttached,
  execAttachedAsync,
  run,
  runAsync,
  spawn,
  spawnAsync,
  stateAware,
  stateAwareAsync,
  version,
} from '../dist/index.js';

function asBindingError(error) {
  assert.ok(BindingError.hasInner(error), `expected BindingError, got ${String(error)}`);
  return BindingError.getInner(error);
}

function isCode(code) {
  return (error) => asBindingError(error).code() === code;
}

const malformed = '{';

describe('generated UniFFI Node SDK', () => {
  it('loads the real Rust cdylib and discovers the host', () => {
    assert.match(version(), /^\d+\.\d+\.\d+/);
    const snapshot = discover();
    assert.ok(Array.isArray(JSON.parse(snapshot.availableBackendsJson)));
    assert.ok(JSON.parse(snapshot.platformSupportJson).availableMethods.length > 0);
  });

  it('preserves structured errors in sync and async run APIs', async () => {
    assert.throws(() => run(malformed), isCode('malformed_request'));
    await assert.rejects(runAsync(malformed), isCode('malformed_request'));
  });

  it('preserves structured errors in state-aware sync and async APIs', async () => {
    assert.throws(
      () => stateAware(malformed, true, true),
      isCode('malformed_request'),
    );
    await assert.rejects(
      stateAwareAsync(malformed, true, true),
      isCode('malformed_request'),
    );
  });

  it('projects attached and streaming exec as sync and async pairs', async () => {
    assert.throws(
      () => execAttached(malformed, true),
      isCode('malformed_request'),
    );
    await assert.rejects(
      execAttachedAsync(malformed, true),
      isCode('malformed_request'),
    );
    assert.throws(() => exec(malformed, true), isCode('malformed_request'));
    await assert.rejects(execAsync(malformed, true), isCode('malformed_request'));
  });

  it('runs commands through synchronous and asynchronous APIs', async () => {
    const request =
      '{"policy":{"version":"0.8.0-alpha"},' +
      '"command":"cmd /c \\"echo generated-sdk & exit /b 17\\""}';
    const syncResult = run(request);
    const asyncResult = await runAsync(request);

    assert.equal(syncResult.exitCode, 17);
    assert.equal(asyncResult.exitCode, 17);
    assert.match(new TextDecoder().decode(syncResult.stdout), /generated-sdk/);
    assert.match(new TextDecoder().decode(asyncResult.stdout), /generated-sdk/);
  });

  it('owns a live sandbox and take-once streams', async () => {
    const sandbox = await spawnAsync(
      '{"policy":{"version":"0.8.0-alpha"},' +
        '"command":"cmd /c \\"echo stdout & echo stderr 1>&2 & exit /b 23\\""}',
    );
    const stdin = sandbox.takeStdin();
    const stdout = sandbox.takeStdout();
    const stderr = sandbox.takeStderr();
    assert.ok(stdin);
    assert.ok(stdout);
    assert.ok(stderr);
    assert.equal(sandbox.takeStdin(), undefined);
    assert.equal(sandbox.takeStdout(), undefined);
    assert.equal(sandbox.takeStderr(), undefined);

    stdin.uniffiDestroy();
    const [stdoutBytes, stderrBytes, outcome] = await Promise.all([
      stdout.readAsync(),
      stderr.readAsync(),
      sandbox.waitAsync(),
    ]);
    assert.match(new TextDecoder().decode(stdoutBytes), /stdout/);
    assert.match(new TextDecoder().decode(stderrBytes), /stderr/);
    assert.deepEqual(outcome, { exitCode: 23, timedOut: false });

    stdout.uniffiDestroy();
    stderr.uniffiDestroy();
    sandbox.uniffiDestroy();
  });

  it('writes and flushes stdin through synchronous handles', () => {
    const sandbox = spawn(
      '{"policy":{"version":"0.8.0-alpha"},"command":"cmd /c findstr ."}',
    );
    const stdin = sandbox.takeStdin();
    assert.ok(stdin);
    const data = new TextEncoder().encode('from stdin\r\n').buffer;

    assert.equal(stdin.write(data), 12n);
    stdin.flush();
    stdin.uniffiDestroy();
    assert.equal(sandbox.wait().timedOut, false);
    sandbox.uniffiDestroy();
  });

  it('rejects concurrent access promptly while wait owns the handle', async () => {
    const sandbox = await spawnAsync(
      '{"policy":{"version":"0.8.0-alpha"},"command":"cmd /c set /p X="}',
    );
    const stdin = sandbox.takeStdin();
    assert.ok(stdin);
    const waiting = sandbox.waitAsync();
    await delay(200);

    const started = Date.now();
    await assert.rejects(sandbox.killAsync(), (error) => {
      const inner = asBindingError(error);
      return inner.code() === 'backend_error' &&
        inner.operation() === 'UniFFI handle synchronization' &&
        /busy/.test(inner.message());
    });
    assert.ok(Date.now() - started < 1_000);
    stdin.uniffiDestroy();
    assert.equal((await waiting).timedOut, false);
    sandbox.uniffiDestroy();
  });
});
