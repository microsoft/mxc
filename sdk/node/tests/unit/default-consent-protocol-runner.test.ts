// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Exercises the production protocol runner with controlled child-process I/O.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { PassThrough, type Readable, type Writable } from 'node:stream';
import type { ChildProcess } from 'node:child_process';

import {
  requestTelemetryConsent,
  _setTelemetryPlatform,
  _setTelemetryConsentChildFactory,
  _setTelemetryConsentProtocolRunner,
  _setTelemetryConsentRunner,
  _setTelemetryConsentTimeoutMs,
  type TelemetryConsentPrompt,
} from '../../src/telemetry.js';

// A minimal ChildProcess-shaped fake wxc-exec that lets a test drive the
// stdout/stderr/exit sequence turn-by-turn.
interface FakeChild extends EventEmitter {
  stdout: Readable;
  stderr: Readable;
  stdin: Writable;
  kill(signal?: NodeJS.Signals | number): boolean;
  killed: boolean;
  killCount: number;
  emitClose(code: number): void;
  writeStdout(chunk: string): void;
  writeStderr(chunk: string): void;
  stdinChunks: string[];
  stdinEnded: boolean;
}

function makeFakeChild(): FakeChild {
  const emitter = new EventEmitter() as FakeChild;
  emitter.stdout = new PassThrough();
  emitter.stderr = new PassThrough();
  emitter.stdin = new PassThrough();
  emitter.killed = false;
  emitter.killCount = 0;
  emitter.stdinChunks = [];
  emitter.stdinEnded = false;
  emitter.stdin.on('data', (chunk) => {
    emitter.stdinChunks.push(chunk.toString('utf8'));
  });
  emitter.stdin.on('end', () => {
    emitter.stdinEnded = true;
  });
  emitter.kill = (): boolean => {
    emitter.killCount += 1;
    emitter.killed = true;
    (emitter.stdout as PassThrough).end();
    (emitter.stderr as PassThrough).end();
    return true;
  };
  emitter.emitClose = (code: number): void => {
    (emitter.stdout as PassThrough).end();
    (emitter.stderr as PassThrough).end();
    emitter.emit('close', code);
  };
  emitter.writeStdout = (chunk: string): void => {
    (emitter.stdout as PassThrough).write(chunk);
  };
  emitter.writeStderr = (chunk: string): void => {
    (emitter.stderr as PassThrough).write(chunk);
  };
  return emitter;
}

// The runner types the factory as returning a `ChildProcess`. Our fake covers
// only the subset the runner uses. Cast once here rather than everywhere.
function installFakeChildFactory(): { current: FakeChild } {
  const box: { current: FakeChild } = { current: null as unknown as FakeChild };
  _setTelemetryConsentChildFactory(() => {
    box.current = makeFakeChild();
    return box.current as unknown as ChildProcess;
  });
  return box;
}

const prompt: TelemetryConsentPrompt = {
  resourceVersion: 1,
  locale: 'en-US',
  title: { id: 'telemetry.consent.title', text: 'Help improve MXC' },
  body: { id: 'telemetry.consent.body', text: 'canonical body' },
  affirmativeLabel: { id: 'telemetry.consent.yes', text: 'Yes' },
  negativeLabel: { id: 'telemetry.consent.no', text: 'No' },
  learnMoreLabel: { id: 'telemetry.consent.learnMore', text: 'Learn more' },
  learnMoreUrl: 'https://example.microsoft.com/consent',
};

function presentationLine(challenge = 'CHALLENGE-1'): string {
  return `${JSON.stringify({
    action: 'request',
    result: 'presentationRequired',
    challenge,
    prompt,
    storedState: 'undetermined',
    effectiveState: 'undetermined',
    needsPrompt: true,
    policy: 'unrestricted',
  })}\n`;
}

function grantedLine(): string {
  return `${JSON.stringify({
    action: 'request',
    result: 'granted',
    storedState: 'granted',
    effectiveState: 'granted',
    needsPrompt: false,
    policy: 'unrestricted',
  })}\n`;
}

async function waitFor(predicate: () => boolean, timeoutMs = 3_000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`waitFor: predicate did not become true within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('defaultConsentProtocolRunner (real code path)', () => {
  beforeEach(() => {
    _setTelemetryPlatform('win32');
    // Ensure the DEFAULT runner is exercised, not one previously injected.
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryConsentRunner(null);
  });

  afterEach(() => {
    _setTelemetryPlatform(null);
    _setTelemetryConsentChildFactory(null);
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryConsentRunner(null);
    _setTelemetryConsentTimeoutMs(null);
  });

  it('assembles a presentationRequired line split across multiple stdout chunks', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    const line = presentationLine();
    // Split the line in three fragments; the runner must accumulate them.
    child.writeStdout(line.slice(0, 10));
    await new Promise((r) => setImmediate(r));
    child.writeStdout(line.slice(10, 40));
    await new Promise((r) => setImmediate(r));
    child.writeStdout(line.slice(40));

    await waitFor(() => child.stdinEnded);
    const echo = JSON.parse(child.stdinChunks.join('').trim());
    assert.strictEqual(echo.decision, 'yes');
    assert.strictEqual(echo.challenge, 'CHALLENGE-1');
    assert.strictEqual(echo.resourceVersion, 1);

    child.writeStdout(grantedLine());
    child.emitClose(0);
    const outcome = await promise;
    assert.strictEqual(outcome.result, 'granted');
  });

  it('suspends the IO timeout while the presenter is thinking', async () => {
    // The runner is documented to clear the IO timeout right before awaiting
    // the presenter and rearm it after. A very short timeout would trip if
    // the presenter's think time were counted toward it.
    _setTelemetryConsentTimeoutMs(200);
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(async (): Promise<'yes'> => {
      await new Promise((r) => setTimeout(r, 500));
      return 'yes';
    });
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    // The 500 ms sleep would trip a naive 200 ms timeout if suspend/resume
    // were broken; we wait for the presenter echo instead.
    await waitFor(() => child.stdinEnded, 3_000);
    child.writeStdout(grantedLine());
    child.emitClose(0);
    const outcome = await promise;
    assert.strictEqual(outcome.result, 'granted');
  });

  it('does not re-arm the IO timeout from stdout or stderr while the presenter is active', async () => {
    _setTelemetryConsentTimeoutMs(100);
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(async (): Promise<'yes'> => {
      box.current.writeStderr('still presenting\n');
      box.current.writeStdout('\n');
      await new Promise((r) => setTimeout(r, 300));
      return 'yes';
    });
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    await waitFor(() => child.stdinEnded, 3_000);
    child.writeStdout(grantedLine());
    child.emitClose(0);
    const outcome = await promise;
    assert.strictEqual(outcome.result, 'granted');
    assert.strictEqual(child.killed, false);
  });

  it('serializes protocol lines before resolving the child close', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(async (): Promise<'yes'> => {
      await new Promise((r) => setTimeout(r, 50));
      return 'yes';
    });
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${presentationLine()}${grantedLine()}`);
    await waitFor(() => child.stdinEnded);
    child.emitClose(0);

    const outcome = await promise;
    assert.strictEqual(outcome.result, 'granted');
    const echo = JSON.parse(child.stdinChunks.join('').trim());
    assert.strictEqual(echo.decision, 'yes');
  });

  it('does not start a queued presenter after the child closes', async () => {
    const box = installFakeChildFactory();
    let presenterCalls = 0;
    const promise = requestTelemetryConsent(() => {
      presenterCalls += 1;
      return new Promise<'yes'>(() => {});
    });
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    child.emitClose(0);

    await assert.rejects(promise, /exited before presentation completed \(0\)/);
    assert.strictEqual(presenterCalls, 0);
    assert.deepStrictEqual(child.stdinChunks, []);
  });

  it('fails closed when the presenter throws and never writes a fallback decision', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => {
      throw new Error('UI unavailable');
    });
    const rejection = assert.rejects(promise, /UI unavailable/);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
    assert.deepStrictEqual(child.stdinChunks, []);
    assert.strictEqual(child.stdinEnded, false);
  });

  it('rejects cleanly on a malformed presentation line and kills the child', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout('this is not json at all\n');
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
    assert.strictEqual(child.killCount, 1);
  });

  it('rejects a status response on the request protocol', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise, /unrecognised telemetry consent output/);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${JSON.stringify({
      action: 'status',
      result: 'status',
      storedState: 'granted',
      effectiveState: 'granted',
      needsPrompt: false,
      policy: 'allowed',
    })}\n`);

    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
    assert.strictEqual(child.killCount, 1);
    assert.deepStrictEqual(child.stdinChunks, []);
  });

  it('does not process queued lines after a protocol failure', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`not json\n${grantedLine()}`);
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
    assert.strictEqual(child.killCount, 1);
    assert.deepStrictEqual(child.stdinChunks, []);
  });

  it('kills the child when stdin fails while replying to the presenter', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(async (): Promise<'yes'> => {
      box.current.stdin.emit('error', new Error('stdin broke'));
      return 'yes';
    });
    const rejection = assert.rejects(promise, /stdin broke/);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
  });

  it('rejects cleanly when the child exits before responding', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStderr('boom\n');
    child.emitClose(2);
    await assert.rejects(promise, /telemetry consent process failed \(2\)/);
  });

  it('fires the IO timeout when the child produces no output at all', async () => {
    _setTelemetryConsentTimeoutMs(50);
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;
    // Do not write to stdout/stderr; the timeout must fire.
    await assert.rejects(promise, /timed out/);
    assert.strictEqual(child.killed, true);
  });

  it('does not let continuous stderr output extend the IO timeout', async () => {
    _setTelemetryConsentTimeoutMs(50);
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;
    const interval = setInterval(() => child.writeStderr('diagnostic\n'), 10);
    try {
      await assert.rejects(promise, /timed out/);
    } finally {
      clearInterval(interval);
    }
    assert.strictEqual(child.killed, true);
  });

  it('does not let partial stdout keep the protocol alive past its deadline', async () => {
    _setTelemetryConsentTimeoutMs(50);
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;
    const interval = setInterval(() => child.writeStdout('x'), 10);
    try {
      await assert.rejects(promise, /timed out/);
    } finally {
      clearInterval(interval);
    }
    assert.strictEqual(child.killed, true);
  });

  it('rejects stdout that exceeds the protocol buffer limit', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout('x'.repeat(1024 * 1024 + 1));

    await assert.rejects(promise, /stdout limit/);
    assert.strictEqual(child.killed, true);
  });

  it('rejects stderr that exceeds the diagnostic buffer limit', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStderr('x'.repeat(64 * 1024 + 1));

    await assert.rejects(promise, /stderr limit/);
    assert.strictEqual(child.killed, true);
  });

  it('rejects more than sixteen protocol lines and kills the child', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout('\n'.repeat(17));

    await assert.rejects(promise, /protocol line limit/);
    assert.strictEqual(child.killed, true);
  });

  it('aborts a pending presenter when the child fails', async () => {
    const box = installFakeChildFactory();
    let observedSignal: AbortSignal | undefined;
    const promise = requestTelemetryConsent((_prompt, signal) => {
      observedSignal = signal;
      return new Promise<'yes'>(() => {});
    });
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    await waitFor(() => observedSignal !== undefined);
    child.emitClose(2);

    await assert.rejects(promise, /exited before presentation completed/);
    assert.strictEqual(observedSignal?.aborted, true);
  });

  it('aborts a pending presenter when the child exits successfully', async () => {
    const box = installFakeChildFactory();
    let observedSignal: AbortSignal | undefined;
    const promise = requestTelemetryConsent((_prompt, signal) => {
      observedSignal = signal;
      return new Promise<'yes'>(() => {});
    });
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(presentationLine());
    await waitFor(() => observedSignal !== undefined);
    child.emitClose(0);

    await assert.rejects(promise, /exited before presentation completed \(0\)/);
    assert.strictEqual(observedSignal?.aborted, true);
  });

  it('kills the child on a presentation missing its challenge', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${JSON.stringify({
      action: 'request',
      result: 'presentationRequired',
      prompt,
      // Missing `challenge`.
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: true,
      policy: 'unrestricted',
    })}\n`);
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
  });
});
