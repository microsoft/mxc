// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Exercises the production protocol runner with controlled child-process I/O.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { PassThrough, type Readable, type Writable } from 'node:stream';
import type { ChildProcess } from 'node:child_process';

import {
  requestTelemetryConsent,
  _setTelemetryPlatform,
  _setTelemetryConsentChildFactory,
  _setTelemetryConsentProtocolRunner,
  _setTelemetryConsentTimeoutMs,
  _resetTelemetryFailureReporting,
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
function installFakeChildFactory(): { current: FakeChild; args: readonly string[] } {
  const box: { current: FakeChild; args: readonly string[] } = {
    current: null as unknown as FakeChild,
    args: [],
  };
  _setTelemetryConsentChildFactory((args) => {
    box.args = args;
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
const yesDecisionFixture = JSON.parse(readFileSync(
  new URL('../../../../../tests/fixtures/telemetry-consent/presenter-decision-yes.json', import.meta.url),
  'utf8',
)) as Record<string, unknown>;

function presentationLine(challenge = 'request-a'): string {
  return `${JSON.stringify({
    action: 'request',
    result: 'presentationRequired',
    challenge,
    prompt,
    storedState: 'undetermined',
    effectiveState: 'undetermined',
    needsPrompt: true,
    policy: 'unrestricted',
    reason: null,
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
    reason: null,
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
    _resetTelemetryFailureReporting();
  });

  afterEach(() => {
    _setTelemetryPlatform(null);
    _setTelemetryConsentChildFactory(null);
    _setTelemetryConsentProtocolRunner(null);
    _setTelemetryConsentTimeoutMs(null);
  });

  it('assembles a presentationRequired line split across multiple stdout chunks', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;
    assert.deepStrictEqual(box.args, [
      '--telemetry-consent',
      'request',
    ]);
    assert.ok(!box.args.includes('--config-base64'));

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
    assert.deepStrictEqual(echo, yesDecisionFixture);

    child.writeStdout(grantedLine());
    child.emitClose(0);
    const outcome = await promise;
    assert.strictEqual(outcome.result, 'granted');
    assert.strictEqual(Object.hasOwn(outcome, 'challenge'), false);
    assert.strictEqual(Object.hasOwn(outcome, 'prompt'), false);
  });

  it('reports successful native request diagnostics once', async () => {
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '));
    try {
      const box = installFakeChildFactory();
      const promise = requestTelemetryConsent(() => 'yes');
      await new Promise((r) => setImmediate(r));
      const child = box.current;

      child.writeStderr('mxc: telemetry administrative policy failure\n');
      child.writeStdout(presentationLine());
      await waitFor(() => child.stdinEnded);
      child.writeStdout(grantedLine());
      child.emitClose(0);

      assert.strictEqual((await promise).result, 'granted');
    } finally {
      console.warn = originalWarn;
    }
    assert.deepStrictEqual(warnings, [
      'mxc-sdk: requestTelemetryConsent native diagnostic: '
        + 'mxc: telemetry administrative policy failure',
    ]);
  });

  it('passes the requested locale only on the dedicated request command', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'dismissed', 'fr-FR');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    assert.deepStrictEqual(box.args, [
      '--telemetry-consent',
      'request',
      '--telemetry-consent-locale=fr-FR',
    ]);
    child.writeStdout(`${JSON.stringify({
      action: 'request',
      result: 'dismissed',
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: true,
      policy: 'unrestricted',
      reason: null,
    })}\n`);
    child.emitClose(0);
    assert.strictEqual((await promise).result, 'dismissed');
  });

  it('rejects multiple terminal responses', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));

    box.current.writeStdout(grantedLine() + grantedLine());

    await assert.rejects(promise, /multiple terminal responses/);
    assert.strictEqual(box.current.killCount, 1);
  });

  it('rejects a presentation after a terminal response', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));

    box.current.writeStdout(grantedLine() + presentationLine());

    await assert.rejects(promise, /presentation after its terminal response/);
    assert.strictEqual(box.current.killCount, 1);
  });

  it('rejects multiple presentations', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));

    box.current.writeStdout(presentationLine() + presentationLine('request-b'));

    await assert.rejects(promise, /multiple presentations/);
    assert.strictEqual(box.current.killCount, 1);
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

  it('fails closed when a dynamically typed presenter returns an invalid decision', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'maybe' as unknown as 'yes');
    const rejection = assert.rejects(promise, /invalid decision 'maybe'/);
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
      reason: null,
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

  it('fails closed when the child stdout stream errors', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.stdout.emit('error', new Error('stdout broke'));

    await assert.rejects(promise, /stdout broke/);
    assert.strictEqual(child.killed, true);
    assert.strictEqual(child.killCount, 1);
  });

  it('fails closed when the child stderr stream errors', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.stderr.emit('error', new Error('stderr broke'));

    await assert.rejects(promise, /stderr broke/);
    assert.strictEqual(child.killed, true);
    assert.strictEqual(child.killCount, 1);
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

  it('counts an unterminated final line against the protocol limit', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${'\n'.repeat(16)}partial`);
    child.emitClose(0);

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
      reason: null,
    })}\n`);
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
  });

  it('kills the child on a presentation with a malformed prompt', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${JSON.stringify({
      action: 'request',
      result: 'presentationRequired',
      prompt: { ...prompt, title: { id: 1, text: 'invalid' } },
      challenge: 'request-a',
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: true,
      policy: 'unrestricted',
      reason: null,
    })}\n`);
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
  });

  it('kills the child when a response omits its required reason field', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise, /unrecognised telemetry consent output/);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${JSON.stringify({
      action: 'request',
      result: 'policyBlocked',
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: false,
      policy: 'blocked',
    })}\n`);
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
  });

  it('kills the child on an unknown status reason', async () => {
    const box = installFakeChildFactory();
    const promise = requestTelemetryConsent(() => 'yes');
    const rejection = assert.rejects(promise);
    await new Promise((r) => setImmediate(r));
    const child = box.current;

    child.writeStdout(`${JSON.stringify({
      action: 'request',
      result: 'policyBlocked',
      storedState: 'undetermined',
      effectiveState: 'undetermined',
      needsPrompt: false,
      reason: 'future-reason',
      policy: 'blocked',
    })}\n`);
    await waitFor(() => child.killed);
    child.emitClose(1);
    await rejection;
  });
});
