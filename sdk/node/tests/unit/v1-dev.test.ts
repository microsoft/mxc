// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { once } from 'node:events';
import { Console } from 'node:console';
import { inspect } from 'node:util';
import type { InspectOptions } from 'node:util';
import { spawnSync } from 'node:child_process';
import { PassThrough, Readable } from 'node:stream';
import { afterEach, it } from 'node:test';
import { _setBindingRawRunAsyncImplementation } from '../../src/bindings/run.js';
import {
  _setBindingRawSandboxProcessFactory,
  _setStateAwareBindingSandboxProcessFactory,
} from '../../src/bindings/streaming.js';
import {
  _setSpawnBindingSandboxWithPtyJsonImplementation,
  _setExecStateAwareBindingSandboxWithPtyImplementation,
} from '../../src/bindings/pty.js';
import { _setBindingStateAwareAsyncImplementation } from '../../src/bindings/state-aware.js';
import { nativeStatusError } from '../../src/bindings/native-error.js';
import { MxcProcess, type NativeLifecycleDriver } from '../../src/v1/container-process.js';
import { MxcError } from '../../src/v1/errors.js';
import { captureProcessOutput } from '../../src/v1/capture.js';
import { MxcPtyProcess } from '../../src/v1/mxc-pty-process.js';
import { runInContainer } from '../../src/v1/lifecycle.js';
import type { ContainerId } from '../../src/v1/lifecycle-types.js';
import * as dev from '../../src/v1/dev/index.js';

afterEach(() => {
  _setBindingRawRunAsyncImplementation();
  _setBindingRawSandboxProcessFactory();
  _setStateAwareBindingSandboxProcessFactory();
  _setSpawnBindingSandboxWithPtyJsonImplementation();
  _setExecStateAwareBindingSandboxWithPtyImplementation();
  _setBindingStateAwareAsyncImplementation();
});

it('preserves V1 structural errors and existing custom inspection subclasses', () => {
  class ExistingInspection extends MxcError {
    [inspect.custom](depth: number, options: InspectOptions): string {
      return `existing-inspector:${depth}:${options.colors}`;
    }
  }
  const structural: MxcError = Object.assign(new Error('structural'), {
    code: 'backend_error' as const,
  });
  assert.strictEqual(structural.message, 'structural');
  const subclass = new ExistingInspection('backend_error', 'generic');
  assert.ok(inspect(subclass).startsWith('existing-inspector:'));
});

it('keeps structured feedback out of automatic uncaught-error text but in JSON storage', () => {
  const fields = {
    code: 'backend_error' as const,
    message: 'Creation refused.',
    details: { policyFailures: { resource: 'POLICY_UNCAUGHT_MARKER', requiredValue: '18446744073709551615' } },
  };
  const error = new MxcError(fields);
  assert.deepStrictEqual(error.details, fields.details);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(error)).details, fields.details);
  assert.strictEqual(Object.keys(error).includes('details'), false);
  const moduleUrl = new URL('../../src/v1/errors.js', import.meta.url).href;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {inspect} from 'node:util';
    import {MxcError} from ${JSON.stringify(moduleUrl)};
    inspect.defaultOptions.depth = null;
    throw new MxcError(JSON.parse(process.env.POLICY_TEST_FIELDS));
  `], { encoding: 'utf8', env: { ...process.env, POLICY_TEST_FIELDS: JSON.stringify(fields) } });
  assert.strictEqual(result.status, 1, result.stderr);
  assert.ok(result.stderr.includes('Creation refused.'), result.stderr);
  assert.strictEqual(result.stderr.includes('POLICY_UNCAUGHT_MARKER'), false);
  assert.strictEqual(result.stderr.includes('18446744073709551615'), false);
  assert.strictEqual(result.stderr.includes('policyFailures'), false);
});

function fakeProcess(stdout = 'out', stderr = 'err'): MxcProcess {
  const standardOutput = new PassThrough();
  const standardError = new PassThrough();
  const driver: NativeLifecycleDriver = {
    id: 42,
    standardInput: null,
    standardOutput,
    standardError,
    poll: () => ({ exitCode: 7, timedOut: false, running: false }),
    wait: async () => ({ exitCode: 7, timedOut: false }),
    warnings: () => ['warning'],
    outputMetadata: () => undefined,
    kill: () => {},
    killForTimeout: () => {},
    free: async () => {},
  };
  const process = new MxcProcess(driver);
  standardOutput.end(stdout);
  standardError.end(stderr);
  return process;
}

function fakeTerminal(): MxcPtyProcess {
  return new MxcPtyProcess({
    id: 43, standardInput: null, standardOutput: null, standardError: null,
    poll: () => ({ exitCode: 0, timedOut: false, running: true }),
    wait: async () => ({ exitCode: 0, timedOut: false }),
    warnings: () => [], outputMetadata: () => undefined,
    kill: () => {}, killForTimeout: () => {}, free: async () => {},
  }, () => {});
}

it('one-shot capture passes the original JSON and independent authorization', async () => {
  const json = ' { "version":"1.1.0-alpha","process":{"commandLine":"echo","timeout":1e2} } ';
  let received: [string, boolean] | undefined;
  _setBindingRawRunAsyncImplementation(async (request, experimental) => {
    received = [request, experimental];
    return {
      stdout: 'out',
      stderr: 'err',
      exitCode: 7,
      timedOut: false,
      warnings: ['warning'],
    };
  });
  const result = await dev.runJson(json, { experimental: true });
  assert.deepStrictEqual(received, [json, true]);
  assert.deepStrictEqual(result, {
    stdout: 'out', stderr: 'err', exitCode: 7, timedOut: false, warnings: ['warning'],
  });
});

it('one-shot live modes pass the exact request and timeout to their bindings', async () => {
  const json = '{"version":"1.0.0","containment":"seatbelt","process":{"commandLine":"echo","timeout":120}}';
  let pipeArgs: unknown[] = [];
  let ptyArgs: unknown[] = [];
  const pipe = fakeProcess();
  _setBindingRawSandboxProcessFactory(async (...args) => {
    pipeArgs = args;
    return pipe;
  });
  _setSpawnBindingSandboxWithPtyJsonImplementation(async (...args) => {
    ptyArgs = args;
    return fakeTerminal();
  });
  const spawned = await dev.spawnJson(json, { experimental: true });
  const terminal = await dev.spawnWithPtyJson(json, { size: { rows: 30, columns: 90 } });
  assert.strictEqual(spawned, pipe);
  assert.deepStrictEqual(pipeArgs, [json, true, 120, undefined]);
  assert.deepStrictEqual(ptyArgs, [json, false, 30, 90, 120]);
  spawned.dispose();
  terminal.dispose();
});

it('state-aware execution captures streams and preserves container ownership', async () => {
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo","timeout":250}}';
  let received: unknown[] = [];
  const proc = fakeProcess();
  _setStateAwareBindingSandboxProcessFactory((...args) => {
    received = args;
    return proc;
  });
  const output = await dev.runInContainerJson(json, { experimental: true });
  assert.deepStrictEqual(received, [json, true, 250, false]);
  assert.deepStrictEqual(output, {
    stdout: 'out', stderr: 'err', exitCode: 7, timedOut: false, warnings: ['warning'],
  });
  assert.throws(() => proc.standardOutput, /disposed/);
});

it('typed and raw captured execs return partial output when pipes stay open after timeout', {
  timeout: 2000,
}, async () => {
  _setStateAwareBindingSandboxProcessFactory(() => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    stdout.write('partial out');
    stderr.write('partial err');
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: stdout,
      standardError: stderr,
      poll: () => ({ exitCode: -1, timedOut: true, running: false }),
      wait: async () => ({ exitCode: -1, timedOut: true }),
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: async () => {},
    };
    return new MxcProcess(driver);
  });
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  const requests = [
    dev.runInContainerJson(json),
    runInContainer('iso:abc' as ContainerId<'isolation_session'>, { command: 'echo' }),
  ];
  for (const result of await Promise.all(requests)) {
    assert.deepStrictEqual(result, {
      stdout: 'partial out',
      stderr: 'partial err',
      exitCode: -1,
      timedOut: true,
      warnings: [],
    });
  }
});

it('settles capture before a pending native read permits stream close', {
  timeout: 2000,
}, async (t) => {
  for (const waitFails of [false, true]) {
    let finishDestroy: (() => void) | undefined;
    const output = new Readable({
      read() {},
      destroy(_error, callback) {
        finishDestroy = () => callback(null);
      },
    });
    output.push('partial output');
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: output,
      standardError: null,
      poll: () => ({ exitCode: -1, timedOut: true, running: false }),
      wait: async () => {
        if (waitFails) throw new Error('native wait failed');
        return { exitCode: -1, timedOut: true };
      },
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: async () => {},
    };
    const proc = new MxcProcess(driver);
    const externalEnd = () => {};
    const externalClose = () => {};
    const externalError = () => {};
    output.on('end', externalEnd);
    output.on('close', externalClose);
    output.on('error', externalError);
    const concat = t.mock.method(Buffer, 'concat');
    try {
      if (waitFails) {
        await assert.rejects(captureProcessOutput(proc), /native wait failed/);
      } else {
        assert.deepStrictEqual(await captureProcessOutput(proc), {
          result: { exitCode: -1, timedOut: true },
          stdout: 'partial output',
          stderr: '',
        });
      }
      assert.strictEqual(output.destroyed, true);
      assert.strictEqual(output.closed, false);
      assert.deepStrictEqual(output.listeners('end'), [externalEnd]);
      assert.deepStrictEqual(output.listeners('close'), [externalClose]);
      assert.ok(output.listeners('error').includes(externalError));
      assert.strictEqual(concat.mock.callCount(), 1);
      output.emit('end');
      output.emit('error', new Error('late native read failure'));
      const closed = once(output, 'close');
      finishDestroy?.();
      await closed;
      assert.strictEqual(concat.mock.callCount(), 1);
    } finally {
      finishDestroy?.();
      proc.dispose();
      concat.mock.restore();
    }
  }
});

it('preserves the capture failure when process disposal also fails', async () => {
  let cleanupAttempted = false;
  _setStateAwareBindingSandboxProcessFactory(() => {
    const output = new Readable({
      read() { this.destroy(new Error('capture read failed')); },
    });
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: output,
      standardError: null,
      poll: () => ({ exitCode: 0, timedOut: false, running: true }),
      wait: async () => ({ exitCode: 0, timedOut: false }),
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: async () => {},
    };
    const proc = new MxcProcess(driver);
    proc.dispose = () => {
      cleanupAttempted = true;
      throw new Error('dispose failed');
    };
    return proc;
  });
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  await assert.rejects(dev.runInContainerJson(json), /capture read failed/);
  assert.strictEqual(cleanupAttempted, true);
});

it('typed and raw capture reject read failures while process wait is pending', {
  timeout: 2000,
}, async () => {
  const releaseFree: Array<() => void> = [];
  _setStateAwareBindingSandboxProcessFactory(() => {
    const output = new Readable({
      read() { this.destroy(new Error('capture read failed')); },
    });
    const driver: NativeLifecycleDriver = {
      id: 42,
      standardInput: null,
      standardOutput: output,
      standardError: null,
      poll: () => ({ exitCode: 0, timedOut: false, running: true }),
      wait: async () => ({ exitCode: 0, timedOut: false }),
      warnings: () => [],
      outputMetadata: () => undefined,
      kill: () => {},
      killForTimeout: () => {},
      free: () => new Promise<void>((resolve) => {
        releaseFree.push(resolve);
      }),
    };
    return new MxcProcess(driver);
  });
  const json = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  try {
    await Promise.all([
      assert.rejects(dev.runInContainerJson(json), /capture read failed/),
      assert.rejects(
        runInContainer('iso:abc' as ContainerId<'isolation_session'>, { command: 'echo' }),
        /capture read failed/,
      ),
    ]);
  } finally {
    for (const release of releaseFree) release();
  }
});

it('successful stream EOF does not finish capture before process exit', async () => {
  let running = true;
  let captured = false;
  const output = new PassThrough();
  const driver: NativeLifecycleDriver = {
    id: 42,
    standardInput: null,
    standardOutput: output,
    standardError: null,
    poll: () => ({ exitCode: 0, timedOut: false, running }),
    wait: async () => ({ exitCode: 0, timedOut: false }),
    warnings: () => [],
    outputMetadata: () => undefined,
    kill: () => {},
    killForTimeout: () => {},
    free: async () => {},
  };
  const proc = new MxcProcess(driver);
  try {
    const result = captureProcessOutput(proc).then((value) => {
      captured = true;
      return value;
    });
    const ended = new Promise<void>((resolve) => output.once('end', resolve));
    output.end('finished');
    await ended;
    assert.strictEqual(captured, false);
    running = false;
    assert.deepStrictEqual(await result, {
      result: { exitCode: 0, timedOut: false },
      stdout: 'finished',
      stderr: '',
    });
  } finally {
    proc.dispose();
  }
});

it('state-aware pipe and PTY spawns forward exact JSON and terminal controls', async () => {
  const json = ' { "version":"1.1.0-alpha","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo","timeout":300} } ';
  let pipeArgs: unknown[] = [];
  let ptyArgs: unknown[] = [];
  _setStateAwareBindingSandboxProcessFactory((...args) => {
    pipeArgs = args;
    return fakeProcess();
  });
  _setExecStateAwareBindingSandboxWithPtyImplementation(async (...args) => {
    ptyArgs = args;
    return fakeTerminal();
  });
  const proc = await dev.spawnInContainerJson(json, { experimental: true });
  const pty = await dev.spawnInContainerWithPtyJson(json, {
    experimental: true,
    size: { rows: 25, columns: 100 },
  });
  assert.deepStrictEqual(pipeArgs, [json, true, 300, false]);
  assert.deepStrictEqual(ptyArgs, [json, true, 25, 100, 300]);
  proc.dispose();
  pty.dispose();
});

it('all lifecycle phases return the unchanged native response and dry-run flag', async () => {
  const received: Array<{ requestJson: string; dryRun: boolean; experimental: boolean }> = [];
  const reply = '{"result":{"sandboxId":"wsb:123","metadata":{"future":17}}}';
  _setBindingStateAwareAsyncImplementation(async (request) => {
    received.push(request);
    return reply;
  });
  const phases = [
    ['provision', dev.provisionContainerJson, dev.validateProvisionJson],
    ['start', dev.startContainerJson, dev.validateStartJson],
    ['stop', dev.stopContainerJson, dev.validateStopJson],
    ['deprovision', dev.deprovisionContainerJson, dev.validateDeprovisionJson],
  ] as const;
  for (const [phase, execute, validate] of phases) {
    const json = ` { "version":"1.1.0-alpha","phase":"${phase}","sandboxId":"wsb:123" } `;
    assert.strictEqual(await execute(json, { experimental: true }), reply);
    assert.strictEqual(await validate(json, { experimental: true }), reply);
    assert.deepStrictEqual(received.slice(-2), [
      { requestJson: json, experimental: true, dryRun: false },
      { requestJson: json, experimental: true, dryRun: true },
    ]);
  }
  const exec = '{"version":"1.0.0","phase":"exec","sandboxId":"iso:abc","process":{"commandLine":"echo"}}';
  assert.strictEqual(await dev.validateProcessJson(exec), reply);
  assert.deepStrictEqual(received.at(-1), { requestJson: exec, experimental: false, dryRun: true });
});

it('rejects phase mismatches, malformed options and invalid Unicode before native calls', async () => {
  _setBindingStateAwareAsyncImplementation(async () => {
    assert.fail('native must not be called');
  });
  const start = '{"version":"1.0.0","phase":"start","sandboxId":"iso:abc"}';
  await assert.rejects(dev.stopContainerJson(start), { code: 'malformed_request' });
  await assert.rejects(dev.spawnInContainerJson(start), { code: 'malformed_request' });
  await assert.rejects(dev.runJson(start), { code: 'malformed_request' });
  await assert.rejects(dev.validateProcessJson(start), { code: 'malformed_request' });
  // @ts-expect-error Deliberately exercise runtime validation of invalid options.
  await assert.rejects(dev.startContainerJson(start, { experimental: 'yes' }),
    { code: 'malformed_request' });
  // @ts-expect-error Deliberately exercise runtime validation of an invalid PTY size.
  await assert.rejects(dev.spawnWithPtyJson(start, { size: null }),
    { code: 'malformed_request' });
  await assert.rejects(dev.spawnWithPtyJson(start, {
    // @ts-expect-error Unknown PTY size fields must fail at runtime too.
    size: { rows: 24, columns: 80, extra: true },
  }), { code: 'malformed_request' });
  await assert.rejects(dev.startContainerJson(start + '\uD800'), { code: 'malformed_request' });
});

function policyDetail(overrides: Partial<dev.PolicyFailureDetail> = {}): dev.PolicyFailureDetail {
  return {
    failureClass: dev.PolicyFailureClasses.Filesystem,
    failureReason: dev.PolicyFailureReasons.AccessExceedsCeiling,
    requiredAction: dev.PolicyFailureActions.RestrictFilesystemAccess,
    resourceKind: dev.PolicyFailureResourceKinds.Path,
    valueKind: dev.PolicyFailureValueKinds.Access,
    flags: dev.PolicyFailureFlags.HasActionableDetails | dev.PolicyFailureFlags.ResourceComplete,
    requestedValue: dev.PolicyFailureAccessValues.ReadWrite,
    requiredValue: dev.PolicyFailureAccessValues.ReadOnly,
    ...overrides,
  };
}

const policyResourceMarker = 'MXC_POLICY_RESOURCE_STRUCTURED_ONLY_7CDBA9';

function policyFeedback(): dev.PolicyFailures {
  return {
    formatVersion: 1,
    results: [
      {
        version: 1, minimumReaderVersion: 1, outcome: dev.PolicyFailureOutcomes.Blocked,
        details: [
          policyDetail(),
          policyDetail({ resource: [] }),
          policyDetail({ resource: [67, 58, 92, 0xd83d, 0xde00, 0] }),
          policyDetail({
            resource: [...policyResourceMarker].map((character) => character.charCodeAt(0)),
          }),
        ],
      },
      {
        version: 0xffff_ffff, minimumReaderVersion: 0xffff_ffff, outcome: 0xffff_ffff,
        details: [policyDetail({
          failureClass: 0xffff_ffff, failureReason: 0xffff_ffff,
          requiredAction: 0xffff_ffff, resourceKind: 0xffff_ffff,
          valueKind: 0xffff_ffff, flags: 0xffff_ffff,
          requestedValue: '18446744073709551615', requiredValue: '9007199254740993',
          resource: [0xd800, 0],
        })],
      },
    ],
  };
}

it('round-trips cumulative batches without losing numeric codes, u64 values or UTF-16', () => {
  const original = policyFeedback();
  const stored = dev.serializePolicyFailures(original);
  const restored = dev.parsePolicyFailures(stored);
  assert.deepStrictEqual(restored, original);
  assert.deepStrictEqual(JSON.parse(stored).results[0].details[0], {
    failureClass: 2, failureReason: 2, requiredAction: 2, resourceKind: 1,
    valueKind: 1, flags: 3, requestedValue: '2', requiredValue: '1',
  });
  assert.strictEqual(restored.results[0].outcome, dev.PolicyFailureOutcomes.Blocked);
  assert.match(stored, /"18446744073709551615"/);
  assert.match(stored, /"9007199254740993"/);
  const [absent, empty, text] = restored.results[0].details;
  assert.strictEqual(Object.hasOwn(absent, 'resource'), false);
  assert.strictEqual(dev.policyFailureResourceText(absent), undefined);
  assert.strictEqual(dev.policyFailureResourceText(empty), '');
  assert.strictEqual(dev.policyFailureResourceText(text), 'C:\\😀\0');
  assert.throws(() => dev.policyFailureResourceText(restored.results[1].details[0]),
    /malformed UTF-16/);
  assert.throws(() => dev.policyFailureResourceText(policyDetail({ resource: [0xdc00] })),
    /malformed UTF-16/);
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(restored)), original);

  const nullable = {
    ...original,
    results: original.results.map((result, resultIndex) => ({
      ...result,
      details: result.details.map((detail, detailIndex) => (
        resultIndex === 0 && detailIndex === 0 ? { ...detail, resource: null } : detail
      )),
    })),
  };
  const nullableJson = JSON.stringify(nullable);
  const normalized = dev.parsePolicyFailures(nullableJson);
  assert.deepStrictEqual(normalized, original);
  assert.strictEqual(dev.serializePolicyFailures(normalized), stored);
  assert.strictEqual(JSON.stringify(nullable), nullableJson);
});

it('forwards only caller-supplied feedback on the next Dev creation without mutating inputs', async () => {
  const json = ' { "version":"1.1.0-alpha","process":{"commandLine":"echo","timeout":120} } ';
  const report = policyFeedback();
  const terminalDiagnostic = { code: 'feedbackLimitExceeded', reason: 'terminal limit' };
  for (const spawn of [false, true]) {
    const calls: unknown[][] = [];
    const refusal = nativeStatusError(11, {
      message: Buffer.from('creation blocked\0'),
      operation: Buffer.from('CreateProcessSecurityEnvironment\0'),
      nativeCode: Buffer.from(dev.PolicyFailureNativeCodes.PolicyBlocked + '\0'),
      detailsJson: Buffer.from(JSON.stringify({
        policyFailures: report, backendDetail: 'retained',
        policyFeedbackError: terminalDiagnostic, policyResultUnavailable: 'native result unavailable',
      }) + '\0'),
    });
    const recordCall = (...args: unknown[]) => {
      calls.push(args);
      if (calls.length === 1) throw refusal;
    };
    if (spawn) {
      _setBindingRawSandboxProcessFactory(async (...args) => {
        recordCall(...args);
        return fakeProcess();
      });
    } else {
      _setBindingRawRunAsyncImplementation(async (...args) => {
        recordCall(...args);
        return {
          stdout: 'out', stderr: 'err', exitCode: 0, timedOut: false, warnings: ['ordinary warning'],
        };
      });
    }
    const create = spawn ? dev.spawnJson : dev.runJson;
    await assert.rejects(create(json), (error: unknown) => error === refusal);
    assert.strictEqual(calls.length, 1, 'a refusal must not trigger an SDK retry');
    assert.strictEqual(refusal.message, 'creation blocked');
    assert.strictEqual(refusal.toString(), 'MxcError: creation blocked');
    assert.strictEqual(refusal.operation, 'CreateProcessSecurityEnvironment');
    assert.strictEqual(refusal.nativeCode, '0x800704EC');
    assert.strictEqual(typeof refusal.stack, 'string');
    const policyFragments = [
      policyResourceMarker, 'policyFailures', '4294967295',
      '18446744073709551615', '9007199254740993', 'feedbackLimitExceeded', 'terminal limit',
    ];
    let logged = '';
    const logStream = new PassThrough();
    logStream.on('data', (chunk) => { logged += chunk.toString(); });
    const logger = new Console({
      stdout: logStream, stderr: logStream, inspectOptions: { depth: null },
    });
    logger.error(refusal);
    const finished = once(logStream, 'finish');
    logStream.end();
    await finished;
    const renderedError = [
      refusal.message, refusal.toString(), String(refusal), refusal.stack,
      inspect(refusal, { depth: null }), logged,
    ].join('\n');
    for (const fragment of policyFragments) {
      assert.strictEqual(renderedError.includes(fragment), false,
        'error text must not expose structured policy data');
    }
    assert.strictEqual(refusal.details?.ffiStatus, 11);
    assert.strictEqual(refusal.details?.backendDetail, 'retained');
    assert.deepStrictEqual(refusal.details?.policyFeedbackError, terminalDiagnostic);
    assert.strictEqual(refusal.details?.policyResultUnavailable, 'native result unavailable');
    const feedback = dev.policyFailuresFromError(refusal);
    assert.ok(feedback);
    assert.deepStrictEqual(feedback, report);
    const restored = dev.parsePolicyFailures(dev.serializePolicyFailures(feedback));
    assert.deepStrictEqual(restored, report);
    assert.strictEqual(
      dev.policyFailureResourceText(restored.results[0].details[3]), policyResourceMarker,
    );
    const options = Object.freeze({ experimental: true, policyFailures: feedback });
    const before = JSON.stringify(options);
    const result = await create(json, options);
    assert.deepStrictEqual(result.warnings, spawn ? ['warning'] : ['ordinary warning']);
    for (const fragment of policyFragments) {
      assert.strictEqual(result.warnings.some((warning) => warning.includes(fragment)), false,
        'warnings must not expose structured policy data');
    }
    if (result instanceof MxcProcess) result.dispose();
    assert.deepStrictEqual(calls[1], spawn
      ? [json, true, 120, dev.serializePolicyFailures(report)]
      : [json, true, dev.serializePolicyFailures(report)]);
    assert.strictEqual(JSON.stringify(options), before);
    assert.deepStrictEqual(report, policyFeedback());
    const strict = await create(json);
    if (strict instanceof MxcProcess) strict.dispose();
    assert.deepStrictEqual(calls[2], spawn
      ? [json, false, 120, undefined] : [json, false, undefined]);
    assert.strictEqual(calls.length, 3, 'feedback must not be cached for later calls');
  }
});

it('retains terminal feedback beyond reapplication limits for inspection and storage', () => {
  const terminal: dev.PolicyFailures = {
    formatVersion: 1,
    results: Array.from({ length: 65 }, (_, outcome) => ({
      version: 1, minimumReaderVersion: 1, outcome, details: [],
    })),
  };
  const error = new MxcError('policy_validation', 'creation blocked', {
    policyFailures: terminal,
    policyFeedbackError: { code: 'feedbackLimitExceeded', reason: 'input result limit exceeded' },
  });
  assert.deepStrictEqual(dev.policyFailuresFromError(error), terminal);
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(terminal)), terminal);
  terminal.results.push({ version: 1, minimumReaderVersion: 1, outcome: 66, details: [] });
  assert.throws(() => dev.serializePolicyFailures(terminal), /at most 65/);

  const details: dev.PolicyFailures = {
    formatVersion: 1,
    results: Array.from({ length: 17 }, () => ({
      version: 1, minimumReaderVersion: 1, outcome: 1,
      details: Array.from({ length: 64 }, () => policyDetail()),
    })),
  };
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(details)), details);
  details.results.push({
    version: 1, minimumReaderVersion: 1, outcome: 1, details: [policyDetail()],
  });
  assert.throws(() => dev.serializePolicyFailures(details), /cumulative detail storage limit/);
  details.results.pop();
  details.results[0].details.push(policyDetail());
  assert.throws(() => dev.serializePolicyFailures(details), /at most 64/);

  const resources: dev.PolicyFailures = {
    formatVersion: 1,
    results: Array.from({ length: 9 }, () => ({
      version: 1, minimumReaderVersion: 1, outcome: 1,
      details: [policyDetail({ resource: Array<number>(32_767).fill(0) })],
    })),
  };
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(resources)), resources);
  resources.results.push({
    version: 1, minimumReaderVersion: 1, outcome: 1, details: [policyDetail({ resource: [] })],
  });
  assert.throws(() => dev.serializePolicyFailures(resources), /cumulative resource storage limit/);
  resources.results.pop();
  resources.results[0].details.push(policyDetail({ resource: [] }));
  assert.throws(() => dev.serializePolicyFailures(resources), /per-result resource limit/);
});

it('distinguishes absent error feedback from malformed reports and rejects invalid shapes', async () => {
  assert.strictEqual(dev.policyFailuresFromError(new Error('ordinary error')), undefined);
  assert.strictEqual(dev.policyFailuresFromError(new MxcError('backend_error', 'absent')), undefined);
  assert.strictEqual(dev.policyFailuresFromError(new MxcError('backend_error', 'absent', {})), undefined);
  const valid = policyFeedback();
  const invalidDetail = (override: Record<string, unknown>) => ({
    formatVersion: 1,
    results: [{
      version: 1, minimumReaderVersion: 1, outcome: 1,
      details: [{ ...policyDetail(), ...override }],
    }],
  });
  const missing = invalidDetail({});
  delete (missing.results[0].details[0] as Partial<dev.PolicyFailureDetail>).requestedValue;
  for (const value of [
    null, [], {}, { results: [] }, { formatVersion: 1 }, { formatVersion: 2, results: [] },
    { ...valid, extra: true }, invalidDetail({ requestedValue: 9007199254740992 }),
    invalidDetail({ requiredValue: '18446744073709551616' }),
    invalidDetail({ requestedValue: '-1' }), invalidDetail({ flags: 1.5 }),
    invalidDetail({ failureClass: 0x1_0000_0000 }), invalidDetail({ resource: [65536] }),
    invalidDetail({ resource: [1, null] }), invalidDetail({ resource: 'path' }), missing,
  ]) {
    assert.throws(() => dev.parsePolicyFailures(JSON.stringify(value)), { code: 'malformed_request' });
    assert.throws(() => dev.policyFailuresFromError(new MxcError('backend_error', 'bad', {
      policyFailures: value,
    })), { code: 'malformed_request' });
  }
  assert.throws(() => dev.parsePolicyFailures('{'), { code: 'malformed_request' });
  assert.throws(() => dev.parsePolicyFailures(' '.repeat(4.5 * 1024 * 1024 + 1)),
    { code: 'malformed_request' });
  _setBindingRawRunAsyncImplementation(async () => assert.fail('native must not be called'));
  await assert.rejects(dev.runJson('{}', { policyFailures: {} as dev.PolicyFailures }),
    { code: 'malformed_request' });
});

it('rejects creation feedback on every unsupported Dev operation before dispatch', async () => {
  const options: dev.CreationJsonOptions = { policyFailures: policyFeedback() };
  const unsupported = [
    dev.spawnWithPtyJson, dev.runInContainerJson, dev.spawnInContainerJson,
    dev.spawnInContainerWithPtyJson, dev.provisionContainerJson,
    dev.startContainerJson, dev.stopContainerJson, dev.deprovisionContainerJson,
    dev.validateProvisionJson, dev.validateStartJson, dev.validateStopJson,
    dev.validateDeprovisionJson, dev.validateProcessJson,
  ];
  for (const invoke of unsupported) {
    await assert.rejects(invoke('{}', options), /does not support option 'policyFailures'/);
    await assert.rejects(invoke('{}', { policyFailures: undefined } as dev.CreationJsonOptions),
      /does not support option 'policyFailures'/);
    await assert.rejects(invoke('{}', Object.create(options) as dev.CreationJsonOptions),
      /does not support option 'policyFailures'/);
  }
});
