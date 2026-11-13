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
import { _setBindingPolicyPreparationAsyncImplementation } from '../../src/bindings/policy-preparation.js';
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
import * as v1 from '../../src/v1/index.js';
import * as root from '../../src/index.js';

afterEach(() => {
  _setBindingRawRunAsyncImplementation();
  _setBindingPolicyPreparationAsyncImplementation();
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

it('keeps structured policy failures out of automatic uncaught-error text but in JSON storage', () => {
  const fields = {
    code: 'backend_error' as const,
    message: 'Creation refused.',
    details: { policyFailures: { resource: 'POLICY_UNCAUGHT_MARKER', requiredValue: '18446744073709551615' } },
  };
  const error = new MxcError(fields);
  assert.deepStrictEqual(error.details, fields.details);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(error)).details, fields.details);
  assert.deepStrictEqual({ ...error }.details, fields.details);
  assert.deepStrictEqual(Object.assign({}, error).details, fields.details);
  assert.strictEqual(inspect(error, { depth: null }).includes('POLICY_UNCAUGHT_MARKER'), false);
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
  assert.deepStrictEqual(pipeArgs, [json, true, 120]);
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

function policyResult(
  details: dev.PolicyFailureDetail[] = [],
  outcome: number = dev.PolicyFailureOutcomes.Blocked,
): dev.PolicyFailureResult {
  return {
    version: dev.PolicyFailureVersions.Result,
    minimumReaderVersion: dev.PolicyFailureVersions.MinimumReader,
    outcome,
    details,
  };
}

function policyReport(results: dev.PolicyFailureResult[] = []): dev.PolicyFailures {
  return { formatVersion: dev.PolicyFailureVersions.Format, results };
}

const policyResourceMarker = 'MXC_POLICY_RESOURCE_STRUCTURED_ONLY_7CDBA9';

function samplePolicyFailures(): dev.PolicyFailures {
  return policyReport([
    policyResult([
      policyDetail(),
      policyDetail({ resource: '' }),
      policyDetail({ resource: 'C:\\😀\0' }),
      policyDetail({ resource: policyResourceMarker }),
    ]),
    {
      version: 0xffff_ffff, minimumReaderVersion: 0xffff_ffff, outcome: 0xffff_ffff,
      details: [policyDetail({
        failureClass: 0xffff_ffff, failureReason: 0xffff_ffff,
        requiredAction: 0xffff_ffff, resourceKind: 0xffff_ffff,
        valueKind: 0xffff_ffff, flags: 0xffff_ffff,
        requestedValue: '18446744073709551615', requiredValue: '9007199254740993',
        resource: 'C:\\data\0',
      })],
    },
  ]);
}

it('round-trips merged batches without losing numeric codes, u64 values or UTF-16', () => {
  const original = samplePolicyFailures();
  const stored = dev.serializePolicyFailures(original);
  const restored = dev.parsePolicyFailures(stored);
  assert.deepStrictEqual(restored, original);
  assert.deepStrictEqual(JSON.parse(stored).results[0].details[0], policyDetail());
  assert.strictEqual(restored.results[0].outcome, dev.PolicyFailureOutcomes.Blocked);
  assert.match(stored, /"18446744073709551615"/);
  assert.match(stored, /"9007199254740993"/);
  const [absent, empty, text] = restored.results[0].details;
  assert.strictEqual(Object.hasOwn(absent, 'resource'), false);
  assert.strictEqual(empty.resource, '');
  assert.strictEqual(text.resource, 'C:\\😀\0');
  assert.strictEqual(restored.results[1].details[0].resource, 'C:\\data\0');
  assert.match(stored, /"resource":"C:\\\\😀\\u0000"/);
  for (const resource of [{ resource: '\ud800' }, { resource: '\udc00' }]) {
    assert.throws(() => dev.parsePolicyFailures(JSON.stringify(
      policyReport([policyResult([policyDetail(resource)])]))), { code: 'malformed_request' });
    assert.throws(() => dev.serializePolicyFailures(
      policyReport([policyResult([policyDetail(resource)])])), { code: 'malformed_request' });
  }
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

it('separates preparation, application acceptance and strict creation without mutating inputs', async () => {
  const json = ' { "version":"1.1.0-alpha","process":{"commandLine":"echo","timeout":120} } ';
  const report = samplePolicyFailures();
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
    assert.strictEqual(refusal.nativeCode, dev.PolicyFailureNativeCodes.PolicyBlocked);
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
    const failures = dev.policyFailuresFromError(refusal);
    assert.ok(failures);
    assert.deepStrictEqual(failures, report);
    const restored = dev.parsePolicyFailures(dev.serializePolicyFailures(failures));
    assert.deepStrictEqual(restored, report);
    assert.strictEqual(restored.results[0].details[3].resource, policyResourceMarker);
    const candidate: dev.PreparedPolicyRequest = {
      requestJson: json.replace('"timeout":120', '"timeout":100'),
      changes: [{ operation: 'replace', path: '/process/timeout', before: 120, after: 100 }],
    };
    const options: dev.PolicyPreparationOptions = Object.freeze({ experimental: true });
    const before = JSON.stringify({ options, failures });
    const preparationCalls: unknown[][] = [];
    _setBindingPolicyPreparationAsyncImplementation(async (...args) => {
      preparationCalls.push(args);
      return dev.serializePreparedPolicyRequest(candidate);
    });
    const prepared = await dev.preparePolicyJson(json, failures, options);
    assert.deepStrictEqual(prepared, candidate);
    assert.deepStrictEqual(preparationCalls, [[json, dev.serializePolicyFailures(report), true]]);
    assert.strictEqual(calls.length, 1, 'preparation does not start a workload');
    assert.strictEqual(JSON.stringify({ options, failures }), before);
    // The application inspects the report before choosing to submit the candidate.
    assert.deepStrictEqual(prepared.changes[0], {
      operation: 'replace', path: '/process/timeout', before: 120, after: 100,
    });
    const result = await create(prepared.requestJson, { experimental: true });
    assert.deepStrictEqual(result.warnings, spawn ? ['warning'] : ['ordinary warning']);
    for (const fragment of policyFragments) {
      assert.strictEqual(result.warnings.some((warning) => warning.includes(fragment)), false,
        'warnings must not expose structured policy data');
    }
    if (result instanceof MxcProcess) result.dispose();
    assert.deepStrictEqual(calls[1], spawn
      ? [candidate.requestJson, true, 100] : [candidate.requestJson, true]);
    assert.deepStrictEqual(report, samplePolicyFailures());
    failures.results[0].details[0].flags = dev.PolicyFailureFlags.None;
    assert.deepStrictEqual(report, samplePolicyFailures(), 'extraction returned an owned report');
    const strict = await create(json);
    if (strict instanceof MxcProcess) strict.dispose();
    assert.deepStrictEqual(calls[2], spawn
      ? [json, false, 120] : [json, false]);
    assert.strictEqual(calls.length, 3, 'policy failures must not be cached for later calls');
    assert.strictEqual(preparationCalls.length, 1, 'creation does not trigger preparation');
  }
});

it('retains terminal policy failures beyond preparation limits for inspection and storage', () => {
  const terminal = policyReport(Array.from({ length: 65 }, (_, outcome) => policyResult([], outcome)));
  const error = new MxcError('policy_validation', 'creation blocked', {
    policyFailures: terminal,
    policyFeedbackError: { code: 'feedbackLimitExceeded', reason: 'input result limit exceeded' },
  });
  assert.deepStrictEqual(dev.policyFailuresFromError(error), terminal);
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(terminal)), terminal);
  terminal.results.push(policyResult([], 66));
  assert.throws(() => dev.serializePolicyFailures(terminal), /at most 65/);

  const details = policyReport(Array.from({ length: 17 }, () => (
    policyResult(Array.from({ length: 64 }, () => policyDetail())))));
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(details)), details);
  details.results.push(policyResult([policyDetail()]));
  assert.throws(() => dev.serializePolicyFailures(details), /total detail storage limit/);
  details.results.pop();
  details.results[0].details.push(policyDetail());
  assert.throws(() => dev.serializePolicyFailures(details), /at most 64/);

  const resources = policyReport(Array.from({ length: 9 }, () => (
    policyResult([policyDetail({ resource: '\0'.repeat(32_767) })]))));
  assert.deepStrictEqual(dev.parsePolicyFailures(dev.serializePolicyFailures(resources)), resources);
  resources.results.push(policyResult([policyDetail({ resource: '' })]));
  assert.throws(() => dev.serializePolicyFailures(resources), /total resource storage limit/);
  resources.results.pop();
  resources.results[0].details.push(policyDetail({ resource: '' }));
  assert.throws(() => dev.serializePolicyFailures(resources), /per-result resource limit/);
  const oversized = policyReport([policyResult([policyDetail({ resource: '\0'.repeat(32_768) })])]);
  assert.throws(() => dev.serializePolicyFailures(oversized), /per-result resource limit/);
});

it('distinguishes absent error policy failures from malformed reports and rejects invalid shapes', async () => {
  assert.strictEqual(dev.policyFailuresFromError(new Error('ordinary error')), undefined);
  assert.strictEqual(dev.policyFailuresFromError(new MxcError('backend_error', 'absent')), undefined);
  assert.strictEqual(dev.policyFailuresFromError(new MxcError('backend_error', 'absent', {})), undefined);
  const valid = samplePolicyFailures();
  const invalidDetail = (override: Record<string, unknown>) => (
    policyReport([policyResult([{ ...policyDetail(), ...override }])]));
  const missing = invalidDetail({});
  delete (missing.results[0].details[0] as Partial<dev.PolicyFailureDetail>).requestedValue;
  const format = dev.PolicyFailureVersions.Format;
  for (const value of [
    null, [], {}, { results: [] }, { formatVersion: format }, { formatVersion: format + 1, results: [] },
    { ...valid, extra: true }, invalidDetail({ requestedValue: 9007199254740992 }),
    invalidDetail({ requiredValue: '18446744073709551616' }),
    invalidDetail({ requestedValue: '-1' }), invalidDetail({ flags: 1.5 }),
    invalidDetail({ failureClass: 0x1_0000_0000 }), invalidDetail({ resourceUnits: [0xd800] }),
    invalidDetail({ resource: 1 }), invalidDetail({ resource: ['p'] }), missing,
  ]) {
    assert.throws(() => dev.parsePolicyFailures(JSON.stringify(value)), { code: 'malformed_request' });
    assert.throws(() => dev.policyFailuresFromError(new MxcError('backend_error', 'bad', {
      policyFailures: value,
    })), { code: 'backend_error', message: 'native policy failures are malformed' });
  }
  assert.throws(() => dev.parsePolicyFailures('{'), { code: 'malformed_request' });
  assert.throws(() => dev.parsePolicyFailures(' '.repeat(4.5 * 1024 * 1024 + 1)),
    { code: 'malformed_request' });
});

it('rejects duplicate keys in stored observations and preparation results', () => {
  const duplicate = { code: 'malformed_request', message: /duplicate JSON object keys/ };
  const format = dev.PolicyFailureVersions.Format;
  assert.throws(() => dev.parsePolicyFailures(
    `{"formatVersion":${format},"formatVersion":${format},"results":[]}`), duplicate);
  assert.throws(() => dev.parsePolicyFailures(
    `{"formatVersion":${format},"results":[],"\\u0066ormatVersion":${format}}`), duplicate);
  assert.throws(() => dev.parsePreparedPolicyRequest(
    '{"requestJson":"{}","changes":[],"changes":[]}'), duplicate);
  const change = (after: string) => '{"requestJson":"{}","changes":[{"operation":"add",'
    + `"path":"/x","before":null,"after":${after}}]}`;
  assert.throws(() => dev.parsePreparedPolicyRequest(change('[{"k\\"}":1,"k\\u0022}":2}]')), duplicate);
  // Keys repeat across separate objects; strings contain quotes, backslashes and braces.
  const after = '[{"k":"{\\"k\\":1}","k\\\\":"]"},{"k":{"k":"\\\\"}}]';
  assert.deepStrictEqual(dev.parsePreparedPolicyRequest(change(after)).changes[0].after,
    [{ k: '{"k":1}', 'k\\': ']' }, { k: { k: '\\' } }]);
});

it('rejects policy failures in creation options as an unsupported option', async () => {
  _setBindingRawRunAsyncImplementation(async () => assert.fail('native must not be called'));
  // @ts-expect-error Creation options do not accept policy failures.
  await assert.rejects(dev.runJson('{}', { policyFailures: samplePolicyFailures() }),
    { code: 'malformed_request', message: "runJson does not support option 'policyFailures'" });
  await assert.rejects(dev.preparePolicyJson('{}', samplePolicyFailures(), {
    experimental: true, policyFailures: samplePolicyFailures(),
  } as dev.PolicyPreparationOptions), /preparePolicyJson does not support option 'policyFailures'/);
});

it('keeps preparation and policy failure helpers on the Dev subpath only', () => {
  for (const name of [
    'preparePolicyJson', 'parsePreparedPolicyRequest', 'serializePreparedPolicyRequest',
    'mergePolicyFailures', 'parsePolicyFailures', 'serializePolicyFailures',
  ]) {
    assert.strictEqual(typeof (dev as Record<string, unknown>)[name], 'function');
    assert.strictEqual(name in v1, false);
    assert.strictEqual(name in root, false);
  }
});

it('stores ordered edits with required before/after values and distinct real nulls', () => {
  const prepared: dev.PreparedPolicyRequest = {
    requestJson: ' { "version":"1.0.0","process":{"commandLine":"echo"} } ',
    changes: [
      { operation: 'add', path: '/filesystem/deniedPaths', before: null, after: ['C:\\private'] },
      { operation: 'remove', path: '/processContainer/capabilities/0', before: 'internetClient', after: null },
      { operation: 'replace', path: '/a~1b/~0value', before: null, after: { allowed: false, limit: 1.5 } },
      { operation: 'replace', path: '', before: [true, 1, 'text', { nested: null }], after: null },
      { operation: 'add', path: '/explicitNull', before: null, after: null },
      { operation: 'remove', path: '/previousNull', before: null, after: null },
    ],
  };
  const before = JSON.stringify(prepared);
  const stored = dev.serializePreparedPolicyRequest(prepared);
  assert.strictEqual(JSON.stringify(prepared), before);
  const restored = dev.parsePreparedPolicyRequest(stored);
  assert.deepStrictEqual(restored, prepared);
  assert.ok(restored.changes.every((change) => Object.hasOwn(change, 'before')
    && Object.hasOwn(change, 'after')));
  (restored.changes[0].after as dev.JsonValue[]).push('another path');
  assert.strictEqual(JSON.stringify(prepared), before, 'returned JSON values are owned');

  const special = dev.parsePreparedPolicyRequest(
    '{"requestJson":"{}","changes":[{"operation":"replace","path":"/__proto__",'
    + '"before":{"__proto__":{"value":true}},"after":null}]}',
  );
  assert.strictEqual(Object.hasOwn(special.changes[0].before as object, '__proto__'), true);
  assert.deepStrictEqual(dev.parsePreparedPolicyRequest(dev.serializePreparedPolicyRequest(special)), special);
});

it('rejects malformed preparation results and invalid JSON values without input disclosure', async () => {
  const valid = {
    requestJson: '{}',
    changes: [{ operation: 'replace', path: '/policy', before: null, after: true }],
  };
  const marker = 'PREPARATION_INPUT_MUST_NOT_RENDER';
  const change = (overrides: Record<string, unknown>) => ({
    ...valid, changes: [{ ...valid.changes[0], ...overrides }],
  });
  const missingBefore = change({});
  delete (missingBefore.changes[0] as Record<string, unknown>).before;
  const missingAfter = change({});
  delete (missingAfter.changes[0] as Record<string, unknown>).after;
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  const invalid = [
    null, [], {}, { ...valid, extra: true }, { ...valid, requestJson: marker },
    { ...valid, changes: null }, missingBefore, missingAfter,
    change({ operation: 'copy' }), change({ path: '#/policy' }), change({ path: '/bad~2escape' }),
    change({ path: '/bad~' }), change({ extra: true }),
    change({ operation: 'add', before: false }), change({ operation: 'remove', after: false }),
    change({ before: undefined }), change({ after: Infinity }), change({ after: NaN }),
    change({ after: 1n }), change({ after: () => marker }), change({ after: new Date() }),
    change({ after: [undefined] }), change({ after: { value: undefined } }),
    change({ after: '\ud800' }), change({ after: circular }),
  ];
  for (const value of invalid) {
    assert.throws(() => dev.serializePreparedPolicyRequest(value as dev.PreparedPolicyRequest),
      (error: unknown) => error instanceof MxcError && error.code === 'malformed_request'
        && ![error.message, error.stack, inspect(error)].join('\n').includes(marker));
  }
  for (const json of [
    `{${marker}`, JSON.stringify(missingBefore), JSON.stringify(missingAfter),
    '{"requestJson":"{}","changes":[{"operation":"replace","path":"/policy","before":1e400,"after":null}]}',
  ]) {
    assert.throws(() => dev.parsePreparedPolicyRequest(json),
      (error: unknown) => error instanceof MxcError && error.code === 'malformed_request'
        && ![error.message, error.stack, inspect(error)].join('\n').includes(marker));
    _setBindingPolicyPreparationAsyncImplementation(async () => json);
    await assert.rejects(dev.preparePolicyJson('{}', policyReport()),
      (error: unknown) => error instanceof MxcError && error.code === 'backend_error'
        && ![error.message, error.stack, inspect(error)].join('\n').includes(marker));
  }
});

it('bounds preparation request UTF-8, result JSON and edit counts before use', async () => {
  const failures = policyReport();
  let calls = 0;
  _setBindingPolicyPreparationAsyncImplementation(async (requestJson) => {
    calls += 1;
    return JSON.stringify({ requestJson, changes: [] });
  });
  const prefix = '{"text":"';
  const suffix = '"}';
  const request = prefix + 'é'.repeat((8 * 1024 * 1024 - prefix.length - suffix.length - 1) / 2)
    + 'x' + suffix;
  assert.strictEqual(Buffer.byteLength(request, 'utf8'), 8 * 1024 * 1024);
  assert.strictEqual((await dev.preparePolicyJson(request, failures)).requestJson, request);
  for (const json of [request + ' ', '{"text":"\ud800"}', '{}\0{}', '[]', '{']) {
    await assert.rejects(dev.preparePolicyJson(json, failures), { code: 'malformed_request' });
  }
  await assert.rejects(dev.preparePolicyJson('{}', {} as dev.PolicyFailures), { code: 'malformed_request' });
  // @ts-expect-error Preparation validates its independent authorization options.
  await assert.rejects(dev.preparePolicyJson('{}', failures, { experimental: 'true' }),
    { code: 'malformed_request' });
  assert.strictEqual(calls, 1, 'invalid preparation inputs never reach native');
  const grownCandidate = { requestJson: request + ' ', changes: [] };
  const grownJson = dev.serializePreparedPolicyRequest(grownCandidate);
  assert.deepStrictEqual(dev.parsePreparedPolicyRequest(grownJson), grownCandidate);
  _setBindingPolicyPreparationAsyncImplementation(async () => grownJson);
  assert.deepStrictEqual(await dev.preparePolicyJson('{}', failures), grownCandidate,
    'the 8 MiB input bound does not limit a candidate within the 32 MiB result bound');
  assert.throws(() => dev.parsePreparedPolicyRequest(' '.repeat(32 * 1024 * 1024 + 1)),
    { code: 'malformed_request' });
  assert.throws(() => dev.serializePreparedPolicyRequest({
    requestJson: '{}',
    changes: [{ operation: 'replace', path: '', before: null, after: 'é'.repeat(16 * 1024 * 1024) }],
  }), { code: 'malformed_request' });
  const edit: dev.PolicyPreparationChange = { operation: 'replace', path: '', before: null, after: null };
  const candidate = { requestJson: '{}', changes: Array<dev.PolicyPreparationChange>(4096).fill(edit) };
  assert.strictEqual(dev.parsePreparedPolicyRequest(dev.serializePreparedPolicyRequest(candidate)).changes.length, 4096);
  candidate.changes.push(edit);
  assert.throws(() => dev.serializePreparedPolicyRequest(candidate), { code: 'malformed_request' });
});

it('merges complete refusal batches in first-seen order into independent storage', () => {
  const original = samplePolicyFailures();
  const repeated = {
    ...original.results[0],
    details: original.results[0].details.map((detail) => ({ ...detail })),
  };
  repeated.details[0].requestedValue = dev.PolicyFailureAccessValues.ReadWrite.padStart(4, '0');
  const changedOrder = {
    ...original.results[0],
    details: [...original.results[0].details].reverse(),
  };
  const older = policyReport([original.results[0], original.results[0]]);
  const newer = policyReport([repeated, original.results[1], changedOrder]);
  const before = JSON.stringify([older, newer]);
  const merged = dev.mergePolicyFailures(older, newer);
  assert.deepStrictEqual(merged, policyReport([original.results[0], original.results[1], changedOrder]));
  assert.strictEqual(JSON.stringify([older, newer]), before);
  merged.results[1].details[0].resource = 'changed';
  merged.results[1].details[0].requestedValue = '0';
  assert.strictEqual(JSON.stringify([older, newer]), before, 'merge owns every nested value');
  const empty = policyReport();
  assert.deepStrictEqual(dev.mergePolicyFailures(empty, original), original);
  assert.deepStrictEqual(dev.mergePolicyFailures(original, empty), original);
});

it('rejects over-limit merged storage without mutation or truncation', () => {
  const empty = policyReport();
  const results = Array.from({ length: 65 }, (_, outcome) => policyResult([], outcome));
  const full = policyReport(results);
  assert.deepStrictEqual(dev.mergePolicyFailures(full, policyReport([results[0]])), full);
  const detailBatches = Array.from({ length: 18 }, (_, outcome) => policyResult(
    Array.from({ length: outcome === 17 ? 1 : 64 }, () => policyDetail()), outcome));
  const resourceBatches = Array.from({ length: 10 }, (_, outcome) => policyResult(
    [policyDetail({ resource: '\0'.repeat(outcome === 9 ? 0 : 32_767) })], outcome));
  const largeDetail = policyDetail({ requestedValue: '0'.repeat(2.3 * 1024 * 1024) });
  for (const [older, newer] of [
    [full, policyReport([{ ...results[0], outcome: 65 }])],
    [policyReport(detailBatches.slice(0, 17)), policyReport(detailBatches.slice(17))],
    [policyReport(resourceBatches.slice(0, 9)), policyReport(resourceBatches.slice(9))],
    [policyReport([{ ...results[0], details: [largeDetail] }]),
      policyReport([{ ...results[1], details: [largeDetail] }])],
    [policyReport([...results, results[0]]), empty],
    [empty, { formatVersion: dev.PolicyFailureVersions.Format + 1, results: [] }],
  ] satisfies Array<[dev.PolicyFailures, dev.PolicyFailures]>) {
    const before = JSON.stringify([older, newer]);
    assert.throws(() => dev.mergePolicyFailures(older, newer), { code: 'malformed_request' });
    assert.strictEqual(JSON.stringify([older, newer]), before);
  }
});
