// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import {
  deprovisionSandbox,
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
} from '../../src/state-aware.js';
import {
  buildStateAwareEnvelope,
  parseNonExecResponse,
} from '../../src/state-aware-helper.js';
import {
  _setBindingStateAwareWorkerFactory,
  type BindingStateAwareWorkerLike,
  type BindingStateAwareWorkerMessage,
} from '../../src/bindings/state-aware-worker.js';
import { _setStateAwareBindingSandboxProcessFactory } from '../../src/bindings/streaming.js';
import type { BindingStateAwareRequest } from '../../src/bindings/state-aware.js';
import { MxcError } from '../../src/errors.js';
import { SandboxId } from '../../src/state-aware-types.js';
import {
  _createMxcSandboxProcess,
  type SandboxProcessBinding,
  type SandboxReadableBinding,
} from '../../src/sandbox-process.js';
import { ffiTestOptions, platformSkip } from './test-helpers.js';

class FakeStateAwareWorker extends EventEmitter implements BindingStateAwareWorkerLike {
  reply(message: BindingStateAwareWorkerMessage): void {
    queueMicrotask(() => this.emit('message', message));
  }

  fail(error: Error): void {
    queueMicrotask(() => this.emit('error', error));
  }
}

function requestEnvelope(request: BindingStateAwareRequest): Record<string, unknown> {
  return JSON.parse(request.requestJson) as Record<string, unknown>;
}

function installStateAwareReply(responseJson: string): () => BindingStateAwareRequest {
  let request: BindingStateAwareRequest | undefined;
  _setBindingStateAwareWorkerFactory((data) => {
    request = data.request;
    const worker = new FakeStateAwareWorker();
    worker.reply({ ok: true, responseJson });
    return worker;
  });
  return () => {
    assert.ok(request, 'expected a state-aware request');
    return request;
  };
}

function installStateAwareError(
  error: NonNullable<Extract<BindingStateAwareWorkerMessage, { ok: false }>['error']>,
): void {
  _setBindingStateAwareWorkerFactory(() => {
    const worker = new FakeStateAwareWorker();
    worker.reply({ ok: false, error });
    return worker;
  });
}

class FakeExecReadable implements SandboxReadableBinding {
  constructor(
    private readonly chunks: (Buffer | null)[],
    private readonly events: string[],
  ) {}

  read(buffer: Buffer): Promise<number> {
    const next = this.chunks.shift() ?? null;
    if (next !== null) {
      next.copy(buffer);
    }
    return Promise.resolve(next === null ? 0 : next.length);
  }

  close(): void {
    this.events.push('close');
  }

  free(): void {
    this.events.push('free');
  }
}

class FakeStateAwareExecBinding implements SandboxProcessBinding {
  readonly warnings: readonly string[];
  readonly stdoutEvents: string[] = [];
  readonly stderrEvents: string[] = [];
  killed = false;
  freed = false;
  polls = 0;

  constructor(
    readonly id: number,
    stdout: string,
    stderr: string,
    private readonly runningPolls = 0,
    private readonly waitResult = { exitCode: 0, timedOut: false },
    warnings: readonly string[] = [],
  ) {
    this.warnings = warnings;
    this.stdoutBinding = new FakeExecReadable([Buffer.from(stdout), null], this.stdoutEvents);
    this.stderrBinding = new FakeExecReadable([Buffer.from(stderr), null], this.stderrEvents);
  }

  private readonly stdoutBinding: SandboxReadableBinding;
  private readonly stderrBinding: SandboxReadableBinding;

  takeStdin() {
    return null;
  }

  takeStdout() {
    return this.stdoutBinding;
  }

  takeStderr() {
    return this.stderrBinding;
  }

  tryWait() {
    this.polls += 1;
    return {
      running: this.polls <= this.runningPolls,
      exitCode: 0,
      timedOut: false,
    };
  }

  wait() {
    return this.waitResult;
  }

  outputMetadata() {
    return undefined;
  }

  kill(): void {
    this.killed = true;
  }

  free(): void {
    this.freed = true;
  }
}

function installStateAwareExecBinding(
  createBinding: () => FakeStateAwareExecBinding,
): { binding: () => FakeStateAwareExecBinding; request: () => Record<string, unknown>; timeout: () => number | undefined } {
  let binding: FakeStateAwareExecBinding | undefined;
  let requestJson: string | undefined;
  let timeoutMs: number | undefined;
  _setStateAwareBindingSandboxProcessFactory((request, _experimental, timeout) => {
    requestJson = request;
    timeoutMs = timeout;
    binding = createBinding();
    return _createMxcSandboxProcess(binding, timeout);
  });
  return {
    binding: () => {
      assert.ok(binding, 'expected a state-aware exec binding');
      return binding;
    },
    request: () => {
      assert.ok(requestJson, 'expected a state-aware exec request');
      return JSON.parse(requestJson) as Record<string, unknown>;
    },
    timeout: () => timeoutMs,
  };
}

afterEach(() => _setBindingStateAwareWorkerFactory());
afterEach(() => _setStateAwareBindingSandboxProcessFactory());

describe('buildStateAwareEnvelope', () => {
  it('lifts telemetry to the top-level envelope', () => {
    const env = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'windows_sandbox',
      sandboxId: 'wsb:01234567',
      config: { telemetry: { enabled: true } },
    });
    assert.deepEqual(env.telemetry, { enabled: true });
    assert.equal(env.version, '0.9.0-alpha');
    assert.equal(env.experimental, undefined);
  });

  it('leaves explicit telemetry schema validation to the native parser', () => {
    const env = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'windows_sandbox',
      sandboxId: 'wsb:01234567',
      config: { version: '0.8.0-alpha', telemetry: { enabled: true } },
    });
    assert.deepEqual(env.telemetry, { enabled: true });
    assert.equal(env.version, '0.8.0-alpha');
  });

  it('produces a provision envelope with cross-cutting fields lifted to top-level', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: {
        version: '0.6.0-alpha',
        filesystem: { readwritePaths: ['C:\\workspace'] },
        network: { defaultPolicy: 'block' },
        ui: { disable: true, clipboard: 'none', injection: false },
      },
    });
    assert.strictEqual(env.phase, 'provision');
    assert.strictEqual(env.containment, 'isolation_session');
    assert.deepStrictEqual(env.filesystem, { readwritePaths: ['C:\\workspace'] });
    assert.deepStrictEqual(env.network, { defaultPolicy: 'block' });
    assert.deepStrictEqual(env.ui, { disable: true, clipboard: 'none', injection: false });
    assert.strictEqual(env.experimental, undefined);
    assert.strictEqual(env.sandboxId, undefined);
  });

  it('produces a start envelope with no experimental block when no backend config is supplied', () => {
    const env = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'isolation_session',
      sandboxId: 'iso:reg-abc:prov-123',
    });
    assert.strictEqual(env.phase, 'start');
    assert.strictEqual(env.sandboxId, 'iso:reg-abc:prov-123');
    assert.strictEqual(env.experimental, undefined);
  });

  it('produces an exec envelope with process at top-level and no experimental block', () => {
    const env = buildStateAwareEnvelope({
      phase: 'exec',
      backendKey: 'isolation_session',
      sandboxId: 'iso:abc',
      config: { process: { commandLine: 'echo hi' } },
    });
    assert.strictEqual(env.phase, 'exec');
    assert.deepStrictEqual(env.process, { commandLine: 'echo hi' });
    assert.strictEqual(env.experimental, undefined);
  });

  it('produces stop and deprovision envelopes carrying only version + phase + sandboxId', () => {
    for (const phase of ['stop', 'deprovision'] as const) {
      const env = buildStateAwareEnvelope({
        phase,
        backendKey: 'isolation_session',
        sandboxId: 'iso:abc',
      });
      assert.strictEqual(env.phase, phase);
      assert.strictEqual(env.sandboxId, 'iso:abc');
      assert.strictEqual(env.experimental, undefined);
      assert.ok(typeof env.version === 'string' && env.version.length > 0);
    }
  });

  it('uses caller-supplied version when provided', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: { version: '0.6.5-alpha' },
    });
    assert.strictEqual(env.version, '0.6.5-alpha');
  });

  it('nests provision appId under experimental.isolation_session.provision', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: { appId: 'PFN:Contoso.App_8wekyb3d8bbwe' },
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.deepStrictEqual(wire.experimental, {
      isolation_session: {
        provision: { appId: 'PFN:Contoso.App_8wekyb3d8bbwe' },
      },
    });
  });

  it('emits an explicitly empty appId rather than dropping it', () => {
    // Empty is a distinct value from absent; dropping it here would silently
    // change what the caller asked for.
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: { appId: '' },
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.deepStrictEqual(wire.experimental, {
      isolation_session: { provision: { appId: '' } },
    });
  });

  it('omits the experimental block entirely when no appId is supplied', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: {},
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.strictEqual(wire.experimental, undefined);
  });

  it('never emits correlationVector on state-aware envelopes', () => {
    const nonProvision = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'isolation_session',
      sandboxId: 'iso:abc',
    });
    assert.strictEqual(nonProvision.correlationVector, undefined);

    const provision = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
    });
    assert.strictEqual(provision.correlationVector, undefined);
  });

  it('places stable telemetry at the envelope top level', () => {
    const env = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'isolation_session',
      sandboxId: 'iso:abc',
      config: { telemetry: { enabled: true } },
    });
    assert.deepStrictEqual(env.telemetry, { enabled: true });
    assert.strictEqual(env.version, '0.9.0-alpha');
    assert.strictEqual(env.experimental, undefined);
  });

});

describe('parseNonExecResponse', () => {
  it('unwraps result payload', () => {
    const result = parseNonExecResponse<{ sandboxId: string }>('{"result":{"sandboxId":"iso:abc"}}');
    assert.deepStrictEqual(result, { sandboxId: 'iso:abc' });
  });

  it('throws an MxcError carrying each wire error code', () => {
    const codes = [
      'malformed_request',
      'unsupported_containment',
      'unsupported_phase',
      'backend_unavailable',
      'malformed_id',
      'stale_id',
      'not_provisioned',
      'not_started',
      'already_started',
      'policy_validation',
      'backend_error',
    ];
    for (const code of codes) {
      const stdout = JSON.stringify({ error: { code, message: 'boom' } });
      assert.throws(
        () => parseNonExecResponse(stdout),
        (err: unknown) => err instanceof MxcError && err.code === code,
      );
    }
  });

  it('passes details through when wire envelope carries them', () => {
    const stdout = JSON.stringify({
      error: { code: 'backend_error', message: 'boom', details: { hresult: '0x80004005' } },
    });
    assert.throws(() => parseNonExecResponse(stdout), (err: unknown) => {
      return err instanceof MxcError &&
        err.code === 'backend_error' &&
        err.details?.hresult === '0x80004005';
    });
  });

  it('surfaces the structured failure fields from the wire envelope', () => {
    const stdout = JSON.stringify({
      error: {
        code: 'stale_id',
        message: 'agent user not found',
        operation: 'IsoSessionOps.StopSessionAsync',
        nativeCode: '0x80070490',
        remediation: 'Re-provision the sandbox.',
      },
    });
    assert.throws(() => parseNonExecResponse(stdout), (err: unknown) => {
      return err instanceof MxcError &&
        err.code === 'stale_id' &&
        err.message === 'agent user not found' &&
        err.operation === 'IsoSessionOps.StopSessionAsync' &&
        err.nativeCode === '0x80070490' &&
        err.remediation === 'Re-provision the sandbox.';
    });
  });

  // An MXC-side rejection has no API call in flight, so the structured
  // fields must stay absent rather than arriving as empty strings.
  it('leaves the structured fields undefined when the envelope omits them', () => {
    const stdout = JSON.stringify({ error: { code: 'policy_validation', message: 'bad policy' } });
    assert.throws(() => parseNonExecResponse(stdout), (err: unknown) => {
      return err instanceof MxcError &&
        err.operation === undefined &&
        err.nativeCode === undefined &&
        err.remediation === undefined;
    });
  });

  it('throws a plain Error on unparseable stdout', () => {
    assert.throws(() => parseNonExecResponse('not json'), (err: unknown) => {
      return err instanceof Error && !(err instanceof MxcError);
    });
  });

  it('throws a plain Error on stdout that parses but lacks {result}/{error}', () => {
    assert.throws(() => parseNonExecResponse('{"unexpected":"shape"}'));
  });
});

describe('provisionSandbox', { skip: platformSkip }, () => {
  // The unrestricted-network acknowledgment is a required member of
  // IsolationSessionProvisionConfig, so `provisionSandbox` will not accept an
  // omitted config for this backend. Tests below that are not about the config
  // itself use this minimal valid value.
  const ACK = { network: { defaultPolicy: 'allow', allowLocalNetwork: true } } as const;

  it('builds a provision envelope and unwraps the SandboxId from the response', async () => {
    const request = installStateAwareReply(
      '{"result":{"sandboxId":"iso:reg-abc:prov-1","metadata":{"agentUserName":"agent\\\\u1","agentUserSid":"S-1-5-21-1001","ephemeralWorkspacePath":"C:\\\\ProgramData\\\\ws"}}}',
    );
    const result = await provisionSandbox(
      'isolation_session',
      {
        network: { defaultPolicy: 'allow', allowLocalNetwork: true },
        appId: 'example.app.id',
      },
      ffiTestOptions(),
    );
    assert.strictEqual(result.sandboxId, 'iso:reg-abc:prov-1');
    assert.strictEqual(result.metadata?.agentUserName, 'agent\\u1');
    assert.strictEqual(result.metadata?.agentUserSid, 'S-1-5-21-1001');
    assert.strictEqual(result.metadata?.ephemeralWorkspacePath, 'C:\\ProgramData\\ws');
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'provision');
    assert.strictEqual(envelope.containment, 'isolation_session');
    // An unpackaged app may pass any string; it reaches the wire config verbatim.
    const provisionConfig = (envelope.experimental as {
      isolation_session?: { provision?: { appId?: string } };
    })?.isolation_session?.provision;
    assert.strictEqual(provisionConfig?.appId, 'example.app.id');
    // The unrestricted-network acknowledgment is lifted to the envelope top level.
    assert.deepStrictEqual(envelope.network, {
      defaultPolicy: 'allow',
      allowLocalNetwork: true,
    });
  });

  it('throws an MxcError carrying backend_unavailable when mxc_state_aware reports it', async () => {
    installStateAwareError({
      code: 'backend_unavailable',
      message: 'isolation session API not available on this host',
    });
    await assert.rejects(
      () => provisionSandbox('isolation_session', ACK, ffiTestOptions()),
      (err: unknown) => err instanceof MxcError && err.code === 'backend_unavailable',
    );
  });

  it('rejects executor-only options instead of falling back', async () => {
    await assert.rejects(
      () => provisionSandbox('isolation_session', ACK, {
        ...ffiTestOptions(),
        executablePath: 'wxc-exec.exe',
      }),
      (err: unknown) => err instanceof MxcError && err.message.includes('executor-only option'),
    );
  });

  it('rejects on abort and deprovisions a late provision result', async () => {
    const ac = new AbortController();
    const requests: BindingStateAwareRequest[] = [];
    let firstWorker: FakeStateAwareWorker | undefined;
    _setBindingStateAwareWorkerFactory((data) => {
      requests.push(data.request);
      const worker = new FakeStateAwareWorker();
      if (!firstWorker) {
        firstWorker = worker;
      } else {
        worker.reply({ ok: true, responseJson: '{"result":{}}' });
      }
      return worker;
    });
    const promise = provisionSandbox(
      'isolation_session',
      ACK,
      ffiTestOptions({ signal: ac.signal }),
    );
    ac.abort();
    await assert.rejects(promise);
    firstWorker!.reply({ ok: true, responseJson: '{"result":{"sandboxId":"iso:cleanup-me"}}' });
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(requests.length, 2);
    assert.strictEqual(requestEnvelope(requests[1]!).phase, 'deprovision');
    assert.strictEqual(requestEnvelope(requests[1]!).sandboxId, 'iso:cleanup-me');
  });
});

describe('startSandbox', { skip: platformSkip }, () => {
  it('infers backend from sandboxId prefix and sends no per-phase start config', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, undefined, ffiTestOptions());
    const wire = requestEnvelope(request());
    assert.strictEqual(wire.phase, 'start');
    assert.strictEqual(wire.sandboxId, 'iso:reg-abc:prov-1');
    assert.strictEqual(
      wire.experimental,
      undefined,
      'start takes no per-phase config, so no experimental block should be emitted',
    );
  });

  it('does not serialize correlationVector onto the start envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, undefined, ffiTestOptions());
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });

  it('relays stable telemetry from phase config onto the start envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, { telemetry: { enabled: false } }, ffiTestOptions());
    const envelope = requestEnvelope(request());
    assert.deepStrictEqual(envelope.telemetry, { enabled: false });
    assert.strictEqual(envelope.version, '0.9.0-alpha');
    assert.strictEqual(envelope.experimental, undefined);
  });

});

describe('stopSandbox', { skip: platformSkip }, () => {
  it('builds a minimal stop envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await stopSandbox(id, undefined, ffiTestOptions());
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'stop');
    assert.strictEqual(envelope.sandboxId, 'iso:abc');
    assert.strictEqual(envelope.experimental, undefined);
  });

  it('rejects with malformed_id when sandboxId has no recognised prefix', async () => {
    await assert.rejects(
      () => stopSandbox('not-a-real-id' as SandboxId<'isolation_session'>),
      (err: unknown) => err instanceof MxcError && err.code === 'malformed_id',
    );
    await assert.rejects(
      () => stopSandbox('unknownprefix:abc' as SandboxId<'isolation_session'>),
      (err: unknown) => err instanceof MxcError && err.code === 'malformed_id',
    );
  });

  it('does not serialize correlationVector onto the stop envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await stopSandbox(id, undefined, ffiTestOptions());
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });
});

describe('deprovisionSandbox', { skip: platformSkip }, () => {
  it('builds a minimal deprovision envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id, undefined, ffiTestOptions());
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'deprovision');
    assert.strictEqual(envelope.sandboxId, 'iso:abc');
  });

  it('does not serialize correlationVector onto the deprovision envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id, undefined, ffiTestOptions());
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });
});

describe('execInSandboxAsync', { skip: platformSkip }, () => {
  it('returns ExecResult on successful script run', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(17, 'hello\n', '', 1, { exitCode: 0, timedOut: false }),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const result = await execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hello', timeout: 250 } },
      ffiTestOptions(),
    );
    assert.deepStrictEqual(result, { stdout: 'hello\n', stderr: '', exitCode: 0 });
    assert.deepStrictEqual(exec.request().process, { commandLine: 'echo hello', timeout: 250 });
    assert.strictEqual(exec.request().correlationVector, undefined);
    assert.strictEqual(exec.timeout(), 250);
    assert.strictEqual(exec.binding().freed, true);
  });

  it('returns ExecResult on script exit != 0 when stdout is plain script output (not an error envelope)', async () => {
    installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(18, 'oops\n', 'err\n', 0, { exitCode: 7, timedOut: false }),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const result = await execInSandboxAsync(
      id,
      { process: { commandLine: 'fail' } },
      ffiTestOptions(),
    );
    assert.deepStrictEqual(result, { stdout: 'oops\n', stderr: 'err\n', exitCode: 7 });
  });

  it('throws the typed MxcError on dispatch failure before a process is returned', async () => {
    _setStateAwareBindingSandboxProcessFactory(() => {
      throw new MxcError('stale_id', 'id expired');
    });
    const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
    await assert.rejects(
      () => execInSandboxAsync(id, { process: { commandLine: 'echo' } }, ffiTestOptions()),
      (err: unknown) => err instanceof MxcError && err.code === 'stale_id',
    );
  });

  it('returns the dry-run response envelope instead of spawning a live process', async () => {
    const request = installStateAwareReply('{"result":{"validated":true}}');
    _setStateAwareBindingSandboxProcessFactory(() => {
      throw new Error('dry-run should not create a live process');
    });
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const result = await execInSandboxAsync(
      id,
      { process: { commandLine: 'cat' } },
      ffiTestOptions({ dryRun: true }),
    );
    assert.deepStrictEqual(result, {
      stdout: '{"result":{"validated":true}}',
      stderr: '',
      exitCode: 0,
    });
    assert.strictEqual(requestEnvelope(request()).phase, 'exec');
  });

  it('kills and disposes the live process when AbortSignal fires', async () => {
    const ac = new AbortController();
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(19, '', '', Number.MAX_SAFE_INTEGER),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const promise = execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hi' } },
      ffiTestOptions({ signal: ac.signal }),
    );
    ac.abort();
    await assert.rejects(promise);
    assert.strictEqual(exec.binding().killed, true);
    assert.strictEqual(exec.binding().freed, true);
  });

  it('rejects executor-only options instead of falling back', async () => {
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await assert.rejects(
      () => execInSandboxAsync(id, { process: { commandLine: 'echo hi' } }, {
        ...ffiTestOptions(),
        executablePath: 'wxc-exec.exe',
      }),
      (err: unknown) => err instanceof MxcError && err.message.includes('executor-only option'),
    );
  });
});

describe('windows_sandbox state-aware lifecycle', () => {
  it('buildStateAwareEnvelope lifts filesystem (incl. deniedPaths) and emits no experimental block', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'windows_sandbox',
      containment: 'windows_sandbox',
      config: {
        version: '0.6.0-alpha',
        filesystem: {
          readwritePaths: ['C:\\workspace'],
          readonlyPaths: ['C:\\inputs'],
          deniedPaths: ['C:\\secrets'],
        },
      },
    });
    assert.strictEqual(env.phase, 'provision');
    assert.strictEqual(env.containment, 'windows_sandbox');
    assert.deepStrictEqual(env.filesystem, {
      readwritePaths: ['C:\\workspace'],
      readonlyPaths: ['C:\\inputs'],
      deniedPaths: ['C:\\secrets'],
    });
    assert.strictEqual(env.experimental, undefined);
  });

  describe('round-trip via the typed API', { skip: platformSkip }, () => {
    it('provisionSandbox builds a windows_sandbox envelope and routes back via the wsb: prefix', async () => {
      const request = installStateAwareReply('{"result":{"sandboxId":"wsb:prov-1"}}');
      const result = await provisionSandbox(
        'windows_sandbox',
        { filesystem: { readonlyPaths: ['C:\\inputs'] } },
        ffiTestOptions(),
      );
      assert.strictEqual(result.sandboxId, 'wsb:prov-1');
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'provision');
      assert.strictEqual(envelope.containment, 'windows_sandbox');
      assert.deepStrictEqual(envelope.filesystem, { readonlyPaths: ['C:\\inputs'] });
      assert.strictEqual(envelope.experimental, undefined);
    });

    it('startSandbox infers windows_sandbox from the wsb: prefix', async () => {
      const request = installStateAwareReply('{"result":{}}');
      const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
      await startSandbox(id, undefined, ffiTestOptions());
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'start');
      assert.strictEqual(envelope.sandboxId, 'wsb:prov-1');
      assert.strictEqual(envelope.experimental, undefined);
    });

    it('execInSandboxAsync places process at top-level for a wsb: id', async () => {
      const exec = installStateAwareExecBinding(
        () => new FakeStateAwareExecBinding(20, 'hello-from-wsb\n', '', 0, { exitCode: 0, timedOut: false }),
      );
      const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
      const result = await execInSandboxAsync(
        id,
        { process: { commandLine: 'echo hello-from-wsb' } },
        ffiTestOptions(),
      );
      assert.deepStrictEqual(result, { stdout: 'hello-from-wsb\n', stderr: '', exitCode: 0 });
      assert.deepStrictEqual(exec.request().process, { commandLine: 'echo hello-from-wsb' });
    });

    it('stopSandbox and deprovisionSandbox build minimal envelopes for a wsb: id', async () => {
      for (const phase of ['stop', 'deprovision'] as const) {
        const request = installStateAwareReply('{"result":{}}');
        const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
        const call = phase === 'stop' ? stopSandbox : deprovisionSandbox;
        await call(id, undefined, ffiTestOptions());
        const envelope = requestEnvelope(request());
        assert.strictEqual(envelope.phase, phase);
        assert.strictEqual(envelope.sandboxId, 'wsb:prov-1');
      }
    });
  });
});

describe('wslc state-aware lifecycle', () => {
  it('defaults the version to 0.8.0-alpha (not the isolation_session default)', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: { image: 'alpine:latest' },
    });
    assert.strictEqual(env.version, '0.8.0-alpha');
  });

  it('still honors a caller-supplied version over the wslc default', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: { version: '0.8.1-alpha', image: 'alpine:latest' },
    });
    assert.strictEqual(env.version, '0.8.1-alpha');
  });

  it('lifts filesystem + network and nests image under experimental.wslc.provision', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: {
        filesystem: { readwritePaths: ['C:\\ws\\rw'] },
        network: { defaultPolicy: 'allow' },
        image: 'alpine:latest',
        imageTarPath: 'C:\\images\\alpine.tar',
      },
    });
    assert.strictEqual(env.containment, 'wslc');
    assert.deepStrictEqual(env.filesystem, { readwritePaths: ['C:\\ws\\rw'] });
    assert.deepStrictEqual(env.network, { defaultPolicy: 'allow' });
    const wire = JSON.parse(JSON.stringify(env));
    assert.deepStrictEqual(wire.experimental, {
      wslc: { provision: { image: 'alpine:latest', imageTarPath: 'C:\\images\\alpine.tar' } },
    });
  });

  it('omits the experimental block when provision carries no backend-specific field', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: { network: { defaultPolicy: 'block' } },
    });
    assert.strictEqual(env.experimental, undefined);
    assert.deepStrictEqual(env.network, { defaultPolicy: 'block' });
  });

  it('lifts exec process + cooperative proxy network to top-level with no experimental block', () => {
    const env = buildStateAwareEnvelope({
      phase: 'exec',
      backendKey: 'wslc',
      sandboxId: 'wslc:abc',
      config: {
        process: { commandLine: 'echo hi' },
        network: { proxy: { url: 'http://127.0.0.1:8888' } },
      },
    });
    assert.deepStrictEqual(env.process, { commandLine: 'echo hi' });
    assert.deepStrictEqual(env.network, { proxy: { url: 'http://127.0.0.1:8888' } });
    assert.strictEqual(env.experimental, undefined);
  });

  describe('round-trip via the typed API', { skip: platformSkip }, () => {
    it('provisionSandbox builds a wslc envelope and routes back via the wslc: prefix', async () => {
      const request = installStateAwareReply('{"result":{"sandboxId":"wslc:0123abcd"}}');
      const result = await provisionSandbox(
        'wslc',
        { image: 'alpine:latest', network: { defaultPolicy: 'block' } },
        ffiTestOptions(),
      );
      assert.strictEqual(result.sandboxId, 'wslc:0123abcd');
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'provision');
      assert.strictEqual(envelope.containment, 'wslc');
      assert.strictEqual(envelope.version, '0.8.0-alpha');
    });

    it('startSandbox infers wslc from the wslc: prefix', async () => {
      const request = installStateAwareReply('{"result":{}}');
      const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
      await startSandbox(id, undefined, ffiTestOptions());
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'start');
      assert.strictEqual(envelope.sandboxId, 'wslc:0123abcd');
      assert.strictEqual(envelope.experimental, undefined);
    });

    it('execInSandboxAsync places process at top-level for a wslc: id', async () => {
      const exec = installStateAwareExecBinding(
        () => new FakeStateAwareExecBinding(21, 'hello-from-wslc\n', '', 0, { exitCode: 0, timedOut: false }),
      );
      const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
      const result = await execInSandboxAsync(
        id,
        { process: { commandLine: 'echo hello-from-wslc' } },
        ffiTestOptions(),
      );
      assert.deepStrictEqual(result, { stdout: 'hello-from-wslc\n', stderr: '', exitCode: 0 });
      assert.deepStrictEqual(exec.request().process, { commandLine: 'echo hello-from-wslc' });
    });

    it('stopSandbox and deprovisionSandbox build minimal envelopes for a wslc: id', async () => {
      for (const phase of ['stop', 'deprovision'] as const) {
        const request = installStateAwareReply('{"result":{}}');
        const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
        const call = phase === 'stop' ? stopSandbox : deprovisionSandbox;
        await call(id, undefined, ffiTestOptions());
        const envelope = requestEnvelope(request());
        assert.strictEqual(envelope.phase, phase);
        assert.strictEqual(envelope.sandboxId, 'wslc:0123abcd');
      }
    });
  });
});
