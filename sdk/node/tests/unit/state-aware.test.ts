// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { PassThrough } from 'node:stream';
import {
  deprovisionSandbox,
  execInSandbox,
  execInSandboxAsync,
  provisionSandbox,
  type StateAwareStreamingOptions,
  startSandbox,
  stopSandbox,
} from '../../src/state-aware.js';
import {
  buildStateAwareEnvelope,
  parseNonExecResponse,
} from '../../src/state-aware-helper.js';
import {
  _setBindingStateAwareAsyncImplementation,
  type BindingStateAwareRequest,
} from '../../src/bindings/state-aware.js';
import { _setStateAwareBindingSandboxProcessFactory } from '../../src/bindings/streaming.js';
import { MxcError, type MxcErrorFields } from '../../src/errors.js';
import { SandboxId } from '../../src/state-aware-types.js';
import {
  MxcSandboxProcess,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
} from '../../src/sandbox-process.js';

function requestEnvelope(request: BindingStateAwareRequest): Record<string, unknown> {
  return JSON.parse(request.requestJson) as Record<string, unknown>;
}

function installStateAwareReply(responseJson: string): () => BindingStateAwareRequest {
  let request: BindingStateAwareRequest | undefined;
  _setBindingStateAwareAsyncImplementation(async (value) => {
    request = value;
    return responseJson;
  });
  return () => {
    assert.ok(request, 'expected a state-aware request');
    return request;
  };
}

function installStateAwareError(
  error: MxcErrorFields,
): void {
  _setBindingStateAwareAsyncImplementation(async () => {
    throw new MxcError(error);
  });
}

class FakeStateAwareExecBinding implements NativeLifecycleDriver {
  readonly standardInput = null;
  readonly standardOutput = new PassThrough();
  readonly standardError = new PassThrough();
  killed = false;
  killCount = 0;
  killError: Error | undefined;
  freed = false;
  polls = 0;
  private status: NativeLifecycleStatus = {
    exitCode: 0,
    running: true,
    timedOut: false,
  };

  constructor(
    readonly id: number,
    stdout: string,
    stderr: string,
    private readonly runningPolls = 0,
    private readonly waitResult = { exitCode: 0, timedOut: false },
    private readonly warningValues: readonly string[] = [],
    endStreams = true,
  ) {
    if (endStreams) {
      this.completeStreams(stdout, stderr);
    }
  }

  completeStreams(stdout = '', stderr = ''): void {
    this.standardOutput.end(stdout);
    this.standardError.end(stderr);
  }

  poll(): NativeLifecycleStatus {
    this.polls += 1;
    if (this.polls > this.runningPolls) {
      this.status = { ...this.waitResult, running: false };
    }
    return this.status;
  }

  async wait() {
    return this.waitResult;
  }

  outputMetadata() {
    return undefined;
  }

  warnings(): readonly string[] {
    return this.warningValues;
  }

  kill(): void {
    this.killed = true;
    this.killCount += 1;
    if (this.killError !== undefined) throw this.killError;
  }

  killForTimeout(): void {
    this.killed = true;
  }

  async free(): Promise<void> {
    this.freed = true;
  }
}

function installStateAwareExecBinding(
  createBinding: () => FakeStateAwareExecBinding,
): {
  binding: () => FakeStateAwareExecBinding;
  request: () => Record<string, unknown>;
  experimental: () => boolean;
  timeout: () => number | undefined;
} {
  let binding: FakeStateAwareExecBinding | undefined;
  let requestJson: string | undefined;
  let experimental = false;
  let timeoutMs: number | undefined;
  _setStateAwareBindingSandboxProcessFactory((request, allowExperimental, timeout) => {
    requestJson = request;
    experimental = allowExperimental;
    timeoutMs = timeout;
    binding = createBinding();
    return new MxcSandboxProcess(binding, timeout);
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
    experimental: () => experimental,
    timeout: () => timeoutMs,
  };
}

function readStreamText(stream: NodeJS.ReadableStream | null): Promise<string> {
  if (stream === null) {
    return Promise.resolve('');
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer | string) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    stream.once('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.once('error', reject);
  });
}

afterEach(() => _setBindingStateAwareAsyncImplementation());
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
    assert.equal(env.version, '0.10.0-alpha');
    assert.equal(env.experimental, undefined);
  });

  it('rejects an explicitly older schema version when telemetry is present', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'start',
        backendKey: 'windows_sandbox',
        sandboxId: 'wsb:01234567',
        config: { version: '0.8.0-alpha', telemetry: { enabled: true } },
      }),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.includes(
          "State-aware windows_sandbox requests require schema version '0.10.0-alpha'",
        ),
    );
  });

  it('selects schema 0.9 when WSLC exec inherits the backend environment', () => {
    const env = buildStateAwareEnvelope({
      phase: 'exec',
      backendKey: 'wslc',
      sandboxId: 'wslc:abc',
      config: {
        process: {
          commandLine: 'echo hi',
          inheritDefaultEnv: true,
        },
      },
    });
    assert.equal(env.version, '0.9.0-alpha');
    assert.deepEqual(env.process, {
      commandLine: 'echo hi',
      inheritDefaultEnv: true,
    });
  });

  it('rejects an explicitly older schema version when the environment is inherited', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'exec',
        backendKey: 'wslc',
        sandboxId: 'wslc:abc',
        config: {
          version: '0.8.0-alpha',
          process: {
            commandLine: 'echo hi',
            inheritDefaultEnv: true,
          },
        },
      }),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.includes(
          "State-aware wslc requests require schema version '0.9.0-alpha'",
        ),
    );
  });

  it('produces a provision envelope with cross-cutting fields lifted to top-level', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: {
        version: '0.9.0-alpha',
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow', hostLoopback: 'allow' },
        },
      },
    });
    assert.strictEqual(env.phase, 'provision');
    assert.strictEqual(env.containment, 'isolation_session');
    assert.deepStrictEqual(env.network, {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    });
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

  it('rejects an untyped caller-supplied version with malformed_request', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'provision',
        backendKey: 'isolation_session',
        containment: 'isolation_session',
        config: { version: '0.6.5-alpha' },
      }),
      (err: unknown) => err instanceof MxcError &&
        err.code === 'malformed_request' &&
        /require schema version '0\.9\.0-alpha'/.test(err.message),
    );
  });

  it('nests provision appId under isolationSession.provision', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: { appId: 'PFN:Contoso.App_8wekyb3d8bbwe' },
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.deepStrictEqual(wire.isolationSession, {
      provision: { appId: 'PFN:Contoso.App_8wekyb3d8bbwe' },
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
    assert.deepStrictEqual(wire.isolationSession, {
      provision: { appId: '' },
    });
  });

  it('omits the IsolationSession section when no appId is supplied', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: {},
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.strictEqual(wire.isolationSession, undefined);
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

describe('provisionSandbox', () => {
  // The unrestricted-network posture is a required member of
  // IsolationSessionProvisionConfig, so `provisionSandbox` will not accept an
  // omitted config for this backend. Tests below that are not about the config
  // itself use this minimal valid value.
  const ACK = {
    network: {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    },
  } as const;

  it('builds a provision envelope and unwraps the SandboxId from the response', async () => {
    const request = installStateAwareReply(
      '{"result":{"sandboxId":"iso:reg-abc:prov-1","metadata":{"agentUserName":"agent\\\\u1","agentUserSid":"S-1-5-21-1001","ephemeralWorkspacePath":"C:\\\\ProgramData\\\\ws"}}}',
    );
    const result = await provisionSandbox(
      'isolation_session',
      {
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow', hostLoopback: 'allow' },
        },
        appId: 'example.app.id',
      },
    );
    assert.strictEqual(result.sandboxId, 'iso:reg-abc:prov-1');
    assert.strictEqual(result.metadata?.agentUserName, 'agent\\u1');
    assert.strictEqual(result.metadata?.agentUserSid, 'S-1-5-21-1001');
    assert.strictEqual(result.metadata?.ephemeralWorkspacePath, 'C:\\ProgramData\\ws');
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'provision');
    assert.strictEqual(envelope.containment, 'isolation_session');
    // An unpackaged app may pass any string; it reaches the wire config verbatim.
    const provisionConfig = (envelope.isolationSession as {
      provision?: { appId?: string };
    })?.provision;
    assert.strictEqual(provisionConfig?.appId, 'example.app.id');
    // The unrestricted-network acknowledgment is lifted to the envelope top level.
    assert.deepStrictEqual(envelope.network, {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    });
  });

  it('throws an MxcError carrying backend_unavailable when mxc_state_aware reports it', async () => {
    installStateAwareError({
      code: 'backend_unavailable',
      message: 'isolation session API not available on this host',
    });
    await assert.rejects(
      () => provisionSandbox('isolation_session', ACK),
      (err: unknown) => err instanceof MxcError && err.code === 'backend_unavailable',
    );
  });

  it('rejects unsupported options', async () => {
    await assert.rejects(
      () => provisionSandbox('isolation_session', ACK, {
        executablePath: 'wxc-exec.exe',
      }),
      (err: unknown) => err instanceof MxcError && err.message.includes("does not support option 'executablePath'"),
    );
  });

  it('rejects on abort and deprovisions a late provision result', async () => {
    const ac = new AbortController();
    const requests: BindingStateAwareRequest[] = [];
    let completeProvision!: (responseJson: string) => void;
    _setBindingStateAwareAsyncImplementation((request) => {
      requests.push(request);
      if (requests.length === 1) {
        return new Promise((resolve) => {
          completeProvision = resolve;
        });
      }
      return Promise.resolve('{"result":{}}');
    });
    const promise = provisionSandbox(
      'isolation_session',
      ACK,
      { signal: ac.signal },
    );
    ac.abort();
    await assert.rejects(promise);
    completeProvision('{"result":{"sandboxId":"iso:cleanup-me"}}');
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(requests.length, 2);
    assert.strictEqual(requestEnvelope(requests[1]!).phase, 'deprovision');
    assert.strictEqual(requestEnvelope(requests[1]!).sandboxId, 'iso:cleanup-me');
  });
});

describe('startSandbox', () => {
  it('infers backend from sandboxId prefix and sends no per-phase start config', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id);
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
    await startSandbox(id);
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });

  it('relays stable telemetry from phase config onto the start envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, { telemetry: { enabled: false } });
    const envelope = requestEnvelope(request());
    assert.deepStrictEqual(envelope.telemetry, { enabled: false });
    assert.strictEqual(envelope.version, '0.9.0-alpha');
    assert.strictEqual(envelope.experimental, undefined);
  });

});

describe('stopSandbox', () => {
  it('builds a minimal stop envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await stopSandbox(id);
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
    await stopSandbox(id);
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });
});

describe('deprovisionSandbox', () => {
  it('builds a minimal deprovision envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id);
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'deprovision');
    assert.strictEqual(envelope.sandboxId, 'iso:abc');
  });

  it('does not serialize correlationVector onto the deprovision envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id);
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });
});

describe('execInSandboxAsync', () => {
  it('does not require experimental authorization for stable backends', async () => {
    installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(16, 'stable\n', ''),
    );
    const result = await execInSandboxAsync(
      'iso:abc' as SandboxId<'isolation_session'>,
      { process: { commandLine: 'echo stable' } },
    );
    assert.deepStrictEqual(result, {
      stdout: 'stable\n',
      stderr: '',
      exitCode: 0,
    });
  });

  it('returns ExecResult on successful script run', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(17, 'hello\n', '', 1, { exitCode: 0, timedOut: false }),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const result = await execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hello', timeout: 250 } },
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
    );
    assert.deepStrictEqual(result, { stdout: 'oops\n', stderr: 'err\n', exitCode: 7 });
  });

  it('throws the typed MxcError on dispatch failure before a process is returned', async () => {
    _setStateAwareBindingSandboxProcessFactory(() => {
      throw new MxcError('stale_id', 'id expired');
    });
    const id = 'iso:prov-1' as SandboxId<'isolation_session'>;
    await assert.rejects(
      () => execInSandboxAsync(
        id,
        { process: { commandLine: 'echo' } },
        { experimental: true },
      ),
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
      { dryRun: true },
    );
    assert.deepStrictEqual(result, {
      stdout: '{"result":{"validated":true}}',
      stderr: '',
      exitCode: 0,
    });
    assert.strictEqual(requestEnvelope(request()).phase, 'exec');
  });

  it('throws a typed MxcError when dry-run validation returns an error envelope', async () => {
    installStateAwareReply(
      '{"error":{"code":"policy_validation","message":"invalid exec policy"}}',
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;

    await assert.rejects(
      () => execInSandboxAsync(
        id,
        { process: { commandLine: 'cat' } },
        { dryRun: true },
      ),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'policy_validation',
    );
  });

  it('does not dispatch when AbortSignal is already aborted', async () => {
    const ac = new AbortController();
    ac.abort(new Error('cancelled before dispatch'));
    let dispatchCount = 0;
    _setStateAwareBindingSandboxProcessFactory(() => {
      dispatchCount += 1;
      throw new Error('must not dispatch');
    });
    const id = 'iso:abc' as SandboxId<'isolation_session'>;

    await assert.rejects(
      () => execInSandboxAsync(
        id,
        { process: { commandLine: 'echo hi' } },
        { signal: ac.signal },
      ),
      /cancelled before dispatch/,
    );
    assert.strictEqual(dispatchCount, 0);
  });

  it('kills and disposes the live process when AbortSignal fires', async () => {
    const ac = new AbortController();
    const reason = new Error('cancelled by caller');
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(19, '', '', Number.MAX_SAFE_INTEGER),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const promise = execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hi' } },
      { signal: ac.signal },
    );
    ac.abort(reason);
    await assert.rejects(promise, (error: unknown) => error === reason);
    assert.strictEqual(exec.binding().killed, true);
    assert.strictEqual(exec.binding().killCount, 1);
    assert.strictEqual(exec.binding().freed, true);
  });

  it('cancels while stdout and stderr are still active', async () => {
    const ac = new AbortController();
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(
        20,
        '',
        '',
        Number.MAX_SAFE_INTEGER,
        { exitCode: 0, timedOut: false },
        [],
        false,
      ),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const promise = execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hi' } },
      { signal: ac.signal },
    );

    ac.abort();
    await assert.rejects(promise);
    assert.strictEqual(exec.binding().standardOutput.destroyed, true);
    assert.strictEqual(exec.binding().standardError.destroyed, true);
    assert.strictEqual(exec.binding().killed, true);
    assert.strictEqual(exec.binding().freed, true);
  });

  it('preserves the abort reason when native cancellation cleanup fails', async () => {
    const ac = new AbortController();
    const reason = new Error('cancelled by caller');
    const binding = new FakeStateAwareExecBinding(
      21,
      '',
      '',
      Number.MAX_SAFE_INTEGER,
    );
    binding.killError = new Error('native kill failed');
    const exec = installStateAwareExecBinding(() => binding);
    const promise = execInSandboxAsync(
      'iso:abc' as SandboxId<'isolation_session'>,
      { process: { commandLine: 'echo hi' } },
      { signal: ac.signal },
    );

    ac.abort(reason);
    await assert.rejects(promise, (error: unknown) => error === reason);
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(exec.binding().killCount, 2);
    assert.strictEqual(exec.binding().freed, true);
  });

  it('rejects unsupported options', async () => {
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    for (const [option, value] of [
      ['executablePath', 'wxc-exec.exe'],
      ['skipPlatformCheck', true],
      ['inheritDefaultEnv', true],
    ] as const) {
      await assert.rejects(
        () => execInSandboxAsync(
          id,
          { process: { commandLine: 'echo hi' } },
          { [option]: value },
        ),
        (err: unknown) =>
          err instanceof MxcError &&
          err.message.includes(`does not support option '${option}'`),
      );
    }
  });
});

describe('execInSandbox', () => {
  it('returns a live MxcSandboxProcess backed by the shared FFI controller', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(22, 'live\n', '', 0, { exitCode: 0, timedOut: false }, ['warning']),
    );
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const proc = execInSandbox(
      id,
      { process: { commandLine: 'echo live', timeout: 123 } },
    );

    try {
      assert.strictEqual(proc.id, 22);
      assert.deepStrictEqual(proc.warnings, ['warning']);
      assert.strictEqual(await readStreamText(proc.standardOutput), 'live\n');
      assert.deepStrictEqual(await proc.waitAsync(), { exitCode: 0, timedOut: false });
      assert.deepStrictEqual(exec.request().process, { commandLine: 'echo live', timeout: 123 });
      assert.strictEqual(exec.experimental(), false);
      assert.strictEqual(exec.timeout(), 123);
    } finally {
      proc.dispose();
    }
  });

  it('forwards experimental authorization for experimental backends', () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(23, '', '', Number.MAX_SAFE_INTEGER),
    );
    const proc = execInSandbox(
      'iso:abc' as SandboxId<'isolation_session'>,
      { process: { commandLine: 'echo live' } },
      { experimental: true },
    );
    try {
      assert.strictEqual(exec.experimental(), true);
    } finally {
      proc.dispose();
    }
  });

  it('rejects dryRun because no live process exists', () => {
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    assert.throws(
      () => execInSandbox(
        id,
        { process: { commandLine: 'echo live' } },
        { dryRun: true } as StateAwareStreamingOptions,
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'malformed_request' && /does not support dryRun/.test(err.message),
    );
  });

  it('rejects AbortSignal because callers own the live process', () => {
    const controller = new AbortController();
    assert.throws(
      () => execInSandbox(
        'iso:abc' as SandboxId<'isolation_session'>,
        { process: { commandLine: 'echo done' } },
        {
          signal: controller.signal,
        } as StateAwareStreamingOptions,
      ),
      (err: unknown) => err instanceof MxcError
        && err.code === 'malformed_request'
        && /call kill\(\)/.test(err.message),
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
        version: '0.10.0-alpha',
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

  describe('round-trip via the typed API', () => {
    it('provisionSandbox builds a windows_sandbox envelope and routes back via the wsb: prefix', async () => {
      const request = installStateAwareReply('{"result":{"sandboxId":"wsb:prov-1"}}');
      const result = await provisionSandbox(
        'windows_sandbox',
        { filesystem: { readonlyPaths: ['C:\\inputs'] } },
        { experimental: true },
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
      await startSandbox(id, undefined, { experimental: true });
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'start');
      assert.strictEqual(envelope.sandboxId, 'wsb:prov-1');
      assert.strictEqual(envelope.experimental, undefined);
    });

    it('execInSandboxAsync rejects live execution for a wsb: id', async () => {
      const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
      await assert.rejects(
        () => execInSandboxAsync(
          id as unknown as SandboxId<'isolation_session'>,
          { process: { commandLine: 'echo hello-from-wsb' } },
          { experimental: true },
        ),
        (error: unknown) =>
          error instanceof MxcError &&
          error.code === 'unsupported_containment',
      );
    });

    it('execInSandboxAsync can dry-run a wsb exec request', async () => {
      const request = installStateAwareReply('{"result":{"validated":true}}');
      const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
      await execInSandboxAsync(
        id,
        { process: { commandLine: 'echo hello-from-wsb' } },
        { dryRun: true, experimental: true },
      );
      assert.strictEqual(requestEnvelope(request()).phase, 'exec');
    });

    it('stopSandbox and deprovisionSandbox build minimal envelopes for a wsb: id', async () => {
      for (const phase of ['stop', 'deprovision'] as const) {
        const request = installStateAwareReply('{"result":{}}');
        const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
        const call = phase === 'stop' ? stopSandbox : deprovisionSandbox;
        await call(id, undefined, { experimental: true });
        const envelope = requestEnvelope(request());
        assert.strictEqual(envelope.phase, phase);
        assert.strictEqual(envelope.sandboxId, 'wsb:prov-1');
      }
    });
  });
});

describe('wslc state-aware lifecycle', () => {
  it('defaults the version to the published 0.9.0-alpha contract', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: { image: 'alpine:latest' },
    });
    assert.strictEqual(env.version, '0.9.0-alpha');
  });

  it('rejects a caller-supplied version without a registered wslc state-aware contract', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'provision',
        backendKey: 'wslc',
        containment: 'wslc',
        config: { version: '0.8.1-alpha', image: 'alpine:latest' },
      }),
      (err: unknown) => err instanceof MxcError &&
        err.code === 'malformed_request' &&
        /require schema version '0\.9\.0-alpha'/.test(err.message),
    );
  });

  it('lifts filesystem + network and nests image under wslc.provision', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: {
        filesystem: { readwritePaths: ['C:\\ws\\rw'] },
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow', hostLoopback: 'allow' },
        },
        image: 'alpine:latest',
        imageTarPath: 'C:\\images\\alpine.tar',
      },
    });
    assert.strictEqual(env.containment, 'wslc');
    assert.deepStrictEqual(env.filesystem, { readwritePaths: ['C:\\ws\\rw'] });
    assert.deepStrictEqual(env.network, {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.deepStrictEqual(wire.wslc, {
      provision: { image: 'alpine:latest', imageTarPath: 'C:\\images\\alpine.tar' },
    });
  });

  it('omits the WSLC section when provision carries no backend-specific field', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: {
        network: {
          egress: { default: 'deny' },
          ingress: { default: 'deny', hostLoopback: 'deny' },
        },
      },
    });
    assert.strictEqual(env.wslc, undefined);
    assert.deepStrictEqual(env.network, {
      egress: { default: 'deny' },
      ingress: { default: 'deny', hostLoopback: 'deny' },
    });
  });

  it('lifts exec process + cooperative proxy network to top-level with no experimental block', () => {
    const env = buildStateAwareEnvelope({
      phase: 'exec',
      backendKey: 'wslc',
      sandboxId: 'wslc:abc',
      config: {
        process: { commandLine: 'echo hi' },
        runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' },
      },
    });
    assert.deepStrictEqual(env.process, { commandLine: 'echo hi' });
    assert.deepStrictEqual(env.runtimeConfig, {
      networkProxy: 'http://127.0.0.1:8888',
    });
    assert.strictEqual(env.experimental, undefined);
  });

  describe('round-trip via the typed API', () => {
    it('provisionSandbox builds a wslc envelope and routes back via the wslc: prefix', async () => {
      const request = installStateAwareReply('{"result":{"sandboxId":"wslc:0123abcd"}}');
      const result = await provisionSandbox(
        'wslc',
        {
          image: 'alpine:latest',
          network: {
            egress: { default: 'deny' },
            ingress: { default: 'deny', hostLoopback: 'deny' },
          },
        },
      );
      assert.strictEqual(result.sandboxId, 'wslc:0123abcd');
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'provision');
      assert.strictEqual(envelope.containment, 'wslc');
      assert.strictEqual(envelope.version, '0.9.0-alpha');
    });

    it('startSandbox infers wslc from the wslc: prefix', async () => {
      const request = installStateAwareReply('{"result":{}}');
      const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
      await startSandbox(id);
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'start');
      assert.strictEqual(envelope.sandboxId, 'wslc:0123abcd');
      assert.strictEqual(envelope.experimental, undefined);
    });

    it('execInSandboxAsync rejects live execution for a wslc: id', async () => {
      const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
      await assert.rejects(
        () => execInSandboxAsync(
          id as unknown as SandboxId<'isolation_session'>,
          { process: { commandLine: 'echo hello-from-wslc' } },
        ),
        (error: unknown) =>
          error instanceof MxcError &&
          error.code === 'unsupported_containment',
      );
    });

    it('stopSandbox and deprovisionSandbox build minimal envelopes for a wslc: id', async () => {
      for (const phase of ['stop', 'deprovision'] as const) {
        const request = installStateAwareReply('{"result":{}}');
        const id = 'wslc:0123abcd' as SandboxId<'wslc'>;
        const call = phase === 'stop' ? stopSandbox : deprovisionSandbox;
        await call(id);
        const envelope = requestEnvelope(request());
        assert.strictEqual(envelope.phase, phase);
        assert.strictEqual(envelope.sandboxId, 'wslc:0123abcd');
      }
    });
  });
});
