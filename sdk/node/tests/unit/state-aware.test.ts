// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { PassThrough } from 'node:stream';
import {
  deprovisionContainer,
  spawnInContainer,
  runInContainer,
  spawnInContainerWithPty,
  provisionContainer,
  startContainer,
  stopContainer,
  validateProvision,
  validateProcess,
  validateStart,
  validateStop,
  validateDeprovision,
} from '../../src/v1/lifecycle.js';
import {
  buildStateAwareEnvelope,
  parseNonExecResponse,
} from '../../src/state-aware-helper.js';
import {
  _setBindingStateAwareAsyncImplementation,
  type BindingStateAwareRequest,
} from '../../src/bindings/state-aware.js';
import { _setStateAwareBindingSandboxProcessFactory } from '../../src/bindings/streaming.js';
import { MxcError, type MxcErrorFields } from '../../src/v1/errors.js';
import { ContainerId } from '../../src/v1/lifecycle-types.js';
import {
  MxcProcess,
  type NativeLifecycleDriver,
  type NativeLifecycleStatus,
} from '../../src/v1/container-process.js';

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
    return new MxcProcess(binding, timeout);
  });
  return {
    binding: () => {
      assert.ok(binding, 'expected a state-aware exec binding');
      return binding;
    },
    request: () => {
      assert.ok(requestJson, 'expected a state-aware execution request');
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

describe('lifecycle execution options', () => {
  it('rejects supplied dryRun on asynchronous execution and lifecycle operations', async () => {
    _setBindingStateAwareAsyncImplementation(async () => {
      assert.fail('invalid options must not reach native execution');
    });
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    for (const dryRun of [true, false, undefined]) {
      const options = { dryRun } as never;
      for (const operation of [
        () => provisionContainer({
          containment: 'isolation_session',
          network: {
            egress: { default: 'allow' },
            ingress: { default: 'allow', hostLoopback: 'allow' },
          },
        }, options),
        () => startContainer(id, options),
        () => stopContainer(id, options),
        () => deprovisionContainer(id, options),
        () => runInContainer(id, { command: 'echo hello' }, options),
        () => spawnInContainer(id, { command: 'echo hello' }, options),
      ]) {
        await assert.rejects(
          async () => operation(),
          (error: unknown) => error instanceof MxcError
            && error.code === 'malformed_request'
            && /does not support dryRun/.test(error.message),
        );
      }
      await assert.rejects(
        spawnInContainerWithPty(id, { command: 'echo hello' }, options),
        /does not support dryRun/,
      );
    }
  });
});

describe('validation results', () => {
  const id = 'iso:validation' as ContainerId<'isolation_session'>;
  const calls = [
    () => validateProvision({ containment: 'wslc' }, { experimental: true, telemetry: { enabled: false } }),
    () => validateStart(id, { experimental: true, telemetry: { enabled: false } }),
    () => validateStop(id, { experimental: true, telemetry: { enabled: false } }),
    () => validateDeprovision(id, { experimental: true, telemetry: { enabled: false } }),
    () => validateProcess(id, { command: 'echo validation' }, { experimental: true, telemetry: { enabled: false } }),
  ];

  it('preserves warnings for every phase without executing a workload', async () => {
    _setStateAwareBindingSandboxProcessFactory(() => {
      throw new Error('validation must not spawn');
    });
    for (const call of calls) {
      const request = installStateAwareReply('{"result":{"warnings":["policy warning","telemetry warning"]}}');
      assert.deepStrictEqual(await call(), { warnings: ['policy warning', 'telemetry warning'] });
      assert.strictEqual(request().dryRun, true);
      assert.strictEqual(request().experimental, true);
      assert.deepStrictEqual(requestEnvelope(request()).telemetry, { enabled: false });
    }
  });

  describe('lifecycle results', () => {
    const id = 'iso:results' as ContainerId<'isolation_session'>;
    const calls = [
      () => startContainer(id),
      () => stopContainer(id),
      () => deprovisionContainer(id),
    ];

    it('preserves warnings across lifecycle operations and provision', async () => {
      installStateAwareReply('{"result":{"sandboxId":"wslc:results","warnings":["policy warning","cleanup warning"]}}');
      for (const call of calls) {
        assert.deepStrictEqual(await call(), { warnings: ['policy warning', 'cleanup warning'] });
      }
      const provision = await provisionContainer({ containment: 'wslc' });
      assert.deepStrictEqual(provision.warnings, ['policy warning', 'cleanup warning']);
      assert.strictEqual(provision.containerId, 'wslc:results');
    });

    it('defaults omitted warnings to empty arrays', async () => {
      installStateAwareReply('{"result":{"sandboxId":"wslc:results"}}');
      for (const call of calls) assert.deepStrictEqual(await call(), { warnings: [] });
      assert.deepStrictEqual((await provisionContainer({ containment: 'wslc' })).warnings, []);
    });

    it('rejects malformed warnings and result objects', async () => {
      for (const result of [null, [], 42, { warnings: null }, { warnings: [null] }, { warnings: [1] }]) {
        installStateAwareReply(JSON.stringify({ result }));
        for (const call of calls) {
          await assert.rejects(call, (error: unknown) => error instanceof MxcError && error.code === 'backend_error');
        }
        const provisionResult = typeof result === 'object' && result !== null && !Array.isArray(result)
          ? { ...result, sandboxId: 'wslc:results' } : result;
        installStateAwareReply(JSON.stringify({ result: provisionResult }));
        await assert.rejects(() => provisionContainer({ containment: 'wslc' }),
          (error: unknown) => error instanceof MxcError && error.code === 'backend_error');
      }
    });

    it('rejects missing or malformed provision metadata fields', async () => {
      const request = {
        containment: 'isolation_session',
        network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow', hostLoopback: 'allow' },
        },
      } as const;
      for (const metadata of [{}, { agentUserName: null, agentUserSid: 'sid', ephemeralWorkspacePath: 'path' }]) {
        installStateAwareReply(JSON.stringify({ result: { sandboxId: id, metadata } }));
        await assert.rejects(() => provisionContainer(request),
          (error: unknown) => error instanceof MxcError && error.code === 'backend_error');
      }
    });
  });

  it('returns an empty warning list when native warnings are omitted or empty', async () => {
    for (const reply of ['{"result":{}}', '{"result":{"warnings":[]}}']) {
      installStateAwareReply(reply);
      for (const call of calls) assert.deepStrictEqual(await call(), { warnings: [] });
    }
  });

  it('rejects malformed results rather than treating them as successful validation', async () => {
    for (const result of [null, [], 42, { warnings: null }, { warnings: 'warning' }, { warnings: [1] }]) {
      installStateAwareReply(JSON.stringify({ result }));
      for (const call of calls) {
        await assert.rejects(call, (error: unknown) =>
          error instanceof MxcError && error.code === 'backend_error');
      }
    }
  });
});

describe('buildStateAwareEnvelope', () => {
  it('lifts telemetry to the top-level envelope', () => {
    const env = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'isolation_session',
      sandboxId: 'iso:01234567',
      config: { telemetry: { enabled: true } },
    });
    assert.deepEqual(env.telemetry, { enabled: true });
    assert.equal(env.version, '1.0.0');
    assert.equal(env.experimental, undefined);
  });

  it('rejects any caller-selected schema version', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'start',
        backendKey: 'isolation_session',
        sandboxId: 'iso:01234567',
        config: { version: '1.0.0', telemetry: { enabled: true } },
      }),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'malformed_request' &&
        error.message.includes(
          'State-aware high-level requests do not accept a caller-selected version',
        ),
    );
  });

  it('selects stable schema 1.0 when WSLC exec inherits the backend environment', () => {
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
    assert.equal(env.version, '1.0.0');
    assert.deepEqual(env.process, {
      commandLine: 'echo hi',
      inheritDefaultEnv: true,
    });
  });

  it('rejects a caller-selected version when the environment is inherited', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'exec',
        backendKey: 'wslc',
        sandboxId: 'wslc:abc',
        config: {
          version: '1.0.0',
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
          'State-aware high-level requests do not accept a caller-selected version',
        ),
    );
  });

  it('produces a provision envelope with cross-cutting fields lifted to top-level', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
      config: {
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
        /do not accept a caller-selected version/.test(err.message),
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
    assert.strictEqual(env.version, '1.0.0');
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

describe('provisionContainer', () => {
  // The unrestricted-network posture is a required member of
  // IsolationSessionProvisionConfig, so `provisionContainer` will not accept an
  // omitted config for this backend. Tests below that are not about the config
  // itself use this minimal valid value.
  const ACK = {
    network: {
      egress: { default: 'allow' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    },
  } as const;

  it('builds a provision envelope and unwraps the ContainerId from the response', async () => {
    const request = installStateAwareReply(
      '{"result":{"sandboxId":"iso:reg-abc:prov-1","metadata":{"agentUserName":"agent\\\\u1","agentUserSid":"S-1-5-21-1001","ephemeralWorkspacePath":"C:\\\\ProgramData\\\\ws"}}}',
    );
    const result = await provisionContainer(
      { containment: 'isolation_session', network: {
          egress: { default: 'allow' },
          ingress: { default: 'allow', hostLoopback: 'allow' },
        }, appId: 'example.app.id' },
    );
    assert.strictEqual(result.containerId, 'iso:reg-abc:prov-1');
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

  it('throws an MxcError carrying backend_unavailable when mxc_run_state_aware_json reports it', async () => {
    installStateAwareError({
      code: 'backend_unavailable',
      message: 'isolation session API not available on this host',
    });
    await assert.rejects(
      () => provisionContainer({ containment: 'isolation_session', ...ACK }),
      (err: unknown) => err instanceof MxcError && err.code === 'backend_unavailable',
    );
  });

  it('rejects unsupported options', async () => {
    await assert.rejects(
      () => provisionContainer({ containment: 'isolation_session', ...ACK }, {
        executablePath: 'wxc-exec.exe',
      } as never),
      (err: unknown) => err instanceof MxcError && err.message.includes("does not support option 'executablePath'"),
    );
  });

  it('forwards experimental authorization for explicit provision validation', async () => {
    const request = installStateAwareReply('{"result":{}}');
    await validateProvision({ containment: 'isolation_session', ...ACK }, {
      experimental: true,
    });
    assert.strictEqual(request().experimental, true);
    assert.strictEqual(request().dryRun, true);
  });
});

describe('startContainer', () => {
  it('infers backend from sandboxId prefix and sends no per-phase start config', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as ContainerId<'isolation_session'>;
    await startContainer(id);
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
    const id = 'iso:reg-abc:prov-1' as ContainerId<'isolation_session'>;
    await startContainer(id);
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });

  it('rejects Windows Sandbox identities in the stable lifecycle API', async () => {
    await assert.rejects(
      () => startContainer('wsb:prov-1' as ContainerId<'isolation_session'>),
      (err: unknown) =>
        err instanceof MxcError &&
        err.code === 'unsupported_containment' &&
        err.message.includes('Windows Sandbox identities are experimental'),
    );
  });

  it('relays stable telemetry from phase config onto the start envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:reg-abc:prov-1' as ContainerId<'isolation_session'>;
    await startContainer(id, { telemetry: { enabled: false } });
    const envelope = requestEnvelope(request());
    assert.deepStrictEqual(envelope.telemetry, { enabled: false });
    assert.strictEqual(envelope.version, '1.0.0');
    assert.strictEqual(envelope.experimental, undefined);
  });

});

describe('stopContainer', () => {
  it('builds a minimal stop envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    await stopContainer(id);
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'stop');
    assert.strictEqual(envelope.sandboxId, 'iso:abc');
    assert.strictEqual(envelope.experimental, undefined);
  });

  it('rejects with malformed_id when sandboxId has no recognised prefix', async () => {
    await assert.rejects(
      () => stopContainer('not-a-real-id' as ContainerId<'isolation_session'>),
      (err: unknown) => err instanceof MxcError && err.code === 'malformed_id',
    );
    await assert.rejects(
      () => stopContainer('unknownprefix:abc' as ContainerId<'isolation_session'>),
      (err: unknown) => err instanceof MxcError && err.code === 'malformed_id',
    );
  });

  it('does not serialize correlationVector onto the stop envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    await stopContainer(id);
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });
});

describe('deprovisionContainer', () => {
  it('builds a minimal deprovision envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    await deprovisionContainer(id);
    const envelope = requestEnvelope(request());
    assert.strictEqual(envelope.phase, 'deprovision');
    assert.strictEqual(envelope.sandboxId, 'iso:abc');
  });

  it('does not serialize correlationVector onto the deprovision envelope', async () => {
    const request = installStateAwareReply('{"result":{}}');
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    await deprovisionContainer(id);
    assert.strictEqual(requestEnvelope(request()).correlationVector, undefined);
  });
});

describe('runInContainer', () => {
  it('does not require experimental authorization for stable backends', async () => {
    installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(16, 'stable\n', ''),
    );
    const result = await runInContainer(
      'iso:abc' as ContainerId<'isolation_session'>,
      { command: 'echo stable' },
    );
    assert.deepStrictEqual(result, {
      stdout: 'stable\n',
      stderr: '',
      exitCode: 0,
      timedOut: false,
      warnings: [],
    });
  });

  it('returns ExecResult on successful script run', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(17, 'hello\n', '', 1, { exitCode: 0, timedOut: false }),
    );
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    const result = await runInContainer(
      id,
      { command: 'echo hello',
timeoutMs: 250 },
    );
    assert.deepStrictEqual(result, {
      stdout: 'hello\n',
      stderr: '',
      exitCode: 0,
      timedOut: false,
      warnings: [],
    });
    assert.deepStrictEqual(exec.request().process, { commandLine: 'echo hello', timeout: 250 });
    assert.strictEqual(exec.request().correlationVector, undefined);
    assert.strictEqual(exec.timeout(), 250);
    assert.strictEqual(exec.binding().freed, true);
  });

  it('forwards experimental authorization to state-aware streaming exec', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(17, '', ''),
    );
    const result = await runInContainer(
      'iso:abc' as ContainerId<'isolation_session'>,
      { command: 'echo experimental' },
      { experimental: true },
    );
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(exec.experimental(), true);
  });

  it('returns ExecResult on script exit != 0 when stdout is plain script output (not an error envelope)', async () => {
    installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(18, 'oops\n', 'err\n', 0, { exitCode: 7, timedOut: false }),
    );
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    const result = await runInContainer(
      id,
      { command: 'fail' },
    );
    assert.deepStrictEqual(result, {
      stdout: 'oops\n',
      stderr: 'err\n',
      exitCode: 7,
      timedOut: false,
      warnings: [],
    });
  });

  it('throws the typed MxcError on dispatch failure before a process is returned', async () => {
    _setStateAwareBindingSandboxProcessFactory(() => {
      throw new MxcError('stale_id', 'id expired');
    });
    const id = 'iso:prov-1' as ContainerId<'isolation_session'>;
    await assert.rejects(
      () => runInContainer(
        id,
        { command: 'echo' },
        {},
      ),
      (err: unknown) => err instanceof MxcError && err.code === 'stale_id',
    );
  });

  it('validates a process without spawning or fabricating execution output', async () => {
    const request = installStateAwareReply('{"result":{"validated":true}}');
    _setStateAwareBindingSandboxProcessFactory(() => {
      throw new Error('dry-run should not create a live process');
    });
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    const result = await validateProcess(
      id,
      { command: 'cat' },
    );
    assert.deepStrictEqual(result, { warnings: [] });
    assert.strictEqual(request().dryRun, true);
    assert.strictEqual(requestEnvelope(request()).phase, 'exec');
  });

  it('throws a typed MxcError when dry-run validation returns an error envelope', async () => {
    installStateAwareReply(
      '{"error":{"code":"policy_validation","message":"invalid exec policy"}}',
    );
    const id = 'iso:abc' as ContainerId<'isolation_session'>;

    await assert.rejects(
      () => validateProcess(
        id,
        { command: 'cat' },
      ),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'policy_validation',
    );
  });

  it('rejects unsupported options', async () => {
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    for (const [option, value] of [
      ['executablePath', 'wxc-exec.exe'],
      ['skipPlatformCheck', true],
      ['inheritDefaultEnv', true],
      ['signal', new AbortController().signal],
    ] as const) {
      await assert.rejects(
        () => runInContainer(
          id,
          { command: 'echo hi' },
          { [option]: value },
        ),
        (err: unknown) =>
          err instanceof MxcError &&
          err.message.includes(`does not support option '${option}'`),
      );
    }
  });
});

describe('spawnInContainer', () => {
  it('returns a live MxcProcess backed by the shared FFI controller', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(22, 'live\n', '', 0, { exitCode: 0, timedOut: false }, ['warning']),
    );
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    const proc = await spawnInContainer(
      id,
      { command: 'echo live',
timeoutMs: 123 },
    );

    try {
      assert.strictEqual(proc.id, 22);
      assert.deepStrictEqual(proc.warnings, ['warning']);
      assert.strictEqual(await readStreamText(proc.standardOutput), 'live\n');
      assert.deepStrictEqual(await proc.wait(), { exitCode: 0, timedOut: false });
      assert.deepStrictEqual(exec.request().process, { commandLine: 'echo live', timeout: 123 });
      assert.strictEqual(exec.experimental(), false);
      assert.strictEqual(exec.timeout(), 123);
    } finally {
      proc.dispose();
    }
  });

  describe('spawnInContainerWithPty', () => {
    const config = { command: 'powershell.exe' };

    it('rejects invalid terminal dimensions before loading native bindings', async () => {
      await assert.rejects(
        spawnInContainerWithPty(
          'iso:abc' as ContainerId<'isolation_session'>,
          config,
          { size: { rows: 0, columns: 80 } },
        ),
        (error: unknown) => error instanceof MxcError
          && error.code === 'malformed_request'
          && /rows and columns/.test(error.message),
      );
    });
  });

  it('forwards experimental authorization for live exec', async () => {
    const exec = installStateAwareExecBinding(
      () => new FakeStateAwareExecBinding(22, '', ''),
    );
    const proc = await spawnInContainer(
      'iso:abc' as ContainerId<'isolation_session'>,
      { command: 'echo live' },
      { experimental: true },
    );
    assert.strictEqual(exec.experimental(), true);
    proc.dispose();
  });
  it('rejects any supplied dryRun because no live process exists', async () => {
    const id = 'iso:abc' as ContainerId<'isolation_session'>;
    for (const dryRun of [true, false, undefined]) {
      await assert.rejects(
        spawnInContainer(
          id,
          { command: 'echo live' },
          { dryRun } as never,
        ),
        (err: unknown) => err instanceof MxcError && err.code === 'malformed_request' && /does not support dryRun/.test(err.message),
      );
    }
  });

  it('rejects unsupported execution options', async () => {
    await assert.rejects(
      spawnInContainer(
        'iso:abc' as ContainerId<'isolation_session'>,
        { command: 'echo done' },
        { signal: new AbortController().signal } as never,
      ),
      (err: unknown) => err instanceof MxcError
        && err.code === 'malformed_request'
        && /does not support option 'signal'/.test(err.message),
    );
  });
});

describe('wslc state-aware lifecycle', () => {
  it('targets the SDK-owned stable 1.0.0 contract', () => {
    const env = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'wslc',
      containment: 'wslc',
      config: { image: 'alpine:latest' },
    });
    assert.strictEqual(env.version, '1.0.0');
  });

  it('rejects a caller-supplied version', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'provision',
        backendKey: 'wslc',
        containment: 'wslc',
        config: { version: '1.0.0', image: 'alpine:latest' },
      }),
      (err: unknown) => err instanceof MxcError &&
        err.code === 'malformed_request' &&
        /do not accept a caller-selected version/.test(err.message),
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
        network: { runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' } },
      },
    });
    assert.deepStrictEqual(env.process, { commandLine: 'echo hi' });
    assert.deepStrictEqual(env.runtimeConfig, {
      networkProxy: 'http://127.0.0.1:8888',
    });
    assert.strictEqual(env.network, undefined);
    assert.strictEqual(env.experimental, undefined);
  });

  it('rejects state-aware runtime config outside network.runtimeConfig', () => {
    assert.throws(
      () => buildStateAwareEnvelope({
        phase: 'exec',
        backendKey: 'wslc',
        sandboxId: 'wslc:abc',
        config: {
          process: { commandLine: 'echo hi' },
          runtimeConfig: { networkProxy: 'http://127.0.0.1:8888' },
        },
      }),
      (err: unknown) => err instanceof MxcError
        && err.code === 'malformed_request'
        && /network\.runtimeConfig/.test(err.message),
    );
  });

  describe('round-trip via the typed API', () => {
    it('provisionContainer builds a wslc envelope and routes back via the wslc: prefix', async () => {
      const request = installStateAwareReply('{"result":{"sandboxId":"wslc:0123abcd"}}');
      const result = await provisionContainer(
        { containment: 'wslc', image: 'alpine:latest', network: {
            egress: { default: 'deny' },
            ingress: { default: 'deny', hostLoopback: 'deny' },
          } },
      );
      assert.strictEqual(result.containerId, 'wslc:0123abcd');
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'provision');
      assert.strictEqual(envelope.containment, 'wslc');
      assert.strictEqual(envelope.version, '1.0.0');
    });

    it('startContainer infers wslc from the wslc: prefix', async () => {
      const request = installStateAwareReply('{"result":{}}');
      const id = 'wslc:0123abcd' as ContainerId<'wslc'>;
      await startContainer(id);
      const envelope = requestEnvelope(request());
      assert.strictEqual(envelope.phase, 'start');
      assert.strictEqual(envelope.sandboxId, 'wslc:0123abcd');
      assert.strictEqual(envelope.experimental, undefined);
    });

    it('runInContainer runs live execution for a wslc: id', async () => {
      const exec = installStateAwareExecBinding(
        () => new FakeStateAwareExecBinding(31, 'hello-from-wslc\n', ''),
      );
      const id = 'wslc:0123abcd' as ContainerId<'wslc'>;
      const result = await runInContainer(
        id,
        { command: 'echo hello-from-wslc' },
      );
      assert.deepStrictEqual(result, {
        stdout: 'hello-from-wslc\n',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        warnings: [],
      });
      assert.strictEqual(exec.request().phase, 'exec');
      assert.strictEqual(exec.request().sandboxId, 'wslc:0123abcd');
    });

    it('stopContainer and deprovisionContainer build minimal envelopes for a wslc: id', async () => {
      for (const phase of ['stop', 'deprovision'] as const) {
        const request = installStateAwareReply('{"result":{}}');
        const id = 'wslc:0123abcd' as ContainerId<'wslc'>;
        const call = phase === 'stop' ? stopContainer : deprovisionContainer;
        await call(id);
        const envelope = requestEnvelope(request());
        assert.strictEqual(envelope.phase, phase);
        assert.strictEqual(envelope.sandboxId, 'wslc:0123abcd');
      }
    });
  });
});
