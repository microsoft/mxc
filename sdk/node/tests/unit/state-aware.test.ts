// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  deprovisionSandbox,
  execInSandboxAsync,
  provisionSandbox,
  startSandbox,
  stopSandbox,
} from '../../src/state-aware.js';
import {
  _resetSpawnImpl,
  _setSpawnImpl,
  buildStateAwareEnvelope,
  parseNonExecResponse,
} from '../../src/state-aware-helper.js';
import { MxcError } from '../../src/errors.js';
import { SandboxId } from '../../src/state-aware-types.js';
import { fakeSpawn, testOptions, platformSkip } from './test-helpers.js';

describe('buildStateAwareEnvelope', () => {
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
      config: { appId: 'Contoso.App_8wekyb3d8bbwe' },
    });
    const wire = JSON.parse(JSON.stringify(env));
    assert.deepStrictEqual(wire.experimental, {
      isolation_session: {
        provision: { appId: 'Contoso.App_8wekyb3d8bbwe' },
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

  it('relays correlationVector onto non-provision envelopes and omits it from provision', () => {
    const nonProvision = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'isolation_session',
      sandboxId: 'iso:abc',
      correlationVector: 'BASEbaseBASEbaseBASEba.1',
    });
    assert.strictEqual(nonProvision.correlationVector, 'BASEbaseBASEbaseBASEba.1');

    // Provision seeds its own cV in the executor; the builder never emits one.
    const provision = buildStateAwareEnvelope({
      phase: 'provision',
      backendKey: 'isolation_session',
      containment: 'isolation_session',
    });
    assert.strictEqual(provision.correlationVector, undefined);
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
  let activeFake: ReturnType<typeof fakeSpawn> | null = null;

  // The unrestricted-network acknowledgment is a required member of
  // IsolationSessionProvisionConfig, so `provisionSandbox` will not accept an
  // omitted config for this backend. Tests below that are not about the config
  // itself use this minimal valid value.
  const ACK = { network: { defaultPolicy: 'allow', allowLocalNetwork: true } } as const;

  beforeEach(() => { activeFake = null; });
  afterEach(() => { _resetSpawnImpl(); activeFake = null; });

  it('builds a provision envelope and unwraps the SandboxId from the response', async () => {
    const fake = fakeSpawn({
      stdout: '{"result":{"sandboxId":"iso:reg-abc:prov-1","metadata":{"agentUserName":"agent\\\\u1","agentUserSid":"S-1-5-21-1001","ephemeralWorkspacePath":"C:\\\\ProgramData\\\\ws"}}}',
      exitCode: 0,
    });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    const result = await provisionSandbox(
      'isolation_session',
      {
        network: { defaultPolicy: 'allow', allowLocalNetwork: true },
        appId: 'Contoso.App_8wekyb3d8bbwe',
      },
      testOptions(),
    );
    assert.strictEqual(result.sandboxId, 'iso:reg-abc:prov-1');
    assert.strictEqual(result.metadata?.agentUserName, 'agent\\u1');
    assert.strictEqual(result.metadata?.agentUserSid, 'S-1-5-21-1001');
    assert.strictEqual(result.metadata?.ephemeralWorkspacePath, 'C:\\ProgramData\\ws');
    assert.strictEqual(fake.captured.envelope?.phase, 'provision');
    assert.strictEqual(fake.captured.envelope?.containment, 'isolation_session');
    // The unrestricted-network acknowledgment is lifted to the envelope top level.
    assert.deepStrictEqual(fake.captured.envelope?.network, {
      defaultPolicy: 'allow',
      allowLocalNetwork: true,
    });
    assert.ok(fake.captured.args?.includes('--experimental'));
  });

  it('surfaces the correlationVector from the provision result envelope', async () => {
    const fake = fakeSpawn({
      stdout: '{"result":{"sandboxId":"iso:reg-abc:prov-1","correlationVector":"BASEbaseBASEbaseBASEba.42"}}',
      exitCode: 0,
    });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    const result = await provisionSandbox('isolation_session', ACK, testOptions());
    assert.strictEqual(result.correlationVector, 'BASEbaseBASEbaseBASEba.42');
    // Provision itself never sends a correlationVector on the wire.
    assert.strictEqual(fake.captured.envelope?.correlationVector, undefined);
  });

  it('throws an MxcError carrying backend_unavailable when the executor reports it', async () => {
    const fake = fakeSpawn({
      stdout: '{"error":{"code":"backend_unavailable","message":"isolation session API not available on this host"}}',
      exitCode: 1,
    });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    await assert.rejects(
      () => provisionSandbox('isolation_session', ACK, testOptions()),
      (err: unknown) => err instanceof MxcError && err.code === 'backend_unavailable',
    );
  });

  it('rejects when AbortSignal fires before close', async () => {
    const ac = new AbortController();
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    const promise = provisionSandbox(
      'isolation_session',
      ACK,
      testOptions({ signal: ac.signal }),
    );
    ac.abort();
    await assert.rejects(promise);
    assert.ok(activeFake.killCount() >= 1, 'expected child.kill() to fire on abort');
  });
});

describe('startSandbox', { skip: platformSkip }, () => {
  afterEach(() => { _resetSpawnImpl(); });

  it('infers backend from sandboxId prefix and sends no per-phase start config', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, undefined, testOptions());
    assert.strictEqual(fake.captured.envelope?.phase, 'start');
    assert.strictEqual(fake.captured.envelope?.sandboxId, 'iso:reg-abc:prov-1');
    const wire = JSON.parse(JSON.stringify(fake.captured.envelope));
    assert.strictEqual(
      wire.experimental,
      undefined,
      'start takes no per-phase config, so no experimental block should be emitted',
    );
  });

  it('relays the correlationVector from options onto the start envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, undefined, testOptions({ correlationVector: 'BASEbaseBASEbaseBASEba.7' }));
    assert.strictEqual(fake.captured.envelope?.correlationVector, 'BASEbaseBASEbaseBASEba.7');
  });
});

describe('stopSandbox', { skip: platformSkip }, () => {
  afterEach(() => { _resetSpawnImpl(); });

  it('builds a minimal stop envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await stopSandbox(id, undefined, testOptions());
    assert.strictEqual(fake.captured.envelope?.phase, 'stop');
    assert.strictEqual(fake.captured.envelope?.sandboxId, 'iso:abc');
    assert.strictEqual(fake.captured.envelope?.experimental, undefined);
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

  it('relays the correlationVector from options onto the stop envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await stopSandbox(id, undefined, testOptions({ correlationVector: 'BASEbaseBASEbaseBASEba.9' }));
    assert.strictEqual(fake.captured.envelope?.correlationVector, 'BASEbaseBASEbaseBASEba.9');
  });
});

describe('deprovisionSandbox', { skip: platformSkip }, () => {
  afterEach(() => { _resetSpawnImpl(); });

  it('builds a minimal deprovision envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id, undefined, testOptions());
    assert.strictEqual(fake.captured.envelope?.phase, 'deprovision');
    assert.strictEqual(fake.captured.envelope?.sandboxId, 'iso:abc');
  });

  it('relays the correlationVector from options onto the deprovision envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id, undefined, testOptions({ correlationVector: 'BASEbaseBASEbaseBASEba.11' }));
    assert.strictEqual(fake.captured.envelope?.correlationVector, 'BASEbaseBASEbaseBASEba.11');
  });
});

describe('execInSandboxAsync', { skip: platformSkip }, () => {
  afterEach(() => { _resetSpawnImpl(); });

  it('returns ExecResult on successful script run', async () => {
    const fake = fakeSpawn({ stdout: 'hello\n', stderr: '', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const result = await execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hello' } },
      testOptions(),
    );
    assert.deepStrictEqual(result, { stdout: 'hello\n', stderr: '', exitCode: 0 });
  });

  it('returns ExecResult on script exit != 0 when stdout is plain script output (not an error envelope)', async () => {
    const fake = fakeSpawn({ stdout: 'oops\n', stderr: 'err\n', exitCode: 7 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    const result = await execInSandboxAsync(
      id,
      { process: { commandLine: 'fail' } },
      testOptions(),
    );
    assert.deepStrictEqual(result, { stdout: 'oops\n', stderr: 'err\n', exitCode: 7 });
  });

  it('throws the typed MxcError on dispatch failure (exit != 0 and stdout is a complete error envelope)', async () => {
    const fake = fakeSpawn({
      stdout: '{"error":{"code":"stale_id","message":"id expired"}}',
      stderr: '',
      exitCode: 1,
    });
    _setSpawnImpl(fake.spawn);
    const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
    await assert.rejects(
      () => execInSandboxAsync(id, { process: { commandLine: 'echo' } }, testOptions()),
      (err: unknown) => err instanceof MxcError && err.code === 'stale_id',
    );
  });

  it('closes the child stdin so a stdin-reading command sees EOF instead of hanging', async () => {
    // Regression for the buffered-exec hang: the Rust state-aware path waits
    // for stdin EOF before closing guest stdin, so spawnAndCollect must end()
    // the child's write end when it supplies no input.
    const fake = fakeSpawn({ stdout: '', stderr: '', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await execInSandboxAsync(id, { process: { commandLine: 'cat' } }, testOptions());
    assert.strictEqual(
      fake.stdinEnded(),
      true,
      'buffered exec must close the child stdin (end()) so stdin reads see EOF',
    );
  });

  it('relays the correlationVector from options onto the exec envelope', async () => {
    const fake = fakeSpawn({ stdout: 'hi\n', stderr: '', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await execInSandboxAsync(
      id,
      { process: { commandLine: 'echo hi' } },
      testOptions({ correlationVector: 'BASEbaseBASEbaseBASEba.13' }),
    );
    assert.strictEqual(fake.captured.envelope?.correlationVector, 'BASEbaseBASEbaseBASEba.13');
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
    afterEach(() => { _resetSpawnImpl(); });

    it('provisionSandbox builds a windows_sandbox envelope and routes back via the wsb: prefix', async () => {
      const fake = fakeSpawn({ stdout: '{"result":{"sandboxId":"wsb:prov-1"}}', exitCode: 0 });
      _setSpawnImpl(fake.spawn);
      const result = await provisionSandbox(
        'windows_sandbox',
        { filesystem: { readonlyPaths: ['C:\\inputs'] } },
        testOptions(),
      );
      assert.strictEqual(result.sandboxId, 'wsb:prov-1');
      assert.strictEqual(fake.captured.envelope?.phase, 'provision');
      assert.strictEqual(fake.captured.envelope?.containment, 'windows_sandbox');
      assert.deepStrictEqual(fake.captured.envelope?.filesystem, { readonlyPaths: ['C:\\inputs'] });
      assert.strictEqual(fake.captured.envelope?.experimental, undefined);
    });

    it('startSandbox infers windows_sandbox from the wsb: prefix', async () => {
      const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
      _setSpawnImpl(fake.spawn);
      const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
      await startSandbox(id, undefined, testOptions());
      assert.strictEqual(fake.captured.envelope?.phase, 'start');
      assert.strictEqual(fake.captured.envelope?.sandboxId, 'wsb:prov-1');
      assert.strictEqual(fake.captured.envelope?.experimental, undefined);
    });

    it('execInSandboxAsync places process at top-level for a wsb: id', async () => {
      const fake = fakeSpawn({ stdout: 'hello-from-wsb\n', stderr: '', exitCode: 0 });
      _setSpawnImpl(fake.spawn);
      const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
      const result = await execInSandboxAsync(
        id,
        { process: { commandLine: 'echo hello-from-wsb' } },
        testOptions(),
      );
      assert.deepStrictEqual(result, { stdout: 'hello-from-wsb\n', stderr: '', exitCode: 0 });
      assert.deepStrictEqual(fake.captured.envelope?.process, { commandLine: 'echo hello-from-wsb' });
    });

    it('stopSandbox and deprovisionSandbox build minimal envelopes for a wsb: id', async () => {
      for (const phase of ['stop', 'deprovision'] as const) {
        const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
        _setSpawnImpl(fake.spawn);
        const id = 'wsb:prov-1' as SandboxId<'windows_sandbox'>;
        const call = phase === 'stop' ? stopSandbox : deprovisionSandbox;
        await call(id, undefined, testOptions());
        assert.strictEqual(fake.captured.envelope?.phase, phase);
        assert.strictEqual(fake.captured.envelope?.sandboxId, 'wsb:prov-1');
        _resetSpawnImpl();
      }
    });
  });
});
