// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'events';
import { Readable } from 'stream';
import {
  _resetSpawnImpl,
  _setSpawnImpl,
  buildStateAwareEnvelope,
  deprovisionSandbox,
  execInSandboxAsync,
  parseNonExecResponse,
  provisionSandbox,
  startSandbox,
  stopSandbox,
} from '../../src/state-aware.js';
import {
  MxcAlreadyStartedError,
  MxcBackendError,
  MxcBackendUnavailableError,
  MxcMalformedIdError,
  MxcMalformedRequestError,
  MxcNotProvisionedError,
  MxcNotStartedError,
  MxcPolicyValidationError,
  MxcStaleIdError,
  MxcUnsupportedContainmentError,
  MxcUnsupportedPhaseError,
} from '../../src/errors.js';
import { SandboxId } from '../../src/state-aware-types.js';
import { SandboxSpawnOptions } from '../../src/sandbox.js';

// Tests stub child_process.spawn but the binary-resolution path runs first
// and demands an existing executable on disk. Pointing it at the Node
// binary is the simplest always-on-disk choice; the fake spawn ignores the
// path anyway.
function testOptions(extra?: Partial<SandboxSpawnOptions>): SandboxSpawnOptions {
  return { experimental: true, executablePath: process.execPath, ...extra };
}

interface FakeChildOpts {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  error?: Error;
}

function fakeSpawn(opts: FakeChildOpts): {
  spawn: (cmd: string, args: string[], spawnOpts: unknown) => unknown;
  captured: { cmd?: string; args?: string[]; envelope?: Record<string, unknown> };
  killCount: () => number;
} {
  const captured: { cmd?: string; args?: string[]; envelope?: Record<string, unknown> } = {};
  let kills = 0;
  const spawn = (cmd: string, args: string[], _spawnOpts: unknown) => {
    captured.cmd = cmd;
    captured.args = args;
    const idx = args.indexOf('--config-base64');
    if (idx >= 0 && idx + 1 < args.length) {
      const decoded = Buffer.from(args[idx + 1], 'base64').toString('utf-8');
      captured.envelope = JSON.parse(decoded);
    }
    const ee = new EventEmitter();
    const stdout = new Readable({ read() { /* no-op */ } });
    const stderr = new Readable({ read() { /* no-op */ } });
    setImmediate(() => {
      if (opts.error) {
        ee.emit('error', opts.error);
        return;
      }
      stdout.push(opts.stdout ?? '');
      stdout.push(null);
      stderr.push(opts.stderr ?? '');
      stderr.push(null);
      ee.emit('close', opts.exitCode ?? 0);
    });
    return Object.assign(ee, {
      stdout,
      stderr,
      kill: (_sig?: NodeJS.Signals | number) => {
        kills += 1;
        setImmediate(() => ee.emit('close', null));
        return true;
      },
    });
  };
  return { spawn, captured, killCount: () => kills };
}

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

  it('produces a start envelope with backend-specific configurationId nested under experimental', () => {
    const env = buildStateAwareEnvelope({
      phase: 'start',
      backendKey: 'isolation_session',
      sandboxId: 'iso:reg-abc:prov-123',
      config: { configurationId: 'small' },
    });
    assert.strictEqual(env.phase, 'start');
    assert.strictEqual(env.sandboxId, 'iso:reg-abc:prov-123');
    assert.deepStrictEqual(env.experimental, {
      isolation_session: { start: { configurationId: 'small' } },
    });
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
});

describe('parseNonExecResponse', () => {
  it('unwraps result payload', () => {
    const result = parseNonExecResponse<{ sandboxId: string }>('{"result":{"sandboxId":"iso:abc"}}');
    assert.deepStrictEqual(result, { sandboxId: 'iso:abc' });
  });

  it('throws the matching MxcError subclass on each wire error code', () => {
    type MxcCtor = new (message: string, details?: Record<string, unknown>) => Error;
    const cases: Array<[string, MxcCtor]> = [
      ['malformed_request', MxcMalformedRequestError],
      ['unsupported_containment', MxcUnsupportedContainmentError],
      ['unsupported_phase', MxcUnsupportedPhaseError],
      ['backend_unavailable', MxcBackendUnavailableError],
      ['malformed_id', MxcMalformedIdError],
      ['stale_id', MxcStaleIdError],
      ['not_provisioned', MxcNotProvisionedError],
      ['not_started', MxcNotStartedError],
      ['already_started', MxcAlreadyStartedError],
      ['policy_validation', MxcPolicyValidationError],
      ['backend_error', MxcBackendError],
    ];
    for (const [code, cls] of cases) {
      const stdout = JSON.stringify({ error: { code, message: 'boom' } });
      assert.throws(() => parseNonExecResponse(stdout), (err: unknown) => err instanceof cls);
    }
  });

  it('passes details through when wire envelope carries them', () => {
    const stdout = JSON.stringify({
      error: { code: 'backend_error', message: 'boom', details: { hresult: '0x80004005' } },
    });
    assert.throws(() => parseNonExecResponse(stdout), (err: unknown) => {
      return err instanceof MxcBackendError &&
        (err as MxcBackendError).details?.hresult === '0x80004005';
    });
  });

  it('throws a plain Error on unparseable stdout', () => {
    assert.throws(() => parseNonExecResponse('not json'), (err: unknown) => {
      return err instanceof Error && !(err instanceof MxcBackendError);
    });
  });

  it('throws a plain Error on stdout that parses but lacks {result}/{error}', () => {
    assert.throws(() => parseNonExecResponse('{"unexpected":"shape"}'));
  });
});

describe('provisionSandbox', () => {
  let activeFake: ReturnType<typeof fakeSpawn> | null = null;

  beforeEach(() => { activeFake = null; });
  afterEach(() => { _resetSpawnImpl(); activeFake = null; });

  it('builds a provision envelope and unwraps the SandboxId from the response', async () => {
    const fake = fakeSpawn({
      stdout: '{"result":{"sandboxId":"iso:reg-abc:prov-1","metadata":{"agentUserName":"agent\\\\u1"}}}',
      exitCode: 0,
    });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    const result = await provisionSandbox(
      'isolation_session',
      { filesystem: { readwritePaths: ['C:\\workspace'] } },
      testOptions(),
    );
    assert.strictEqual(result.sandboxId, 'iso:reg-abc:prov-1');
    assert.strictEqual(result.metadata?.agentUserName, 'agent\\u1');
    assert.strictEqual(fake.captured.envelope?.phase, 'provision');
    assert.strictEqual(fake.captured.envelope?.containment, 'isolation_session');
    assert.deepStrictEqual(fake.captured.envelope?.filesystem, { readwritePaths: ['C:\\workspace'] });
    assert.ok(fake.captured.args?.includes('--experimental'));
  });

  it('throws MxcBackendUnavailableError when the executor reports backend_unavailable', async () => {
    const fake = fakeSpawn({
      stdout: '{"error":{"code":"backend_unavailable","message":"IsoSessionApp.dll not registered"}}',
      exitCode: 1,
    });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    await assert.rejects(
      () => provisionSandbox('isolation_session', undefined, testOptions()),
      (err: unknown) => err instanceof MxcBackendUnavailableError,
    );
  });

  it('rejects when AbortSignal fires before close', async () => {
    const ac = new AbortController();
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    activeFake = fake;
    _setSpawnImpl(fake.spawn);
    const promise = provisionSandbox(
      'isolation_session',
      undefined,
      testOptions({ signal: ac.signal }),
    );
    ac.abort();
    await assert.rejects(promise);
    assert.ok(activeFake.killCount() >= 1, 'expected child.kill() to fire on abort');
  });
});

describe('startSandbox / stopSandbox / deprovisionSandbox', () => {
  afterEach(() => { _resetSpawnImpl(); });

  it('startSandbox infers backend from sandboxId prefix and nests configurationId under experimental', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:reg-abc:prov-1' as SandboxId<'isolation_session'>;
    await startSandbox(id, { configurationId: 'small' }, testOptions());
    assert.strictEqual(fake.captured.envelope?.phase, 'start');
    assert.strictEqual(fake.captured.envelope?.sandboxId, 'iso:reg-abc:prov-1');
    assert.deepStrictEqual(fake.captured.envelope?.experimental, {
      isolation_session: { start: { configurationId: 'small' } },
    });
  });

  it('stopSandbox builds a minimal stop envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await stopSandbox(id, undefined, testOptions());
    assert.strictEqual(fake.captured.envelope?.phase, 'stop');
    assert.strictEqual(fake.captured.envelope?.sandboxId, 'iso:abc');
    assert.strictEqual(fake.captured.envelope?.experimental, undefined);
  });

  it('deprovisionSandbox builds a minimal deprovision envelope', async () => {
    const fake = fakeSpawn({ stdout: '{"result":{}}', exitCode: 0 });
    _setSpawnImpl(fake.spawn);
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await deprovisionSandbox(id, undefined, testOptions());
    assert.strictEqual(fake.captured.envelope?.phase, 'deprovision');
    assert.strictEqual(fake.captured.envelope?.sandboxId, 'iso:abc');
  });

  it('rejects with MxcMalformedIdError when sandboxId has no recognised prefix', async () => {
    await assert.rejects(
      () => stopSandbox('not-a-real-id' as SandboxId<'isolation_session'>),
      (err: unknown) => err instanceof MxcMalformedIdError,
    );
    await assert.rejects(
      () => stopSandbox('unknownprefix:abc' as SandboxId<'isolation_session'>),
      (err: unknown) => err instanceof MxcMalformedIdError,
    );
  });
});

describe('execInSandboxAsync', () => {
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
    const id = 'iso:abc' as SandboxId<'isolation_session'>;
    await assert.rejects(
      () => execInSandboxAsync(id, { process: { commandLine: 'echo' } }, testOptions()),
      (err: unknown) => err instanceof MxcStaleIdError,
    );
  });
});
