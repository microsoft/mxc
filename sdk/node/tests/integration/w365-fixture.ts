// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import type { Readable } from 'node:stream';
import koffi from 'koffi';

const pool = '11111111-1111-1111-1111-111111111111';
const session = '22222222-2222-2222-2222-222222222222';
const id = `w365:${pool}:${session}`;
const provision = JSON.stringify({
  version: '1.1.0-alpha', phase: 'provision', containment: 'w365_agents',
  w365Agents: { provision: { poolId: pool } },
});
const request = (phase: string, sandboxId = id) => JSON.stringify({
  version: '1.1.0-alpha', phase, sandboxId,
  ...(phase === 'exec' ? { process: { commandLine: 'echo must-not-run' } } : {}),
});

// Run explicitly with a separately built test-support library, never the shipping DLL.
it('W365 Dev JSON preserves lifecycle recovery, readiness and captured/live execution',
  { timeout: 90000 }, async () => {
    assert.ok(process.env.MXC_FFI_DIR, 'MXC_FFI_DIR must select a test-support library');
    const directory = mkdtempSync(join(tmpdir(), 'mxc-w365-'));
    const certificate = join(directory, 'certificate.pem');
    const key = join(directory, 'key.pem');
    const keys = ['W365A_CONTROLPLANE_URL', 'W365A_CP_TOKEN',
      'W365A_DP_SUFFIX', 'W365A_DP_TOKEN',
      'MXC_W365_TEST_CA', 'MXC_W365_TEST_PORT'] as const;
    const environment = keys.map(name => [name, process.env[name]] as const);
    const stackSize = koffi.config().async_stack_size;
    const library = koffi.load(process.platform === 'win32' ? 'kernel32.dll'
      : process.platform === 'darwin' ? 'libSystem.B.dylib' : 'libc.so.6');
    const replies: { status: number; body: string }[] = [];
    type ExecPeer = { start: Record<string, unknown>;
      readFrame: () => Promise<{ kind: number; payload: Buffer }>;
      send: (kind: number, payload: Buffer) => void };
    const executions: ((peer: ExecPeer) => Promise<void>)[] = [];
    const fixtureErrors: unknown[] = [];
    const requests: { method: string | undefined; url: string | undefined;
      authorization: string | undefined; userType: string | string[] | undefined;
      clientRequestId: string | string[] | undefined }[] = [];
    let server: ReturnType<typeof createServer> | undefined;
    const reply = (status: number, body: object | undefined = undefined) =>
      replies.push({ status, body: body === undefined ? '' : JSON.stringify(body) });
    const options = { experimental: true };
    try {
      const getProcessId = library.func(process.platform === 'win32'
        ? 'uint32_t GetCurrentProcessId()' : 'int getpid()');
      const pid = await new Promise<number>((resolve, reject) =>
        getProcessId.async((error: Error | null, pid: number) => {
          if (error) reject(error);
          else resolve(pid);
        }));
      assert.equal(pid, process.pid);
      const { MxcError } = await import('@microsoft/mxc-sdk/v1');
      const {
        provisionContainerJson, startContainerJson, runInContainerJson,
        spawnInContainerJson, stopContainerJson, deprovisionContainerJson,
        validateProvisionJson,
      } = await import('@microsoft/mxc-sdk/v1/dev');
      assert.equal(koffi.config().async_stack_size, stackSize,
        'the SDK must not change the application Koffi configuration');
      const nativeStdio = await import(new URL(
        '../bindings/native-stdio.js', import.meta.resolve('@microsoft/mxc-sdk/v1'),
      ).href) as typeof import('./node_modules/@microsoft/mxc-sdk/dist/bindings/native-stdio.js');
      const supportsStreaming = nativeStdio.supportsNativeStdio(
        process.platform, process.versions.node);
      execFileSync(process.env.MXC_W365_TEST_OPENSSL ?? 'openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-addext', 'extendedKeyUsage=serverAuth',
        '-addext', 'basicConstraints=critical,CA:FALSE',
        '-keyout', key, '-out', certificate,
      ], { stdio: 'pipe' });
      server = createServer({ cert: readFileSync(certificate), key: readFileSync(key) },
        (incoming, response) => {
          requests.push({
            method: incoming.method, url: incoming.url,
            authorization: incoming.headers.authorization,
            userType: incoming.headers['user-type'],
            clientRequestId: incoming.headers['x-ms-client-request-id'],
          });
          const next = replies.shift();
          assert.ok(next, 'unexpected W365 service request');
          response.writeHead(next.status, {
            'Content-Length': Buffer.byteLength(next.body), Connection: 'close',
            'x-ms-request-id': 'fixture-request',
          });
          response.end(next.body);
        });
      server.on('upgrade', (incoming, socket, head) => {
        const execute = async () => {
          requests.push({
            method: incoming.method, url: incoming.url,
            authorization: incoming.headers.authorization,
            userType: incoming.headers['user-type'],
            clientRequestId: incoming.headers['x-ms-client-request-id'],
          });
          assert.equal(incoming.headers.upgrade, 'exec');
          assert.equal(incoming.url, `/computers/${session}/microsoft.exec?api-version=1.0`);
          const script = executions.shift();
          assert.ok(script, 'unexpected Exec request');
          let pending: Buffer = head;
          socket.on('data', (chunk: Buffer) => { pending = Buffer.concat([pending, chunk]); });
          const peer: ExecPeer = {
            start: {},
            async readFrame() {
              while (pending.length < 5
                || pending.length < 5 + pending.readUInt32BE(1)) {
                await once(socket, 'data');
              }
              const length = pending.readUInt32BE(1);
              assert.ok(length <= 65536);
              const frame = { kind: pending[0], payload: pending.subarray(5, 5 + length) };
              pending = pending.subarray(5 + length);
              return frame;
            },
            send(kind, payload) {
              const header = Buffer.alloc(5);
              header[0] = kind;
              header.writeUInt32BE(payload.length, 1);
              socket.write(Buffer.concat([header, payload]));
            },
          };
          socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec\r\n\r\n');
          const start = await peer.readFrame();
          assert.equal(start.kind, 1);
          const payload = JSON.parse(start.payload.toString());
          assert.equal(payload.shell, 'raw');
          assert.equal(payload.mode, 'pipe');
          peer.start = payload;
          peer.send(0x11, Buffer.from('{"pid":123}'));
          await script(peer);
          socket.end();
        };
        void execute().catch(error => {
          fixtureErrors.push(error);
          socket.destroy();
        });
      });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      process.env.W365A_CONTROLPLANE_URL = 'localhost';
      process.env.W365A_CP_TOKEN = 'fixture-token';
      process.env.W365A_DP_SUFFIX = 'localhost';
      process.env.W365A_DP_TOKEN = 'synthetic-data-plane-token';
      process.env.MXC_W365_TEST_CA = certificate;
      process.env.MXC_W365_TEST_PORT = String(address.port);
      await assert.rejects(provisionContainerJson(provision),
        (error: unknown) => error instanceof MxcError && error.code === 'backend_unavailable');
      await validateProvisionJson(provision, options);
      await assert.rejects(startContainerJson(request('start', 'w365:invalid'), options),
        (error: unknown) => error instanceof MxcError && error.code === 'malformed_id');
      for (const call of [
        () => runInContainerJson(request('exec', 'w365:invalid'), options),
        () => spawnInContainerJson(request('exec', 'w365:invalid'), options),
      ]) {
        await assert.rejects(call, (error: unknown) => {
          assert.ok(error instanceof MxcError);
          assert.equal(error.code, supportsStreaming ? 'malformed_id' : 'backend_unavailable');
          if (!supportsStreaming) {
            const platform = nativeStdio.nativeStdioPlatformName(process.platform);
            const requirement = nativeStdio.nativeStdioNodeRequirement(process.platform);
            assert.equal(error.message,
              `native stdio on ${platform} requires Node.js ${requirement}; ` +
              `current version is ${process.versions.node}`);
          }
          return true;
        });
      }
      assert.equal(requests.length, 0, 'validation must not call the service');

      reply(200, { sessionId: session, status: 'Succeeded' });
      const value = JSON.parse(await provisionContainerJson(provision, options));
      assert.equal(value.result.sandboxId, id);
      for (const phase of ['stop', 'deprovision']) {
        reply(204);
        const call = phase === 'stop' ? stopContainerJson : deprovisionContainerJson;
        const value = JSON.parse(await call(request(phase), options));
        assert.equal(value.result.metadata.releaseRequested, true);
      }
      for (const knownId of [true, false]) {
        reply(500, {
          sessionId: knownId ? session : 'invalid',
          connectivityUrl: 'https://example.invalid/?ticket=must-not-surface',
        });
        await assert.rejects(provisionContainerJson(provision, options), (error: unknown) => {
          assert.ok(error instanceof MxcError);
          assert.equal(error.code, 'backend_error');
          assert.match(error.message, /provision_timeout/);
          const clientRequestId = requests.at(-1)?.clientRequestId;
          assert.equal(typeof clientRequestId, 'string');
          assert.ok(error.message.includes(`clientRequestId=${clientRequestId}`));
          assert.ok(error.message.includes('requestId=fixture-request'));
          assert.ok(error.message.includes('possiblySucceeded=true'));
          assert.equal(error.message.includes(id), knownId);
          assert.equal(error.message.includes('sandboxId'), knownId);
          assert.ok(!error.message.includes('must-not-surface'));
          assert.ok(!error.message.includes('fixture-token'));
          return true;
        });
      }
      process.env.W365A_CP_TOKEN = 'renewed-fixture-token';
      reply(204);
      await deprovisionContainerJson(request('deprovision'), options);
      assert.equal(requests.length, 6, 'checkout must not replay or release automatically');
      assert.equal(replies.length, 0);
      assert.equal(requests[0].method, 'POST');
      assert.equal(requests[0].url, `/api/pools/${pool}/sessions?api-version=3.0`);
      assert.equal(requests[0].userType, undefined);
      assert.equal(requests[5].method, 'DELETE');
      assert.equal(requests[5].url, `/api/sessions/${session}?api-version=2.0`);
      assert.equal(requests[5].authorization, 'Bearer renewed-fixture-token');

      reply(200, { status: 'Live' });
      reply(200, { status: 'Ready' });
      const ready = JSON.parse(await startContainerJson(request('start'), options));
      assert.equal(ready.result.metadata.status, 'Ready');
      if (supportsStreaming) {
        const stdin = async (peer: ExecPeer) => {
          const chunks: Buffer[] = [];
          for (;;) {
            const frame = await peer.readFrame();
            if (frame.kind === 3) {
              assert.equal(frame.payload.length, 0);
              return Buffer.concat(chunks);
            }
            assert.equal(frame.kind, 2);
            chunks.push(frame.payload);
          }
        };
        const collect = async (stream: Readable) => {
          const chunks: Buffer[] = [];
          for await (const chunk of stream) chunks.push(Buffer.from(chunk));
          return Buffer.concat(chunks);
        };
        executions.push(async peer => {
          assert.equal((await stdin(peer)).length, 0, 'capture must close unused stdin');
          peer.send(0x12, Buffer.from('captured-output'));
          peer.send(0x13, Buffer.from('captured-error'));
          peer.send(0x14, Buffer.from('{"code":-1}'));
        });
        const captured = await runInContainerJson(request('exec'), options);
        assert.equal(captured.exitCode, -1);
        assert.equal(captured.stdout, 'captured-output');
        assert.equal(captured.stderr, 'captured-error');

        let release!: () => void;
        let exitSent = false;
        const gate = new Promise<void>(resolve => { release = resolve; });
        executions.push(async peer => {
          assert.deepEqual(await stdin(peer), Buffer.from([0, 255, 65]));
          await gate;
          peer.send(0x12, Buffer.from([255, 0, 66]));
          peer.send(0x13, Buffer.from([128, 0, 67]));
          peer.send(0x14, Buffer.from('{"code":7}'));
          exitSent = true;
        });
        const process = await spawnInContainerJson(request('exec'), options);
        try {
          assert.equal(exitSent, false, 'spawn must return before Exit');
          process.standardInput!.end(Buffer.from([0, 255, 65]));
          const stdout = collect(process.standardOutput!);
          const stderr = collect(process.standardError!);
          release();
          assert.equal((await process.wait()).exitCode, 7);
          assert.deepEqual(await stdout, Buffer.from([255, 0, 66]));
          assert.deepEqual(await stderr, Buffer.from([128, 0, 67]));
        } finally {
          process.dispose();
        }
        executions.push(async peer => {
          assert.equal((await stdin(peer)).length, 0);
          peer.send(0x12, Buffer.from('partial'));
          peer.send(0x15, Buffer.from('{"code":"failed","message":"fixture failure"}'));
        });
        await assert.rejects(runInContainerJson(request('exec'), options), (error: unknown) => {
          assert.ok(error instanceof MxcError);
          assert.equal(error.code, 'backend_error');
          assert.ok(error.message.length > 0);
          return true;
        });

        const timedExec = JSON.stringify({
          version: '1.1.0-alpha', phase: 'exec', sandboxId: id,
          process: { commandLine: 'cmd.exe /c fixture', timeout: 1000 },
        });
        for (const live of [false, true]) {
          executions.push(async peer => {
            assert.equal(peer.start.timeoutMs, 1000);
            assert.equal((await stdin(peer)).length, 0);
            // The service drains output after enforcing the guest runtime limit.
            await new Promise(resolve => setTimeout(resolve, 1200));
            peer.send(0x12, Buffer.from('drained-output'));
            peer.send(0x13, Buffer.from('drained-error'));
            peer.send(0x14, Buffer.from('{"code":124}'));
          });
          if (live) {
            const proc = await spawnInContainerJson(timedExec, options);
            try {
              proc.standardInput!.end();
              const stdout = collect(proc.standardOutput!);
              const stderr = collect(proc.standardError!);
              const outcome = await proc.wait();
              assert.equal(outcome.exitCode, 124);
              assert.equal(outcome.timedOut, false);
              assert.equal((await stdout).toString(), 'drained-output');
              assert.equal((await stderr).toString(), 'drained-error');
            } finally {
              proc.dispose();
            }
          } else {
            const result = await runInContainerJson(timedExec, options);
            assert.equal(result.exitCode, 124);
            assert.equal(result.timedOut, false);
            assert.equal(result.stdout, 'drained-output');
            assert.equal(result.stderr, 'drained-error');
          }
        }

        let finish!: () => void;
        const stalled = new Promise<void>(resolve => { finish = resolve; });
        executions.push(async peer => {
          assert.equal(peer.start.timeoutMs, 1000);
          assert.equal((await stdin(peer)).length, 0);
          await stalled;
        });
        const started = performance.now();
        try {
          await assert.rejects(runInContainerJson(timedExec, options), (error: unknown) => {
            assert.ok(error instanceof MxcError);
            assert.equal(error.code, 'backend_error');
            return true;
          });
          const elapsed = performance.now() - started;
          assert.ok(elapsed >= 30000 && elapsed < 45000,
            `native runtime/drain deadline took ${elapsed} ms`);
        } finally {
          finish();
        }
        assert.equal(requests.length, 14);
      } else {
        assert.equal(requests.length, 8);
      }
      assert.deepEqual(fixtureErrors, []);
      assert.equal(executions.length, 0);
      for (const sent of requests.slice(6)) {
        assert.equal(sent.method, 'GET');
        assert.ok(sent.url?.startsWith(`/computers/${session}/`));
      }
    } finally {
      library.unload();
      if (server?.listening) {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
          server!.close(error => error ? reject(error) : resolve()));
      }
      for (const [name, value] of environment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      rmSync(directory, { recursive: true, force: true });
    }
  });
