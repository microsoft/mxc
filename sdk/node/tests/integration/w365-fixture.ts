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
import koffi from 'koffi';

const pool = '11111111-1111-1111-1111-111111111111';
const session = '22222222-2222-2222-2222-222222222222';
const id = `w365:${pool}:${session}`;
const provision = JSON.stringify({
  version: '1.1.0-alpha', phase: 'provision', containment: 'w365_agents',
  w365Agents: { provision: { poolId: pool } },
});
const request = (phase: string) => JSON.stringify({
  version: '1.1.0-alpha', phase, sandboxId: id,
  ...(phase === 'exec' ? { process: { commandLine: 'echo must-not-run' } } : {}),
});

// Run explicitly with a separately built test-support library, never the shipping DLL.
it('W365 Dev JSON checks out and releases, retaining Provision cleanup IDs in messages',
  { timeout: 30000 }, async () => {
    assert.ok(process.env.MXC_FFI_DIR, 'MXC_FFI_DIR must select a test-support library');
    const directory = mkdtempSync(join(tmpdir(), 'mxc-w365-'));
    const certificate = join(directory, 'certificate.pem');
    const key = join(directory, 'key.pem');
    const keys = ['W365A_CONTROLPLANE_URL', 'W365A_CP_TOKEN',
      'MXC_W365_TEST_CA', 'MXC_W365_TEST_PORT'] as const;
    const environment = keys.map(name => [name, process.env[name]] as const);
    const stackSize = koffi.config().async_stack_size;
    const library = koffi.load(process.platform === 'win32' ? 'kernel32.dll'
      : process.platform === 'darwin' ? 'libSystem.B.dylib' : 'libc.so.6');
    const replies: { status: number; body: string }[] = [];
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
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      process.env.W365A_CONTROLPLANE_URL = 'localhost';
      process.env.W365A_CP_TOKEN = 'fixture-token';
      process.env.MXC_W365_TEST_CA = certificate;
      process.env.MXC_W365_TEST_PORT = String(address.port);
      await assert.rejects(provisionContainerJson(provision),
        (error: unknown) => error instanceof MxcError && error.code === 'backend_unavailable');
      await validateProvisionJson(provision, options);
      await assert.rejects(startContainerJson(request('start'), options),
        (error: unknown) => error instanceof MxcError && error.code === 'unsupported_phase');
      for (const call of [
        () => runInContainerJson(request('exec'), options),
        () => spawnInContainerJson(request('exec'), options),
      ]) {
        await assert.rejects(call, (error: unknown) => {
          assert.ok(error instanceof MxcError);
          assert.equal(error.code, supportsStreaming ? 'unsupported_phase' : 'backend_unavailable');
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
      assert.equal(requests[0].url, `/api/pools/${pool}/sessions?api-version=2.0`);
      assert.equal(requests[0].userType, undefined);
      assert.equal(requests[5].method, 'DELETE');
      assert.equal(requests[5].url, `/api/sessions/${session}?api-version=2.0`);
      assert.equal(requests[5].authorization, 'Bearer renewed-fixture-token');
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
