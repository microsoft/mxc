// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// SDK end-to-end tests — these tests spawn real containers through mxc_ffi.
// They require the appropriate runtime to be installed and configured.
//
// WSLC tests require:
//   - Windows 11 with WSL2 enabled
//   - WSLC SDK runtime installed
//   - mxc_ffi built with WSLC support
//   - wslcsdk.dll available to the native library
//   - network access to Docker Hub, or alpine:latest and python:3.12-alpine
//     already cached
//
// Run via: npm test (from integration directory)

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import os from 'os';
import { sdk } from './test-helpers.js';

// WSLC tests require a Windows machine with WSL2 and WSLC SDK installed.
// Opt-in via MXC_ENABLE_WSLC_TESTS=1 since most CI agents lack the runtime.
const isWslcAvailable = os.platform() === 'win32' && process.env.MXC_ENABLE_WSLC_TESTS === '1';

// Probe a small range of host ports and return the first one we can
// successfully bind to. Avoids both the fixed-port collision risk (any
// other process on the dev box / runner may already own a hard-coded
// port) AND the TOCTOU race that `listen(0) → close → reuse` would
// introduce. Throws if every candidate in the range is busy.
async function pickAvailableHostPort(start = 40000, end = 40099): Promise<number> {
  for (let port = start; port <= end; port++) {
    const ok = await new Promise<boolean>((resolve) => {
      const srv = net.createServer();
      srv.once('error', () => resolve(false));
      srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
    });
    if (ok) return port;
  }
  throw new Error(`pickAvailableHostPort: no free port in [${start}, ${end}]`);
}

describe('WSLC SDK E2E — V1 request APIs', {
  skip: !isWslcAvailable ? 'WSLC tests require MXC_ENABLE_WSLC_TESTS=1 on Windows with WSL2 and WSLC SDK' : undefined,
}, () => {

  it('should run with all WSLC-specific fields set', { timeout: 120_000 }, async () => {
    // Create temp directory for the volume mount.
    // Use short paths under os.tmpdir() — WSLC SDK can fail with very long paths.
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-e2e-'));
    const mountDir = path.join(testDir, 'mount');
    fs.mkdirSync(mountDir);

    try {
      const policy = {
        network: {
          egress: { default: 'allow' as const },
          ingress: { default: 'allow' as const, hostLoopback: 'allow' as const },
        },
        filesystem: { readwritePaths: [mountDir] },
      };
      const result = await sdk.runAsync({
        ...policy,
        command: [
          "python3 -c \"import sys; print(f'Python {sys.version_info.major}.{sys.version_info.minor}')\"",
          'nproc',
          'cat /proc/meminfo | grep MemTotal',
          "echo 'All fields work'",
        ].join(' && '),
        containment: {
          type: 'wslc',
          config: {
            image: 'python:3.12-alpine',
            cpuCount: 2,
            memoryMb: 1024,
          },
        },
      });
      // Intentionally omit `storagePath` so this test reuses the default
      // image store, where `python:3.12-alpine` is already cached. Pointing at
      // a fresh temp directory would make the run pull the image again.

      assert.strictEqual(result.exitCode, 0, `exit=${result.exitCode}\nstdout=${result.stdout}\nstderr=${result.stderr}`);
      assert.ok(result.stdout.includes('Python 3.12'), `Python 3.12 not found in stdout=${result.stdout}`);
      assert.ok(result.stdout.includes('All fields work'), `'All fields work' not found in stdout=${result.stdout}`);
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should forward a TCP port from host to container', { timeout: 120_000 }, async () => {
    const http = await import('node:http');
    // Pick an available host port to avoid collisions on busy dev/CI hosts.
    // The container port can stay fixed because the container's network
    // namespace is isolated from the host.
    const HOST_PORT = await pickAvailableHostPort();
    const CONTAINER_PORT = 8080;

    const policy = {
      network: {
        egress: { default: 'allow' as const },
        ingress: { default: 'allow' as const, hostLoopback: 'allow' as const },
      },
      filesystem: {},
    };
    // The container runs `/bin/sh -c "<script_code>"`. We base64-encode the
    // Python source and run it via a single-argv `python3 -c "..."` call to
    // avoid any embedded-newline / shell-pipeline ambiguity through the WSLC
    // FFI. `handle_request()` serves exactly one request then returns, so
    // the container exits cleanly once the host probe completes — no
    // SIGTERM/SIGKILL dance is needed.
    //
    // We deliberately do NOT wait for an in-container "ready" marker before
    // probing: WSLC's stdout pump may delay delivery of bytes from a
    // long-running process. The host probe retries on ECONNREFUSED, so the
    // retry loop naturally bridges the bind-then-accept window.
    const pythonScript = `import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'PORT_MAPPING_TCP_OK')
    def log_message(self, *a, **k):
        pass
srv = socketserver.TCPServer(('0.0.0.0', ${CONTAINER_PORT}), H)
srv.handle_request()
`;
    const scriptB64 = Buffer.from(pythonScript, 'utf8').toString('base64');
    const child = sdk.spawn({
      ...policy,
      command: `python3 -c "import base64; exec(base64.b64decode('${scriptB64}'))"`,
      containment: {
        type: 'wslc',
        config: {
          image: 'python:3.12-alpine',
          portMappings: [
            { windowsPort: HOST_PORT, containerPort: CONTAINER_PORT, protocol: 'tcp' },
          ],
        },
      },
    });
    const standardOutput = child.standardOutput;
    const standardError = child.standardError;
    assert.ok(standardOutput, 'stdout should be available');
    assert.ok(standardError, 'stderr should be available');
    let stdout = '';
    let stderr = '';
    standardOutput.on('data', (d: Buffer | string) => {
      stdout += Buffer.isBuffer(d) ? d.toString() : d;
    });
    standardError.on('data', (d: Buffer | string) => {
      stderr += Buffer.isBuffer(d) ? d.toString() : d;
    });
    let completion: { exitCode: number; timedOut: boolean } | undefined;
    const closed = child.waitAsync().then((result) => {
      completion = result;
      return result;
    });
    void closed.catch(() => {});

    let body = '';
    let lastErr: Error | undefined;
    try {
      // Probe from the Windows host with poll-retry. Retries cover both the
      // container-start window and the NAT-rule settle window. Each attempt
      // bails if the child has already exited (avoids 60s of pointless retry
      // when the container crashed).
      const probeDeadline = Date.now() + 60_000;
      while (Date.now() < probeDeadline) {
        if (completion !== undefined) {
          throw new Error(`Container exited before probe could succeed (code=${completion.exitCode}). stdout=${stdout} stderr=${stderr}`);
        }
        try {
          body = await new Promise<string>((resolve, reject) => {
            const req = http.get({ host: '127.0.0.1', port: HOST_PORT, timeout: 2000 }, (res) => {
              const chunks: Buffer[] = [];
              res.on('data', (c) => chunks.push(c));
              res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(new Error('http.get timeout')); });
          });
          break;
        } catch (e) {
          lastErr = e as Error;
          await new Promise((r) => setTimeout(r, 500));
        }
      }
      assert.strictEqual(body, 'PORT_MAPPING_TCP_OK', `host probe failed; lastErr=${lastErr?.message} stdout=${stdout} stderr=${stderr}`);
    } finally {
      // After one served request, the Python server returns from handle_request
      // and the container exits naturally. Wait up to 20s for clean exit, then
      // force-kill so a stuck WSLC teardown can never hang the whole suite.
      const cleanExit = await Promise.race([
        closed.then(() => 'closed' as const),
        new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 20_000)),
      ]);
      if (cleanExit === 'timeout') {
        child.kill();
        await Promise.race([
          closed,
          new Promise((r) => setTimeout(r, 5_000)),
        ]);
      }
    }
  });

  it('should reject UDP port mapping before native spawn', () => {
    // The WSLC SDK declares WSLC_PORT_PROTOCOL_UDP in its header but its
    // runtime returns E_NOTIMPL (0x80004001) when UDP is actually requested.
    // The parser rejects UDP up front so SDK consumers get a clear error at
    // spawn time rather than a cryptic HRESULT at container-create time. The
    // SDK type narrows `protocol` to `'tcp'`, so a cast is required here to
    // exercise the parser path that rejects an out-of-type value at runtime.
    const policy = {
      network: {
        egress: { default: 'allow' as const },
        ingress: { default: 'allow' as const, hostLoopback: 'allow' as const },
      },
      filesystem: {},
    };
    const request = {
      ...policy,
      command: 'echo unreachable',
      containment: {
        type: 'wslc' as const,
        config: {
          image: 'python:3.12-alpine',
          portMappings: [
            {
              windowsPort: 39000,
              containerPort: 9000,
              protocol: 'udp' as unknown as 'tcp',
            },
          ],
        },
      },
    };
    assert.throws(
      () => sdk.spawn(request),
      /WSLC port mappings support only protocol 'tcp'/,
    );
  });
});
