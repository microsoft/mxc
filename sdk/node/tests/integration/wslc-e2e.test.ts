// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// SDK end-to-end tests — these tests spawn real containers via wxc-exec.exe.
// They require the appropriate runtime to be installed and configured.
//
// WSLC tests require:
//   - Windows 11 with WSL2 enabled
//   - WSLC SDK runtime installed
//   - wxc-exec.exe built with --features wslc
//   - wslcsdk.dll in the same directory as wxc-exec.exe
//   - alpine:latest and python:3.12-alpine images pre-pulled
//
// Run via: npm test (from integration directory)

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import os from 'os';
import { ChildProcess } from 'child_process';
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

describe('WSLC SDK E2E — createConfigFromPolicy → customize → spawn', {
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
        version: '0.6.0-alpha',
        network: { allowOutbound: true },
        filesystem: { readwritePaths: [mountDir] },
      };
      const config = sdk.createConfigFromPolicy(policy, 'wslc');
      config.process!.commandLine = [
        "python3 -c \"import sys; print(f'Python {sys.version_info.major}.{sys.version_info.minor}')\"",
        "nproc",
        "cat /proc/meminfo | grep MemTotal",
        "echo 'All fields work'",
      ].join(' && ');
      config.experimental!.wslc!.image = 'python:3.12-alpine';
      config.experimental!.wslc!.cpuCount = 2;
      config.experimental!.wslc!.memoryMb = 1024;
      // Intentionally omit `storagePath` so this test reuses the default
      // image store where `python:3.12-alpine` has already been pre-pulled
      // (the docs require operators to pre-pull). Setting storagePath to a
      // fresh temp directory would point WSLC at an empty image store and
      // fail with "image not found" — MXC does not pull at runtime.

      const { stdout, stderr, exitCode } = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve, reject) => {
        const child = sdk.spawnSandboxFromConfig(config, { experimental: true, debug: true, usePty: false }) as ChildProcess;
        let stdout = '';
        let stderr = '';
        child.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
        child.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });
        child.on('error', (error: Error) => {
          reject(new Error(`Failed to spawn WSLC sandbox process: ${error.message}${stderr ? `\n${stderr}` : ''}`));
        });
        child.on('close', (code: number | null) => {
          resolve({ stdout, stderr, exitCode: code ?? -1 });
        });
      });

      assert.strictEqual(exitCode, 0, `exit=${exitCode}\nstdout=${stdout}\nstderr=${stderr}`);
      assert.ok(stdout.includes('Python 3.12'), `Python 3.12 not found in stdout=${stdout}`);
      assert.ok(stdout.includes('All fields work'), `'All fields work' not found in stdout=${stdout}`);
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
      version: '0.6.0-alpha',
      network: { allowOutbound: true },
      filesystem: {},
    };
    const config = sdk.createConfigFromPolicy(policy, 'wslc');
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
    config.process!.commandLine = `python3 -c "import base64; exec(base64.b64decode('${scriptB64}'))"`;
    config.experimental!.wslc!.image = 'python:3.12-alpine';
    config.experimental!.wslc!.portMappings = [
      { windowsPort: HOST_PORT, containerPort: CONTAINER_PORT, protocol: 'tcp' },
    ];

    const child = sdk.spawnSandboxFromConfig(config, { experimental: true, debug: true, usePty: false }) as ChildProcess;
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr?.on('data', (d: Buffer) => { stderr += d.toString(); });
    const closed = new Promise<number | null>((resolve) => {
      if (child.exitCode !== null) {
        resolve(child.exitCode);
      } else {
        child.on('close', (code: number | null) => resolve(code));
      }
    });

    let body = '';
    let lastErr: Error | undefined;
    try {
      // Probe from the Windows host with poll-retry. Retries cover both the
      // container-start window and the NAT-rule settle window. Each attempt
      // bails if the child has already exited (avoids 60s of pointless retry
      // when the container crashed).
      const probeDeadline = Date.now() + 60_000;
      while (Date.now() < probeDeadline) {
        if (child.exitCode !== null) {
          throw new Error(`Container exited before probe could succeed (code=${child.exitCode}). stdout=${stdout} stderr=${stderr}`);
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
        closed,
        new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 20_000)),
      ]);
      if (cleanExit === 'timeout') {
        child.kill('SIGKILL');
        await Promise.race([
          closed,
          new Promise((r) => setTimeout(r, 5_000)),
        ]);
      }
    }
  });

  it('should reject UDP port mapping with a clear SDK-limitation message', { timeout: 60_000 }, async () => {
    // WSLC SDK 2.8.1 declares WSLC_PORT_PROTOCOL_UDP in its header but its
    // runtime returns E_NOTIMPL (0x80004001) when UDP is actually requested.
    // The parser rejects UDP up front so SDK consumers get a clear error at
    // spawn time rather than a cryptic HRESULT at container-create time. The
    // SDK type narrows `protocol` to `'tcp'`, so a cast is required here to
    // exercise the parser path that rejects an out-of-type value at runtime.
    const policy = {
      version: '0.6.0-alpha',
      network: { allowOutbound: true },
      filesystem: {},
    };
    const config = sdk.createConfigFromPolicy(policy, 'wslc');
    config.process!.commandLine = 'echo unreachable';
    config.experimental!.wslc!.image = 'python:3.12-alpine';
    config.experimental!.wslc!.portMappings = [
      { windowsPort: 39000, containerPort: 9000, protocol: 'udp' as unknown as 'tcp' },
    ];

    const { exitCode, combined } = await new Promise<{ exitCode: number; combined: string }>((resolve, reject) => {
      const child = sdk.spawnSandboxFromConfig(config, { experimental: true, debug: true, usePty: false }) as ChildProcess;
      let combined = '';
      const onData = (d: Buffer) => { combined += d.toString(); };
      child.stdout?.on('data', onData);
      child.stderr?.on('data', onData);
      child.on('error', reject);
      child.on('close', (code: number | null) => resolve({ exitCode: code ?? -1, combined }));
    });

    assert.notStrictEqual(exitCode, 0, `expected non-zero exit when UDP is requested; output=${combined}`);
    assert.ok(
      /udp/i.test(combined) && /not supported|not implemented/i.test(combined),
      `expected SDK-limitation message mentioning UDP; output=${combined}`,
    );
  });
});
