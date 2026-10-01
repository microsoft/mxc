// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { once } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import type { Readable, Writable } from 'node:stream';
import semver from 'semver';
import type { ContainerConfig } from '@microsoft/mxc-sdk';
import {
  debugSpawnOptions,
  getSdkPackageRoot,
  isLinuxBubblewrap,
  isLinuxRoot,
  sandboxSkipReason,
  sdk,
  supportedVersions,
} from './test-helpers.js';

interface NativeSandbox {
  readonly standardInput: Writable | null;
  readonly standardOutput: Readable | null;
  readonly standardError: Readable | null;
  waitAsync(): Promise<{ exitCode: number; timedOut: boolean }>;
  kill(): void;
  dispose(): void;
}

interface RequestModule {
  prepareRequestSpec(
    config: ContainerConfig,
    options?: { experimental?: boolean },
  ): unknown;
}

interface StreamingModule {
  spawnBindingSandboxProcess(request: unknown): NativeSandbox;
}

const platformSupport = sdk.getPlatformSupport();
const schemaVersion = supportedVersions.at(-1)!;
const nativeStreamingNodeRequirement = os.platform() === 'win32'
  ? 'Node.js 24.21.0 or newer within Node.js 24, or Node.js 26.8.0 or newer'
  : 'Node.js 24.0.0 or newer';
const supportsNativeStreamingRuntime = os.platform() === 'win32'
  ? semver.satisfies(process.version, '>=24.21.0 <25 || >=26.8.0')
  : semver.gte(process.version, '24.0.0');

// Everything that stops native streaming from running at all, before any
// particular backend is chosen.
const nativeStreamingSkipReason =
  (!platformSupport.isSupported ? `Platform not supported: ${platformSupport.reason}` : undefined) ??
  (!supportsNativeStreamingRuntime
    ? `Native streaming on ${os.platform()} requires ` +
      nativeStreamingNodeRequirement
    : undefined);

// The cases below build their config from an abstract policy, which resolves
// to Bubblewrap on Linux.
const skipReason =
  sandboxSkipReason ??
  nativeStreamingSkipReason ??
  (os.platform() === 'linux' && !isLinuxBubblewrap
    ? 'Native streaming requires Bubblewrap on Linux'
    : undefined);

// Gated like the other LXC suites rather than on MXC_SKIP_OS_BUILD_DEPENDENT_TESTS:
// the Linux integration lane installs LXC and runs under sudo specifically so
// the LXC backend gets covered there.
const lxcSkipReason =
  nativeStreamingSkipReason ??
  (os.platform() !== 'linux' ? 'LXC streaming is available on Linux only' : undefined) ??
  (!isLinuxRoot
    ? 'LXC creates, starts, and attaches to a system container, which needs root (sudo npm test)'
    : undefined) ??
  (!platformSupport.availableMethods.includes('lxc')
    ? 'LXC is not installed on this host'
    : undefined) ??
  (process.env.MXC_SKIP_LXC_TESTS === '1'
    ? 'Skipped: LXC tests disabled (MXC_SKIP_LXC_TESTS)'
    : undefined);

// A lane provisioned to execute these reports a skip as success, so the gate
// would go green having tested nothing. The same switch the Rust and .NET LXC
// suites read.
const lxcExecutionRequired =
  process.env.MXC_LXC_TESTS_REQUIRE_EXECUTION !== undefined &&
  process.env.MXC_LXC_TESTS_REQUIRE_EXECUTION !== '0';
if (lxcExecutionRequired && lxcSkipReason) {
  throw new Error(
    `MXC_LXC_TESTS_REQUIRE_EXECUTION is set, but the LXC streaming tests would skip: ${lxcSkipReason}`,
  );
}

describe(`Internal native streaming (schema ${schemaVersion})`, { skip: skipReason }, () => {
  it('delivers output before the sandbox exits', { timeout: 30000 }, async () => {
    const packageRoot = getSdkPackageRoot();
    const requestModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'request.js'),
    ).href) as RequestModule;
    const streamingModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'streaming.js'),
    ).href) as StreamingModule;

    const command = os.platform() === 'win32'
      ? 'powershell.exe -NoProfile -Command "Write-Output STREAM_FIRST; ' +
        '[Console]::ReadLine() | Out-Null; Write-Output STREAM_SECOND; ' +
        '[Console]::Error.WriteLine(\'STREAM_ERROR\')"'
      : 'sh -c "printf \'STREAM_FIRST\\n\'; IFS= read -r _; ' +
        'printf \'STREAM_SECOND\\n\'; printf \'STREAM_ERROR\\n\' >&2"';
    const policy = {
      ...(os.platform() === 'win32' ? { ui: { allowWindows: true } } : {}),
    };
    const config = sdk.createConfigFromPolicy(policy);
    config.process!.commandLine = command;
    const request = requestModule.prepareRequestSpec(config, {
      experimental: debugSpawnOptions.experimental,
    });
    const sandbox = streamingModule.spawnBindingSandboxProcess(request);
    const standardInput = sandbox.standardInput;
    const standardOutput = sandbox.standardOutput;
    const standardError = sandbox.standardError;
    assert.ok(standardInput, 'streaming stdin should be available');
    assert.ok(standardOutput, 'streaming stdout should be available');
    assert.ok(standardError, 'streaming stderr should be available');

    let stdout = '';
    let stderr = '';
    let resolveFirstChunk: (() => void) | undefined;
    const firstChunk = new Promise<void>((resolve) => {
      resolveFirstChunk = resolve;
    });
    standardOutput.on('data', (data: Buffer) => {
      stdout += data.toString();
      if (stdout.includes('STREAM_FIRST')) {
        resolveFirstChunk?.();
      }
    });
    standardError.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    let completed = false;
    const wait = sandbox.waitAsync().then((result) => {
      completed = true;
      return result;
    });
    const outputEnded = once(standardOutput, 'end');
    const errorEnded = once(standardError, 'end');
    await firstChunk;
    assert.strictEqual(completed, false, 'first output should arrive before process completion');
    standardInput.end('continue\n');

    const result = await wait;
    await Promise.all([outputEnded, errorEnded]);
    assert.strictEqual(result.exitCode, 0, stderr);
    assert.ok(stdout.includes('STREAM_FIRST'));
    assert.ok(stdout.includes('STREAM_SECOND'));
    assert.ok(stderr.includes('STREAM_ERROR'));
  });

  it('drains untaken native output without blocking completion', { timeout: 30000 }, async () => {
    const packageRoot = getSdkPackageRoot();
    const requestModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'request.js'),
    ).href) as RequestModule;
    const streamingModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'streaming.js'),
    ).href) as StreamingModule;

    const command = os.platform() === 'win32'
      ? 'powershell.exe -NoProfile -Command "$chunk = \'x\' * 8192; ' +
        '1..256 | ForEach-Object { [Console]::Out.Write($chunk); ' +
        '[Console]::Error.Write($chunk) }"'
      : 'sh -c "head -c 2097152 /dev/zero; head -c 2097152 /dev/zero >&2"';
    const policy = {
      ...(os.platform() === 'win32' ? { ui: { allowWindows: true } } : {}),
    };
    const config = sdk.createConfigFromPolicy(policy);
    config.process!.commandLine = command;
    const request = requestModule.prepareRequestSpec(config, {
      experimental: debugSpawnOptions.experimental,
    });
    const sandbox = streamingModule.spawnBindingSandboxProcess(request);

    const result = await sandbox.waitAsync();
    assert.strictEqual(result.exitCode, 0);
  });
});

// LXC is reachable in-process only through an explicit `containment: 'lxc'`;
// the abstract policy the block above uses resolves to Bubblewrap on Linux.
describe(`Internal native streaming over LXC (schema ${schemaVersion})`, {
  skip: lxcSkipReason,
}, () => {
  // Creating and starting a container, and destroying it again afterwards, is
  // far slower than spawning a process.
  const LXC_TEST_TIMEOUT = 300000;

  // Shorter than the framework's own timeout on purpose. node:test abandons a
  // timed-out pending test without unwinding its `finally`, so a stalled stream
  // would leave the root-owned container running; rejecting from inside the
  // `try` keeps the cleanup reachable.
  const LXC_STEP_TIMEOUT = 240000;

  function within<T>(work: Promise<T>, what: string): Promise<T> {
    let timer: NodeJS.Timeout;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${what} did not settle within ${LXC_STEP_TIMEOUT}ms`)),
        LXC_STEP_TIMEOUT,
      );
    });
    return Promise.race([work, deadline]).finally(() => clearTimeout(timer)) as Promise<T>;
  }

  it('delivers output before the sandbox exits', { timeout: LXC_TEST_TIMEOUT }, async () => {
    const packageRoot = getSdkPackageRoot();
    const requestModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'request.js'),
    ).href) as RequestModule;
    const streamingModule = await import(pathToFileURL(
      path.join(packageRoot, 'dist', 'bindings', 'streaming.js'),
    ).href) as StreamingModule;

    // `lxc-attach` runs the command through `/bin/sh -c`, and the container is
    // a BusyBox image.
    const command = "printf 'STREAM_FIRST\\n'; IFS= read -r _; " +
      "printf 'STREAM_SECOND\\n'; printf 'STREAM_ERROR\\n' >&2";
    // A network policy stated in the directional form and permitting nothing:
    // the container starts with no interface, so this does not wait out a DHCP
    // lease it would never use. A policy naming no network at all would default
    // to `enforcementMode: 'capabilities'`, which LXC refuses outright.
    const config = sdk.createConfigFromPolicy(
      {
        network: {
          egress: { default: 'deny' },
          ingress: { default: 'deny', hostLoopback: 'deny' },
        },
      },
      'lxc',
      `mxc-node-stream-${process.pid}`,
    );
    config.process!.commandLine = command;
    const request = requestModule.prepareRequestSpec(config, {
      experimental: debugSpawnOptions.experimental,
    });
    const sandbox = await streamingModule.spawnBindingSandboxProcess(request);
    // The workload blocks on stdin, so a failed assertion below would abandon a
    // running root-owned container whose per-PID name no later run can find.
    let settled = false;
    try {
      const standardInput = sandbox.standardInput;
      const standardOutput = sandbox.standardOutput;
      const standardError = sandbox.standardError;
      assert.ok(standardInput, 'streaming stdin should be available');
      assert.ok(standardOutput, 'streaming stdout should be available');
      assert.ok(standardError, 'streaming stderr should be available');

      let stdout = '';
      let stderr = '';
      let resolveFirstChunk: (() => void) | undefined;
      const firstChunk = new Promise<void>((resolve) => {
        resolveFirstChunk = resolve;
      });
      standardOutput.on('data', (data: Buffer) => {
        stdout += data.toString();
        if (stdout.includes('STREAM_FIRST')) {
          resolveFirstChunk?.();
        }
      });
      standardError.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      let completed = false;
      const wait = sandbox.waitAsync().then((result) => {
        completed = true;
        return result;
      });
      const outputEnded = once(standardOutput, 'end');
      const errorEnded = once(standardError, 'end');
      await within(firstChunk, 'the first output chunk');
      assert.strictEqual(completed, false, 'first output should arrive before process completion');
      standardInput.end('continue\n');

      const result = await within(wait, 'the sandbox wait');
      settled = true;
      await within(Promise.all([outputEnded, errorEnded]), 'the stream end events');
      assert.strictEqual(result.exitCode, 0, stderr);
      assert.ok(stdout.includes('STREAM_FIRST'));
      assert.ok(stdout.includes('STREAM_SECOND'));
      assert.ok(stderr.includes('STREAM_ERROR'));
    } finally {
      if (!settled) {
        sandbox.kill();
      }
      sandbox.dispose();
    }
  });
});
