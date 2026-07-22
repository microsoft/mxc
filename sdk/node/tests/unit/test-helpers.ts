// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { EventEmitter } from 'events';
import { Readable } from 'stream';
import { SandboxSpawnOptions } from '../../src/sandbox.js';
import { getPlatformSupport } from '../../src/platform.js';

// Skip marker for describes that hit the binary resolver: undefined when MXC
// is supported on this host, an error string when it isn't.
export const platformSkip: string | false = !getPlatformSupport().isSupported
  ? 'MXC not supported on this machine'
  : false;

/**
 * Spawn-options preset for unit tests that drive the real binary-resolver
 * code path but stub the actual `child_process.spawn`. `experimental: true`
 * exposes the state-aware functions; `executablePath: process.execPath`
 * gives the resolver an always-on-disk path so it can succeed without the
 * fake spawn ever using it.
 */
export function testOptions(extra?: Partial<SandboxSpawnOptions>): SandboxSpawnOptions {
  return { experimental: true, executablePath: process.execPath, ...extra };
}

export interface FakeChildOpts {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  error?: Error;
}

/**
 * Stub for `child_process.spawn` that emits a single round of stdout / stderr
 * data and a synthetic `close` event. Captures the command, args, and
 * decoded envelope (if `--config-base64` is present in args). Tracks
 * `child.kill()` invocations for AbortSignal tests.
 */
export function fakeSpawn(opts: FakeChildOpts): {
  spawn: (cmd: string, args: string[], spawnOpts: unknown) => unknown;
  captured: { cmd?: string; args?: string[]; envelope?: Record<string, unknown> };
  killCount: () => number;
  stdinEnded: () => boolean;
} {
  const captured: { cmd?: string; args?: string[]; envelope?: Record<string, unknown> } = {};
  let kills = 0;
  let stdinEnded = false;
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
    // Minimal stdin spy: buffered exec must close it so a stdin-reading guest
    // process sees EOF instead of hanging (see spawnAndCollect). It also
    // registers an 'error' handler on the pipe to swallow EPIPE, so the spy
    // mirrors the real WritableStream's `on`.
    const stdin = { end: () => { stdinEnded = true; }, on: () => stdin };
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
      stdin,
      stdout,
      stderr,
      kill: (_sig?: NodeJS.Signals | number) => {
        kills += 1;
        setImmediate(() => ee.emit('close', null));
        return true;
      },
    });
  };
  return { spawn, captured, killCount: () => kills, stdinEnded: () => stdinEnded };
}
