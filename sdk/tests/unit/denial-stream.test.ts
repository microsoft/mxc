// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Readable } from 'stream';
import {
  parseDenialStream,
  stripNtPrefix,
  defaultDenialFilters,
  DENIAL_STREAM_MARKER,
  DeniedResource,
  DenialStreamSummary,
} from '../../src/denial-channel/stream.js';

// ---------- helpers ---------------------------------------------------------

const RS = String.fromCharCode(DENIAL_STREAM_MARKER);

/**
 * Build a captureDenials stderr stream from a list of native-format
 * JSON envelopes interleaved with arbitrary workload-stderr bytes.
 * Each envelope is rendered as `\x1e<json>\n` exactly as the native
 * writer would emit it.
 */
function buildStream(parts: ReadonlyArray<{ envelope?: object; passthrough?: string }>): Readable {
  const chunks: Buffer[] = [];
  for (const p of parts) {
    if (p.passthrough !== undefined) {
      chunks.push(Buffer.from(p.passthrough, 'utf8'));
    }
    if (p.envelope !== undefined) {
      chunks.push(Buffer.from(`${RS}${JSON.stringify(p.envelope)}\n`, 'utf8'));
    }
  }
  return Readable.from([Buffer.concat(chunks)]);
}

/** Convenience: build a single-chunk readable from a raw buffer. */
function readableOf(buf: Buffer | string): Readable {
  return Readable.from([typeof buf === 'string' ? Buffer.from(buf, 'utf8') : buf]);
}

// ---------- unit tests for the pure helpers --------------------------------

describe('stripNtPrefix', () => {
  it('strips a \\??\\ prefix', () => {
    assert.strictEqual(stripNtPrefix('\\??\\C:\\Users\\Foo'), 'C:\\Users\\Foo');
  });

  it('leaves paths without a \\??\\ prefix untouched', () => {
    assert.strictEqual(stripNtPrefix('C:\\Users\\Foo'), 'C:\\Users\\Foo');
    assert.strictEqual(
      stripNtPrefix('\\REGISTRY\\USER\\.DEFAULT\\Foo'),
      '\\REGISTRY\\USER\\.DEFAULT\\Foo',
    );
  });

  it('returns the empty string unchanged', () => {
    assert.strictEqual(stripNtPrefix(''), '');
  });
});

describe('defaultDenialFilters', () => {
  const apply = (r: DeniedResource): boolean =>
    defaultDenialFilters.every((f) => f(r));

  const file = (path: string): DeniedResource => ({
    kind: 'file',
    path,
    resourceType: 'file',
    accessType: 'read',
    pid: 1234,
    filetime: 0,
  });

  it('drops \\REGISTRY\\USER\\.DEFAULT registry noise', () => {
    assert.strictEqual(
      apply(file('\\REGISTRY\\USER\\.DEFAULT\\Control Panel\\International')),
      false,
    );
  });

  it('drops System32 loader probes (.dll, .mui, .mun, .cat, .cdf-ms, .nls)', () => {
    for (const ext of ['dll', 'mui', 'mun', 'cat', 'cdf-ms', 'nls']) {
      assert.strictEqual(
        apply(file(`C:\\Windows\\System32\\foo.${ext}`)),
        false,
        `expected .${ext} loader probe to be dropped`,
      );
    }
  });

  it('drops System32 loader probes even when carrying a \\??\\ prefix', () => {
    assert.strictEqual(
      apply(file('\\??\\C:\\Windows\\System32\\kernel32.dll')),
      false,
    );
  });

  it('keeps real workload-target paths under user profile', () => {
    assert.strictEqual(apply(file('C:\\Users\\Alice\\Documents\\report.txt')), true);
  });

  it('keeps arbitrary registry keys that are not the default user', () => {
    assert.strictEqual(apply(file('\\REGISTRY\\MACHINE\\Software\\MyApp')), true);
  });
});

// ---------- end-to-end parser tests ----------------------------------------

describe('parseDenialStream', () => {
  it('parses a single denial + summary into typed shapes', async () => {
    const denials: DeniedResource[] = [];
    const summaries: DenialStreamSummary[] = [];
    const stream = buildStream([
      {
        envelope: {
          type: 'denial',
          path: '\\??\\C:\\Users\\Alice\\Documents\\report.txt',
          resourceType: 'file',
          accessType: 'read',
          pid: 1234,
          filetime: 132000000000000000,
        },
      },
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 1,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream, {
      onDenial: (r) => denials.push(r),
      onSummary: (s) => summaries.push(s),
    });

    assert.strictEqual(result.parseErrors, 0);
    assert.strictEqual(result.denials.length, 1);
    assert.deepStrictEqual(result.denials[0], {
      kind: 'file',
      path: 'C:\\Users\\Alice\\Documents\\report.txt', // \\??\\ stripped by default
      resourceType: 'file',
      accessType: 'read',
      pid: 1234,
      filetime: 132000000000000000,
    });
    assert.deepStrictEqual(result.summary, {
      exitCode: 0,
      totalDenials: 1,
      deniedResourcesTruncated: false,
      // No captureDenialsActive in the wire fixture; parser
      // defaults to true for forward-compat with older binaries.
      captureDenialsActive: true,
      // Same forward-compat policy for childProcessesObserved.
      childProcessesObserved: 0,
      // Same for descendantPidsCovered (Phase E of descendant
      // tracking — landed after captureDenials shipped).
      descendantPidsCovered: 0,
    });
    assert.strictEqual(denials.length, 1, 'onDenial fired exactly once');
    assert.strictEqual(summaries.length, 1, 'onSummary fired exactly once');
  });

  it('demuxes denial lines from interleaved workload stderr writes', async () => {
    const passthrough: Buffer[] = [];
    const stream = buildStream([
      { passthrough: 'workload starting...\n' },
      {
        envelope: {
          type: 'denial',
          path: 'C:\\Users\\Bob\\file.txt',
          resourceType: 'file',
          accessType: 'read',
          pid: 7,
          filetime: 1,
        },
      },
      { passthrough: 'workload progress 50%\n' },
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 1,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream, {
      filters: 'none',
      onPassthrough: (c) => passthrough.push(c),
    });

    assert.strictEqual(result.denials.length, 1);
    assert.ok(result.summary);
    const combined = Buffer.concat(passthrough).toString('utf8');
    // Passthrough should contain only the workload bytes, not the JSON envelopes.
    assert.ok(combined.includes('workload starting'));
    assert.ok(combined.includes('workload progress'));
    assert.ok(!combined.includes('"type":"denial"'));
    assert.ok(!combined.includes('"type":"summary"'));
  });

  it('default filters drop System32 loader probes and DEFAULT-user registry noise', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'denial',
          path: '\\??\\C:\\Windows\\System32\\kernel32.dll',
          resourceType: 'file',
          accessType: 'read',
          pid: 1,
          filetime: 1,
        },
      },
      {
        envelope: {
          type: 'denial',
          path: '\\REGISTRY\\USER\\.DEFAULT\\Control Panel\\International',
          resourceType: 'other',
          accessType: 'unknown',
          pid: 1,
          filetime: 2,
        },
      },
      {
        envelope: {
          type: 'denial',
          path: '\\??\\C:\\Users\\Carol\\Documents\\report.txt',
          resourceType: 'file',
          accessType: 'read',
          pid: 1,
          filetime: 3,
        },
      },
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 3,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream);

    assert.strictEqual(result.denials.length, 1, 'only the real workload target survived');
    assert.strictEqual(result.denials[0].path, 'C:\\Users\\Carol\\Documents\\report.txt');
    // Summary reflects the native-side total (pre-SDK-filter), not the filtered count.
    assert.strictEqual(result.summary?.totalDenials, 3);
  });

  it('filters: "none" passes every denial through unchanged', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'denial',
          path: '\\REGISTRY\\USER\\.DEFAULT\\Foo',
          resourceType: 'other',
          accessType: 'unknown',
          pid: 1,
          filetime: 1,
        },
      },
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 1,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream, { filters: 'none' });
    assert.strictEqual(result.denials.length, 1);
  });

  it('stripNtPrefix: false preserves the raw \\??\\ form', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'denial',
          path: '\\??\\C:\\Users\\Dan\\foo.txt',
          resourceType: 'file',
          accessType: 'read',
          pid: 1,
          filetime: 1,
        },
      },
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 1,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream, { stripNtPrefix: false });
    assert.strictEqual(result.denials[0].path, '\\??\\C:\\Users\\Dan\\foo.txt');
  });

  it('captures rawEventCount when present in the summary (verbose mode)', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 8,
          deniedResourcesTruncated: false,
          rawEventCount: 651,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.strictEqual(result.summary?.totalDenials, 8);
    assert.strictEqual(result.summary?.rawEventCount, 651);
  });

  it('handles a chunk that splits a JSON envelope across boundaries', async () => {
    const json = JSON.stringify({
      type: 'denial',
      path: 'C:\\Users\\Eve\\file.txt',
      resourceType: 'file',
      accessType: 'read',
      pid: 1,
      filetime: 1,
    });
    const summary = JSON.stringify({
      type: 'summary',
      exitCode: 0,
      totalDenials: 1,
      deniedResourcesTruncated: false,
    });
    const full = Buffer.from(`${RS}${json}\n${RS}${summary}\n`, 'utf8');

    // Push the bytes one at a time to exercise mid-segment boundary
    // handling — this is the worst case the demuxer must survive.
    const stream = new Readable({ read() {} });
    for (const byte of full) {
      stream.push(Buffer.from([byte]));
    }
    stream.push(null);

    const result = await parseDenialStream(stream, { filters: 'none' });
    assert.strictEqual(result.parseErrors, 0);
    assert.strictEqual(result.denials.length, 1);
    assert.strictEqual(result.denials[0].path, 'C:\\Users\\Eve\\file.txt');
    assert.strictEqual(result.summary?.totalDenials, 1);
  });

  it('counts unparseable segments as parseErrors and keeps going', async () => {
    const stream = readableOf(
      `${RS}not valid json\n` +
        `${RS}{"type":"denial","path":"C:\\\\ok.txt","resourceType":"file","accessType":"read","pid":1,"filetime":1}\n` +
        `${RS}{"type":"summary","exitCode":0,"totalDenials":1,"deniedResourcesTruncated":false}\n`,
    );

    const result = await parseDenialStream(stream, { filters: 'none' });
    assert.strictEqual(result.parseErrors, 1);
    assert.strictEqual(result.denials.length, 1);
    assert.ok(result.summary);
  });

  it('counts unknown envelope types as parseErrors so version skew is visible', async () => {
    const stream = buildStream([
      { envelope: { type: 'denial-v2', path: 'foo', pid: 1, filetime: 1 } },
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 0,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.strictEqual(result.parseErrors, 1);
    assert.strictEqual(result.denials.length, 0);
    assert.ok(result.summary);
  });

  it('resolves with summary=undefined when the stream ends before a summary line', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'denial',
          path: 'C:\\Users\\Fred\\foo.txt',
          resourceType: 'file',
          accessType: 'read',
          pid: 1,
          filetime: 1,
        },
      },
    ]);

    const result = await parseDenialStream(stream, { filters: 'none' });
    assert.strictEqual(result.denials.length, 1);
    assert.strictEqual(result.summary, undefined);
  });

  it('surfaces captureDenialsActive=false when the native side could not attach the collector', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 0,
          deniedResourcesTruncated: false,
          captureDenialsActive: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.ok(result.summary);
    assert.strictEqual(result.summary!.captureDenialsActive, false);
    assert.strictEqual(result.summary!.totalDenials, 0);
  });

  it('surfaces captureDenialsActive=true when the native side attached the collector', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 3,
          deniedResourcesTruncated: false,
          captureDenialsActive: true,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.strictEqual(result.summary!.captureDenialsActive, true);
  });

  it('defaults captureDenialsActive to true when the field is absent (older native binaries)', async () => {
    // Forward-compat: an older binary that doesn't yet know about
    // the `captureDenialsActive` field shouldn't trip the parser.
    // We optimistically assume "active" so its behavior matches
    // what consumers saw before the field landed.
    const stream = buildStream([
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 0,
          deniedResourcesTruncated: false,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.strictEqual(result.summary!.captureDenialsActive, true);
  });

  it('surfaces childProcessesObserved when present in the summary', async () => {
    const stream = buildStream([
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 2,
          deniedResourcesTruncated: false,
          captureDenialsActive: true,
          childProcessesObserved: 7,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.strictEqual(result.summary!.childProcessesObserved, 7);
  });

  it('defaults childProcessesObserved to 0 when the field is absent (older native binaries)', async () => {
    // Same forward-compat policy as captureDenialsActive: an older
    // native binary that doesn't poll for children should not look
    // like "definitely no children" -- it should look like "the
    // field wasn't reported", and we surface that as 0 with the
    // expectation that consumers treat 0 as "no observation made".
    const stream = buildStream([
      {
        envelope: {
          type: 'summary',
          exitCode: 0,
          totalDenials: 0,
          deniedResourcesTruncated: false,
          captureDenialsActive: true,
        },
      },
    ]);

    const result = await parseDenialStream(stream);
    assert.strictEqual(result.summary!.childProcessesObserved, 0);
  });
});
