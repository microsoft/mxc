// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import {
    isDenialServiceRunning,
    pipeProbeErrorIndicatesRunning,
    readDeniedResources,
    mapEventToResourceInfo,
    validateDenialEvent,
    DenialEvent,
} from '../../src/denial-service.js';
import { DeniedResourceInfo } from '../../src/denied-resources.js';

// ---------------------------------------------------------------------------
// isDenialServiceRunning — pipe availability check
// ---------------------------------------------------------------------------

describe('isDenialServiceRunning', () => {
    it('returns false when denial service pipe does not exist', () => {
        // In test environments the diagnostic service is never running,
        // so this should reliably return false.
        const result = isDenialServiceRunning();
        assert.strictEqual(result, false);
    });

    it('returns a boolean value', () => {
        const result = isDenialServiceRunning();
        assert.strictEqual(typeof result, 'boolean');
    });
});

// ---------------------------------------------------------------------------
// pipeProbeErrorIndicatesRunning — error-code classification (BUG 1 fix)
//
// Regression coverage for the EBUSY-on-listening-pipe bug: fs.statSync threw
// EBUSY on a *listening* named-pipe instance, which the old bare-catch logic
// mis-read as "service down", gating off the entire ETW detection tier. We
// test the classifier in isolation rather than against a live pipe because the
// pipe name is global per-user and node:test runs files concurrently, so a
// real listening pipe would leak into other test files.
// ---------------------------------------------------------------------------

describe('pipeProbeErrorIndicatesRunning', () => {
    it('returns true for EBUSY (pipe exists, server up, handle busy)', () => {
        const err: NodeJS.ErrnoException = Object.assign(new Error('busy'), { code: 'EBUSY' });
        assert.strictEqual(pipeProbeErrorIndicatesRunning(err), true);
    });

    it('returns false for ENOENT (pipe genuinely absent)', () => {
        const err: NodeJS.ErrnoException = Object.assign(new Error('not found'), { code: 'ENOENT' });
        assert.strictEqual(pipeProbeErrorIndicatesRunning(err), false);
    });

    it('returns true for other errnos that imply the pipe exists (EACCES, EPIPE)', () => {
        for (const code of ['EACCES', 'EPIPE']) {
            const err: NodeJS.ErrnoException = Object.assign(new Error(code), { code });
            assert.strictEqual(pipeProbeErrorIndicatesRunning(err), true);
        }
    });

    it('fails closed (false) when the error has no code', () => {
        assert.strictEqual(pipeProbeErrorIndicatesRunning(new Error('no code')), false);
    });
});

// ---------------------------------------------------------------------------
// readDeniedResources — graceful fallback when service unavailable
// ---------------------------------------------------------------------------

describe('readDeniedResources', () => {
    it('returns empty array when service is not available (containerName filter)', async () => {
        const result = await readDeniedResources({ containerName: 'nonexistent-container' });
        assert.ok(Array.isArray(result));
        assert.strictEqual(result.length, 0);
    });

    it('returns empty array with pid filter (primary match key)', async () => {
        const result = await readDeniedResources({ pid: 12345 });
        assert.ok(Array.isArray(result));
        assert.strictEqual(result.length, 0);
    });

    it('resolves (does not throw) with an empty filter', async () => {
        // Graceful fallback — should never throw, just return []
        const result = await readDeniedResources({});
        assert.ok(Array.isArray(result));
        assert.strictEqual(result.length, 0);
    });
});

// ---------------------------------------------------------------------------
// mapEventToResourceInfo — direct mapping tests (L4)
// ---------------------------------------------------------------------------

describe('mapEventToResourceInfo', () => {
    it('maps a file DenialEvent to a high-confidence etw_service resource', () => {
        const event: DenialEvent = {
            path: 'C:\\Users\\me\\secret.txt',
            resourceType: 'file',
            accessType: 'read',
            containerName: 'my-sandbox',
            pid: 5678,
            timestamp: '2025-06-15T12:00:00Z',
            eventId: 4907,
        };

        const mapped = mapEventToResourceInfo(event);
        assert.deepStrictEqual(mapped, {
            path: 'C:\\Users\\me\\secret.txt',
            resourceType: 'file',
            source: 'etw_service',
            confidence: 'high',
            accessType: 'read',
        } satisfies DeniedResourceInfo);
    });

    it('maps a network DenialEvent to a network resource', () => {
        const event: DenialEvent = {
            path: '10.0.0.1:443',
            resourceType: 'network',
            accessType: 'unknown',
            containerName: '',
            pid: 42,
            timestamp: '2025-06-15T12:00:00Z',
        };

        const mapped = mapEventToResourceInfo(event);
        assert.ok(mapped);
        assert.strictEqual(mapped!.resourceType, 'network');
        assert.strictEqual(mapped!.source, 'etw_service');
        assert.strictEqual(mapped!.confidence, 'high');
        assert.strictEqual(mapped!.path, '10.0.0.1:443');
    });

    it("returns null for 'other' resource types (not actionable)", () => {
        const event: DenialEvent = {
            path: 'HKLM\\Software\\Test',
            resourceType: 'other',
            accessType: 'write',
            containerName: 'c',
            pid: 1,
            timestamp: '2025-06-15T12:00:00Z',
        };

        assert.strictEqual(mapEventToResourceInfo(event), null);
    });

    it('preserves every accessType value', () => {
        const accessTypes: DenialEvent['accessType'][] = ['read', 'write', 'execute', 'unknown'];
        for (const at of accessTypes) {
            const mapped = mapEventToResourceInfo({
                path: 'C:\\f',
                resourceType: 'file',
                accessType: at,
                containerName: 'c',
                pid: 1,
                timestamp: '2025-06-15T12:00:00Z',
            });
            assert.strictEqual(mapped?.accessType, at);
        }
    });
});

// ---------------------------------------------------------------------------
// validateDenialEvent — structural validation (L7)
// ---------------------------------------------------------------------------

describe('validateDenialEvent', () => {
    const valid: DenialEvent = {
        path: 'C:\\Users\\me\\f.txt',
        resourceType: 'file',
        accessType: 'read',
        containerName: 'c',
        pid: 100,
        timestamp: '2025-06-15T12:00:00Z',
        eventId: 4907,
    };

    it('accepts a well-formed event', () => {
        assert.strictEqual(validateDenialEvent(valid), true);
    });

    it('accepts an event without the optional eventId', () => {
        const { eventId: _eventId, ...rest } = valid;
        assert.strictEqual(validateDenialEvent(rest), true);
    });

    it('rejects non-objects', () => {
        assert.strictEqual(validateDenialEvent(null), false);
        assert.strictEqual(validateDenialEvent('nope'), false);
        assert.strictEqual(validateDenialEvent(42), false);
        assert.strictEqual(validateDenialEvent(undefined), false);
    });

    it('rejects empty or whitespace-only paths', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, path: '' }), false);
        assert.strictEqual(validateDenialEvent({ ...valid, path: '   ' }), false);
    });

    it('rejects an implausibly long path', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, path: 'C:\\'.padEnd(40000, 'a') }), false);
    });

    it('rejects non-string path', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, path: 123 }), false);
    });

    it('rejects unknown resourceType / accessType', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, resourceType: 'registry' }), false);
        assert.strictEqual(validateDenialEvent({ ...valid, accessType: 'delete' }), false);
    });

    it('rejects invalid pid values', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, pid: -1 }), false);
        assert.strictEqual(validateDenialEvent({ ...valid, pid: 1.5 }), false);
        assert.strictEqual(validateDenialEvent({ ...valid, pid: '100' }), false);
    });

    it('rejects a non-string containerName or timestamp', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, containerName: 5 }), false);
        assert.strictEqual(validateDenialEvent({ ...valid, timestamp: 0 }), false);
    });

    it('rejects a non-numeric eventId (L1: eventId is a number)', () => {
        assert.strictEqual(validateDenialEvent({ ...valid, eventId: '4907' }), false);
    });
});

// ---------------------------------------------------------------------------
// Round-trip: mock named-pipe server -> SDK client -> mapped result (L4)
// ---------------------------------------------------------------------------

/**
 * Replicate the SDK's per-user pipe-name resolution so the mock server can
 * listen on exactly the path readDeniedResources connects to. Returns null
 * when named pipes / SID resolution are unavailable so the test can skip.
 */
function computeDenialPipeName(): string | null {
    if (os.platform() !== 'win32') {
        return null;
    }
    try {
        const systemRoot = process.env['SystemRoot'] || process.env['SYSTEMROOT'] || 'C:\\Windows';
        const whoamiPath = path.join(systemRoot, 'System32', 'whoami.exe');
        const output = execFileSync(whoamiPath, ['/user', '/fo', 'csv', '/nh'], {
            encoding: 'utf8',
            timeout: 3000,
            windowsHide: true,
        }).trim();
        const match = output.match(/"(S-[\d-]+)"/);
        if (match) {
            return `\\\\.\\pipe\\mxc-denials-${match[1]}`;
        }
    } catch {
        // fall through
    }
    return null;
}

describe('readDeniedResources round-trip (mock pipe server)', () => {
    it('reads, validates, and maps an event emitted by a mock server', async (t) => {
        const pipeName = computeDenialPipeName();
        if (!pipeName) {
            t.skip('Named pipes / SID resolution not available in this environment');
            return;
        }

        const emitted: DenialEvent = {
            path: 'C:\\Users\\me\\blocked.txt',
            resourceType: 'file',
            accessType: 'write',
            containerName: '',
            pid: 4321,
            timestamp: '2026-01-15T10:30:00Z',
            eventId: 4907,
        };
        // An 'other' event that must be filtered out, plus a malformed line.
        const otherEvent: DenialEvent = { ...emitted, resourceType: 'other', path: 'HKLM\\X' };

        const server = net.createServer((socket) => {
            socket.on('data', () => {
                socket.write(JSON.stringify(emitted) + '\n');
                socket.write('not-json\n');
                socket.write(JSON.stringify(otherEvent) + '\n');
                socket.end();
            });
        });

        const listening = await new Promise<boolean>((resolve) => {
            server.once('error', () => resolve(false));
            server.listen(pipeName, () => resolve(true));
        });

        if (!listening) {
            t.skip('Could not bind mock named-pipe server');
            return;
        }

        try {
            const results = await readDeniedResources({ pid: emitted.pid });
            assert.strictEqual(results.length, 1, 'only the actionable file event should map');
            assert.deepStrictEqual(results[0], {
                path: emitted.path,
                resourceType: 'file',
                source: 'etw_service',
                confidence: 'high',
                accessType: 'write',
            });
        } finally {
            await new Promise<void>((resolve) => server.close(() => resolve()));
        }
    });
});
