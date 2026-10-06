// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { policy } from '../../src/v1/index.js';

import { execFileSync } from 'node:child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const { getAvailableToolsPolicy, getUserProfilePolicy, getTemporaryFilesPolicy } = policy.filesystem;

// TODO: Investigate why Object.defineProperty(process, 'platform', ...) does not
// take effect on Linux ADO pipeline runners (Node.js v20.19.x). These tests mock
// process.platform to 'win32' and must be skipped on Linux until the root cause
// is understood.
const isLinux = process.platform === 'linux';

describe('filesystem helper environment and options', () => {
    it('cannot override host Windows safety exclusions through the discovery map', {
        skip: process.platform !== 'win32',
    }, () => {
        const hostWindows = process.env['WINDIR'] || process.env['windir'] || 'C:\\Windows';
        for (const WINDIR of [undefined, '', 'C:\\SpoofedWindows']) {
            assert.deepStrictEqual(
                getAvailableToolsPolicy({ PATH: hostWindows, WINDIR }).readonlyPaths,
                [],
            );
        }
    });

    it('does not substitute the host environment for an empty map', () => {
        assert.deepStrictEqual(getAvailableToolsPolicy({}), { readonlyPaths: [], readwritePaths: [] });
        assert.deepStrictEqual(getUserProfilePolicy({}), { readonlyPaths: [], readwritePaths: [] });
    });

    it('discovers profile directories from the supplied environment', () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-profile-'));
        try {
            const expected = process.platform === 'win32'
                ? path.join(root, 'Programs', 'Tool') : path.join(root, '.local', 'bin');
            fs.mkdirSync(expected, { recursive: true });
            const environment = process.platform === 'win32' ? { localappdata: root } : { HOME: root };
            assert.deepStrictEqual(getUserProfilePolicy(environment), {
                readonlyPaths: [expected], readwritePaths: [],
            });
        } finally {
            fs.rmSync(root, { recursive: true });
        }
    });

    it('uses existing temporary storage without creating a directory', () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-temp-'));
        try {
            const environment = process.platform === 'win32' ? { temp: root } : { TMPDIR: root };
            assert.deepStrictEqual(getTemporaryFilesPolicy(environment), {
                readonlyPaths: [], readwritePaths: [root],
            });
            assert.deepStrictEqual(fs.readdirSync(root), []);
        } finally {
            fs.rmSync(root, { recursive: true });
        }
    });

    it('filters ALL APPLICATION PACKAGES only when requested', { skip: process.platform !== 'win32' }, () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-tools & paths-'));
        try {
            execFileSync('icacls.exe', [root, '/grant', '*S-1-15-2-1:(OI)(CI)(RX)'], { windowsHide: true });
            const environment = { path: root };
            assert.deepStrictEqual(getAvailableToolsPolicy(environment).readonlyPaths, [root]);
            assert.deepStrictEqual(
                getAvailableToolsPolicy(environment, { containerType: 'processcontainer' }).readonlyPaths, [],
            );
        } finally {
            fs.rmSync(root, { recursive: true });
        }
    });
});

describe('getAvailableToolsPolicy - PowerShell discovery', () => {
    let originalPlatform: PropertyDescriptor | undefined;
    let tmpDir: string | undefined;

    const mockWindows = () => {
        originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
        Object.defineProperty(process, 'platform', { value: 'win32' });
    };

    const mockLinux = () => {
        originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
        Object.defineProperty(process, 'platform', { value: 'linux' });
    };

    /** Create a temp directory containing a fake pwsh.exe and return its path. */
    const createFakePwshDir = (): string => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-test-'));
        fs.writeFileSync(path.join(tmpDir, 'pwsh.exe'), '');
        return tmpDir;
    };

    afterEach(() => {
        if (originalPlatform) {
            Object.defineProperty(process, 'platform', originalPlatform);
            originalPlatform = undefined;
        }
        if (tmpDir) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
            tmpDir = undefined;
        }
    });

    it('should add system root to readonlyPaths when pwsh.exe is on PATH', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root (e.g. C:\\) should be in readonlyPaths when pwsh.exe is on PATH',
        );
    });

    it('should add PSReadLine dir to readwritePaths when pwsh.exe is on PATH', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        const expected = path.join(
            'C:\\Users\\TestUser', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
        );
        assert.ok(
            result.readwritePaths.some(p => p.toLowerCase() === expected.toLowerCase()),
            'PSReadLine directory should be in readwritePaths',
        );
    });

    it('should not add PowerShell paths when pwsh.exe is not on PATH', { skip: isLinux }, () => {
        mockWindows();
        const env = { PATH: 'C:\\Windows\\System32', USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root should not be in readonlyPaths when pwsh.exe is not on PATH',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty when pwsh.exe is not on PATH',
        );
    });

    it('should return empty policy on non-Windows even when pwsh.exe is on PATH', { skip: isLinux }, () => {
        mockLinux();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root (e.g. C:\\) should not be in readonlyPaths on Linux',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty on Linux',
        );
    });

    it('should not add PSReadLine path when USERPROFILE is not set', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'System root should still be in readonlyPaths',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty without USERPROFILE',
        );
    });
});
