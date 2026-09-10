// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert';
import { getAvailableToolsPolicy, isSystemCriticalPathWith } from '../../src/policy.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

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

    it('should add $PSHOME (not the drive root) to readonlyPaths when pwsh.exe is on PATH', () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(pwshDir).toLowerCase()),
            '$PSHOME should be in readonlyPaths when pwsh.exe is on PATH',
        );
        assert.ok(
            !result.readonlyPaths.some(p => /^[a-z]:\\$/i.test(p)),
            'The drive root must never be granted — it exposes the whole volume',
        );
    });

    it('should add PSReadLine dir to readwritePaths when pwsh.exe is on PATH', () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const result = getAvailableToolsPolicy(env);
        const expected = path.resolve(path.join(
            'C:\\Users\\TestUser', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
        ));
        assert.ok(
            result.readwritePaths.some(p => p.toLowerCase() === expected.toLowerCase()),
            'PSReadLine directory should be in readwritePaths',
        );
    });

    it('should not add PowerShell paths when pwsh.exe is not on PATH', () => {
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

    it('should return empty policy on non-Windows even when pwsh.exe is on PATH', () => {
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

    it('should not add PSReadLine path when USERPROFILE is not set', () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir };
        const result = getAvailableToolsPolicy(env);
        assert.ok(
            result.readonlyPaths.some(p => p.toLowerCase() === path.resolve(pwshDir).toLowerCase()),
            '$PSHOME should still be in readonlyPaths',
        );
        assert.strictEqual(result.readwritePaths.length, 0,
            'readwritePaths should be empty without USERPROFILE',
        );
    });

    it('should never grant a filesystem root discovered on PATH', () => {
        const root = path.parse(process.cwd()).root;
        const result = getAvailableToolsPolicy({ PATH: root });
        assert.deepStrictEqual(result.readonlyPaths, [],
            'A filesystem root must never be granted — it exposes the whole volume',
        );
    });

    // The PSReadLine write grant is derived from USERPROFILE, which can
    // legitimately sit under %WINDIR% — the SYSTEM account's profile is
    // C:\Windows\System32\config\systemprofile. Only a real Windows host can
    // exercise this: mocking `process.platform` leaves the imported `path`
    // module POSIX, so the backslash-based %WINDIR% comparison never matches.
    // The equivalent semantics are covered on every host by the
    // 'Windows path semantics' suite below.
    it('should not grant write access under %WINDIR%', { skip: process.platform !== 'win32' }, () => {
        const pwshDir = createFakePwshDir();
        const env = {
            PATH: pwshDir,
            USERPROFILE: path.join(process.env['WINDIR'] || 'C:\\Windows', 'System32', 'config', 'systemprofile'),
        };
        const result = getAvailableToolsPolicy(env);
        assert.deepStrictEqual(result.readwritePaths, [],
            'No write grant may land under %WINDIR%',
        );
    });
});

describe('isSystemCriticalPath - Windows path semantics', () => {
    // The imported `path` module is POSIX on Linux/macOS, so mocking
    // `process.platform` alone cannot reach the Windows branches. Injecting
    // `path.win32` exercises them on every host.
    const isCritical = (p: string) => isSystemCriticalPathWith(p, path.win32, true);
    const originalWinDir = process.env['WINDIR'];

    afterEach(() => {
        if (originalWinDir === undefined) {
            delete process.env['WINDIR'];
        } else {
            process.env['WINDIR'] = originalWinDir;
        }
    });

    it('should reject drive and UNC share roots', () => {
        process.env['WINDIR'] = 'C:\\Windows';
        for (const root of ['C:\\', 'C:/', 'D:\\', '\\\\server\\share', '\\\\server\\share\\']) {
            assert.strictEqual(isCritical(root), true, `${root} must be system-critical`);
        }
    });

    it('should reject roots expressed in the verbatim or device namespace', () => {
        process.env['WINDIR'] = 'C:\\Windows';
        for (const root of [
            '\\\\?\\C:\\',
            '\\\\?\\C:',            // drive-relative: must not resolve against the cwd
            '\\\\.\\C:',
            '\\\\?\\Volume{9f1b2c3d-0000-0000-0000-000000000000}\\',
            '\\\\?\\UNC\\server\\share',
            '\\\\?\\unc\\server\\share\\',
        ]) {
            assert.strictEqual(isCritical(root), true, `${root} must be system-critical`);
        }
    });

    it('should reject %WINDIR% however it is spelled', () => {
        process.env['WINDIR'] = 'C:\\Windows';
        for (const dir of [
            'C:\\Windows',
            'c:\\windows\\system32',
            'C:\\Windows\\..\\Windows\\System32',
            '\\\\?\\C:\\Windows\\System32',
            '\\\\.\\C:\\Windows',
            // The SYSTEM account's USERPROFILE — the PSReadLine write grant
            // derived from it must be rejected.
            'C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine',
        ]) {
            assert.strictEqual(isCritical(dir), true, `${dir} must be system-critical`);
        }
    });

    it('should allow ordinary tool directories', () => {
        process.env['WINDIR'] = 'C:\\Windows';
        for (const dir of [
            'C:\\Program Files\\PowerShell\\7',
            'C:\\tools',
            'C:\\WindowsApps\\vendor',   // prefix of %WINDIR% but not under it
            '\\\\server\\share\\tools',
            '\\\\?\\UNC\\server\\share\\tools',
        ]) {
            assert.strictEqual(isCritical(dir), false, `${dir} must not be system-critical`);
        }
    });

    it('should reject the POSIX root on non-Windows', () => {
        assert.strictEqual(isSystemCriticalPathWith('/', path.posix, false), true);
        assert.strictEqual(isSystemCriticalPathWith('/usr/bin', path.posix, false), true);
        assert.strictEqual(isSystemCriticalPathWith('/opt/tools', path.posix, false), false);
    });
});
