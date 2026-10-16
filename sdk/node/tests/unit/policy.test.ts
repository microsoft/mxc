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
        assert.deepStrictEqual(
            getAvailableToolsPolicy({}, { allowPowerShellDriveRootRead: true }),
            { readonlyPaths: [], readwritePaths: [] },
        );
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
            fs.writeFileSync(path.join(root, 'pwsh.exe'), '');
            const environment = { path: root };
            const driveRoot = path.resolve('C:\\');
            assert.deepStrictEqual(getAvailableToolsPolicy(environment).readonlyPaths, [root]);
            assert.deepStrictEqual(
                getAvailableToolsPolicy(environment, { containerType: 'processcontainer' }).readonlyPaths, [],
            );
            // containerType filters ACLs and does not opt in to the drive-root read.
            assert.deepStrictEqual(
                getAvailableToolsPolicy(environment, {
                    containerType: 'processcontainer',
                    allowPowerShellDriveRootRead: false,
                }).readonlyPaths,
                [],
            );
            assert.deepStrictEqual(
                getAvailableToolsPolicy(environment, {
                    containerType: 'processcontainer',
                    allowPowerShellDriveRootRead: true,
                }).readonlyPaths,
                [driveRoot],
            );
        } finally {
            fs.rmSync(root, { recursive: true });
        }
    });

    it('preserves a drive root explicitly supplied on PATH', { skip: process.platform !== 'win32' }, () => {
        const pwshDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-test-'));
        try {
            fs.writeFileSync(path.join(pwshDir, 'pwsh.exe'), '');
            const driveRoot = path.resolve((process.env['SystemDrive'] || 'C:') + '\\');
            assert.strictEqual(fs.statSync(driveRoot).isDirectory(), true);
            const environment = { PATH: `${driveRoot};${pwshDir}`, USERPROFILE: 'C:\\Users\\TestUser' };
            const history = path.resolve(path.join(
                'C:\\Users\\TestUser', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
            ));
            const result = getAvailableToolsPolicy(environment);
            const toolDir = path.resolve(pwshDir);
            assert.deepStrictEqual(result.readonlyPaths, [driveRoot, toolDir]);
            assert.deepStrictEqual(result.readwritePaths, [history]);
            assert.deepStrictEqual(
                getAvailableToolsPolicy({ PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' }).readonlyPaths,
                [toolDir],
            );
        } finally {
            fs.rmSync(pwshDir, { recursive: true, force: true });
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

    const psReadLine = (profile: string): string => path.resolve(path.join(
        profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine',
    ));

    const driveRoot = (drive: string): string => path.resolve(drive + '\\');

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

    it('should keep the tool directory and PSReadLine history without a drive root', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser' };
        const toolDir = path.resolve(pwshDir);
        const history = psReadLine('C:\\Users\\TestUser');
        const optionSets = [undefined, {}, { allowPowerShellDriveRootRead: false }] as const;
        for (const options of optionSets) {
            const result = getAvailableToolsPolicy(env, options);
            assert.deepStrictEqual(result.readonlyPaths, [toolDir]);
            assert.deepStrictEqual(result.readwritePaths, [history]);
        }
    });

    it('should restore the drive root only when allowPowerShellDriveRootRead is true', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const toolDir = path.resolve(pwshDir);
        const history = psReadLine('C:\\Users\\TestUser');

        const nonDefaultDrive = getAvailableToolsPolicy(
            { PATH: pwshDir, SystemDrive: 'D:', USERPROFILE: 'C:\\Users\\TestUser' },
            { allowPowerShellDriveRootRead: true },
        );
        assert.deepStrictEqual(nonDefaultDrive.readonlyPaths, [toolDir, driveRoot('D:')]);
        assert.deepStrictEqual(nonDefaultDrive.readwritePaths, [history]);

        for (const systemDrive of [undefined, '']) {
            const environment: { [key: string]: string | undefined } = {
                PATH: pwshDir,
                USERPROFILE: 'C:\\Users\\TestUser',
            };
            if (systemDrive !== undefined) {
                environment['SystemDrive'] = systemDrive;
            }
            const fallback = getAvailableToolsPolicy(environment, { allowPowerShellDriveRootRead: true });
            assert.deepStrictEqual(fallback.readonlyPaths, [toolDir, driveRoot('C:')]);
            assert.deepStrictEqual(fallback.readwritePaths, [history]);
        }

        const caseInsensitive = getAvailableToolsPolicy(
            { path: pwshDir, systemdrive: 'E:', userprofile: 'C:\\Users\\Other' },
            { allowPowerShellDriveRootRead: true },
        );
        assert.deepStrictEqual(caseInsensitive.readonlyPaths, [toolDir, driveRoot('E:')]);
        assert.deepStrictEqual(caseInsensitive.readwritePaths, [psReadLine('C:\\Users\\Other')]);
    });

    it('should not add a drive root without pwsh.exe even when opted in', { skip: isLinux }, () => {
        mockWindows();
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-test-'));
        const env = { PATH: tmpDir, USERPROFILE: 'C:\\Users\\TestUser', SystemDrive: 'D:' };
        const result = getAvailableToolsPolicy(env, { allowPowerShellDriveRootRead: true });
        assert.deepStrictEqual(result.readonlyPaths, [path.resolve(tmpDir)]);
        assert.deepStrictEqual(result.readwritePaths, []);
    });

    it('should return no PowerShell grant on non-Windows even when opted in', { skip: isLinux }, () => {
        mockLinux();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, USERPROFILE: 'C:\\Users\\TestUser', SystemDrive: 'D:' };
        const result = getAvailableToolsPolicy(env, { allowPowerShellDriveRootRead: true });
        assert.ok(!result.readonlyPaths.includes(driveRoot('D:')));
        assert.ok(!result.readonlyPaths.includes(driveRoot('C:')));
        assert.deepStrictEqual(result.readwritePaths, []);
    });

    it('should not add PSReadLine history when USERPROFILE is not set', { skip: isLinux }, () => {
        mockWindows();
        const pwshDir = createFakePwshDir();
        const env = { PATH: pwshDir, SystemDrive: 'D:' };
        const toolDir = path.resolve(pwshDir);
        const withoutRoot = getAvailableToolsPolicy(env, { allowPowerShellDriveRootRead: false });
        assert.deepStrictEqual(withoutRoot.readonlyPaths, [toolDir]);
        assert.deepStrictEqual(withoutRoot.readwritePaths, []);
        const withRoot = getAvailableToolsPolicy(env, { allowPowerShellDriveRootRead: true });
        assert.deepStrictEqual(withRoot.readonlyPaths, [toolDir, driveRoot('D:')]);
        assert.deepStrictEqual(withRoot.readwritePaths, []);
    });
});
