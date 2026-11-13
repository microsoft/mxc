// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { it } from 'node:test';
import {
  runJson, spawnJson, spawnWithPtyJson, validateProcessJson,
  preparePolicyJson, parsePolicyFailures, serializePolicyFailures, type PolicyFailures,
  PolicyFailureOutcomes, PolicyFailureClasses, PolicyFailureReasons, PolicyFailureActions,
  PolicyFailureResourceKinds, PolicyFailureValueKinds, PolicyFailureAccessValues, PolicyFailureFlags,
  PolicyFailureVersions,
} from '@microsoft/mxc-sdk/v1/dev';
import { MxcError, policy } from '@microsoft/mxc-sdk/v1';
import { createPrivateWindowsTempDir, isLinuxRoot, sandboxSkipReason } from './test-helpers.js';

const windows = process.platform === 'win32';
const creationSkip = windows ? sandboxSkipReason
  : process.platform === 'linux' ? (isLinuxRoot ? undefined : 'Bubblewrap requires root')
  : process.platform === 'darwin' ? undefined : 'Unsupported host';
async function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  let text = '';
  for await (const chunk of stream) text += chunk.toString();
  return text;
}

for (const version of ['1.0.0', '1.1.0-alpha']) {
  const request = (commandLine: string) => JSON.stringify({
    version,
    containment: 'process',
    process: { commandLine, timeout: 30000 },
  });

  it(`V1.Dev runJson captures output and exit status (${version})`, { skip: creationSkip }, async () => {
    const result = await runJson(request(windows
      ? 'cmd.exe /c "echo DEV_CAPTURE_OK & echo DEV_CAPTURE_ERR 1>&2 & exit /b 7"'
      : "printf 'DEV_CAPTURE_OK\\n'; printf 'DEV_CAPTURE_ERR\\n' >&2; exit 7"));
    assert.equal(result.exitCode, 7);
    assert.equal(result.timedOut, false);
    assert.ok(result.stdout.includes('DEV_CAPTURE_OK'));
    assert.ok(result.stderr.includes('DEV_CAPTURE_ERR'));
    assert.ok(Array.isArray(result.warnings));
  });

  it(`V1.Dev spawnJson supports bidirectional pipes (${version})`, { skip: creationSkip }, async () => {
    const proc = await spawnJson(request(windows
      ? 'cmd.exe /v:on /c "set /p L= & echo DEV_PIPE:!L! & echo DEV_PIPE_ERR 1>&2 & exit /b 9"'
      : 'IFS= read -r line; printf "DEV_PIPE:%s\\n" "$line"; printf "DEV_PIPE_ERR\\n" >&2; exit 9'),
    { experimental: true });
    try {
      assert.ok(proc.standardInput);
      assert.ok(proc.standardOutput);
      assert.ok(proc.standardError);
      const stdout = readAll(proc.standardOutput);
      const stderr = readAll(proc.standardError);
      proc.standardInput.end(windows ? 'ping-pong\r\n' : 'ping-pong\n');
      const result = await proc.wait();
      assert.equal(result.exitCode, 9);
      assert.equal(result.timedOut, false);
      assert.ok((await stdout).includes('DEV_PIPE:ping-pong'));
      assert.ok((await stderr).includes('DEV_PIPE_ERR'));
    } finally {
      proc.dispose();
    }
  });

  it(`V1.Dev spawnWithPtyJson supports an interactive terminal (${version})`, { skip: creationSkip }, async () => {
    const command = windows ? 'cmd.exe'
      : 'test -t 0 && test -t 1 || exit 12; IFS= read -r value; '
        + 'stty size; printf "DEV_PTY_%s\\n" "$value"; exit 13';
    const terminal = await spawnWithPtyJson(request(command), {
      size: { rows: 30, columns: 90 },
    });
    try {
      const output = readAll(terminal.output);
      terminal.resize({ rows: 40, columns: 100 });
      terminal.input.write(windows
        ? 'set MXC_DEV_MARK=OK\r\necho DEV_PTY_%MXC_DEV_MARK%\r\nexit /b 13\r\n'
        : 'OK\n');
      const result = await terminal.wait();
      const text = await output;
      assert.equal(result.exitCode, 13, text);
      assert.equal(result.timedOut, false);
      assert.match(text, /DEV_PTY_OK/);
      if (!windows) assert.match(text, /40 100/);
    } finally {
      terminal.dispose();
    }
  });
}

it('V1.Dev rejects unknown fields and unregistered exact versions through native', async () => {
  const unregistered =
    '{"version":"999.0.0","process":{"commandLine":"echo must-not-run"}}';
  await assert.rejects(
    runJson(unregistered),
    (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
  );

  const unknownField =
    '{"version":"1.0.0","phase":"exec","sandboxId":"iso:unused","process":{"commandLine":"echo must-not-run"},"extra":true}';
  await assert.rejects(
    validateProcessJson(unknownField),
    (error: unknown) => error instanceof MxcError && error.code === 'malformed_request',
  );
});

it('V1.Dev bounds terminal policy failures at native preparation without creating a workload', async () => {
  const report: PolicyFailures = {
    formatVersion: PolicyFailureVersions.Format,
    results: Array.from({ length: 65 }, (_, outcome) => ({
      version: PolicyFailureVersions.Result,
      minimumReaderVersion: PolicyFailureVersions.MinimumReader,
      outcome,
      details: [],
    })),
  };
  const restored = parsePolicyFailures(serializePolicyFailures(report));
  assert.deepEqual(restored, report);
  const request = '{"version":"1.1.0-alpha","containment":"processcontainer",'
    + '"process":{"commandLine":"echo must-not-run"}}';
  await assert.rejects(preparePolicyJson(request, restored), (error: unknown) => {
      assert.ok(error instanceof MxcError);
      assert.equal(error.code, 'malformed_request');
      assert.equal(error.details?.ffiStatus, 1);
      assert.match(error.message, /result limit/);
      return true;
  });
});

it('V1.Dev preparation without observations returns the request unchanged on every backend', async () => {
  for (const containment of ['processcontainer', 'process', 'bubblewrap', 'seatbelt', undefined]) {
    const request = JSON.stringify({
      version: '1.1.0-alpha',
      ...(containment === undefined ? {} : { containment }),
      process: { commandLine: 'echo must-not-run' },
    });
    const prepared = await preparePolicyJson(request, {
      formatVersion: PolicyFailureVersions.Format, results: [],
    });
    assert.equal(prepared.requestJson, request, `containment ${containment ?? '(default)'}`);
    assert.deepEqual(prepared.changes, []);
  }
  const bubblewrap = '{"version":"1.1.0-alpha","containment":"bubblewrap",'
    + '"process":{"commandLine":"echo must-not-run"}}';
  await assert.rejects(preparePolicyJson(bubblewrap, {
    formatVersion: PolicyFailureVersions.Format,
    results: [{
      version: PolicyFailureVersions.Result,
      minimumReaderVersion: PolicyFailureVersions.MinimumReader,
      outcome: PolicyFailureOutcomes.Blocked,
      details: [],
    }],
  }), (error: unknown) => {
    assert.ok(error instanceof MxcError);
    assert.equal(error.code, 'unsupported_containment');
    return true;
  });
});

it('V1.Dev prepares filesystem ceilings for caller-accepted strict creation', {
  skip: windows ? sandboxSkipReason : 'Windows ProcessContainer only',
  timeout: 90000,
}, async () => {
  const directory = createPrivateWindowsTempDir('mxc-policy-preparation', import.meta.dirname);
  try {
    const toolDirectory = path.join(directory, 'tools');
    const restrictedDirectory = path.join(directory, 'restricted-😀');
    const permittedDirectory = path.join(directory, 'permitted');
    for (const child of [toolDirectory, restrictedDirectory, permittedDirectory]) fs.mkdirSync(child);
    const workload = path.join(toolDirectory, 'workload.cmd');
    const toolFile = path.join(toolDirectory, 'tool-data.txt');
    const restrictedFile = path.join(restrictedDirectory, 'seed.txt');
    const permittedFile = path.join(permittedDirectory, 'sentinel.txt');
    const seed = 'RESTRICTED_SEED_UNCHANGED';
    const permittedSeed = 'PERMITTED_SEED';
    fs.writeFileSync(path.join(toolDirectory, 'pwsh.exe'), '');
    fs.writeFileSync(toolFile, 'PREPARATION_TOOL_READ_OK\r\n');
    fs.writeFileSync(restrictedFile, seed);
    fs.writeFileSync(permittedFile, permittedSeed);
    fs.writeFileSync(workload, [
      '@echo off',
      'setlocal EnableDelayedExpansion',
      'echo PREPARATION_READY',
      'set "INPUT="',
      'set /p INPUT=',
      'set "MODE=run"',
      'if defined INPUT set "MODE=spawn"',
      '(echo UNEXPECTED_RESTRICTED_WRITE) 2>nul >"%~1"',
      'rem Redirection denial may leave ERRORLEVEL unchanged; verify the seed instead.',
      'set "SEED="',
      'set /p SEED=<"%~1"',
      `if not "!SEED!"=="${seed}" exit /b 21`,
      'ver >nul',
      '>"%~2" echo PERMITTED_WRITE:!MODE!',
      'if errorlevel 1 exit /b 22',
      'ver >nul',
      'type "%~3"',
      'if errorlevel 1 exit /b 23',
      'if /i not "%CD%"=="%~4" exit /b 24',
      'echo PREPARATION_CWD_MATCHED',
      'echo PREPARATION_INPUT:!INPUT!',
      'echo PREPARATION_SEED:!SEED!',
      'echo PREPARATION_ENV:%MXC_PREPARATION_VALUE%',
      'echo PREPARATION_STDERR:!MODE! 1>&2',
      'exit /b 0',
    ].join('\r\n') + '\r\n');
    const tools = policy.filesystem.getAvailableToolsPolicy({
      PATH: toolDirectory,
      SystemDrive: path.parse(directory).root.replace(/\\$/, ''),
    }, { containerType: 'processcontainer' });
    assert.deepEqual(tools, { readonlyPaths: [toolDirectory], readwritePaths: [] });
    const request = {
      version: '1.1.0-alpha',
      containment: 'processcontainer',
      filesystem: { ...tools, readwritePaths: [restrictedDirectory, permittedDirectory] },
      ui: { disable: true },
      process: {
        commandLine: `cmd.exe /d /v:on /c ""${workload}" "${restrictedFile}" "${permittedFile}" "${toolFile}" "${restrictedDirectory}""`,
        timeout: 30000,
        inheritDefaultEnv: true,
        env: ['MXC_PREPARATION_VALUE=ORIGINAL_VALUE'],
      },
    };
    const failures: PolicyFailures = {
      formatVersion: PolicyFailureVersions.Format,
      results: [{
        version: PolicyFailureVersions.Result,
        minimumReaderVersion: PolicyFailureVersions.MinimumReader,
        outcome: PolicyFailureOutcomes.Blocked,
        details: [{
          failureClass: PolicyFailureClasses.Filesystem,
          failureReason: PolicyFailureReasons.AccessExceedsCeiling,
          requiredAction: PolicyFailureActions.RestrictFilesystemAccess,
          resourceKind: PolicyFailureResourceKinds.Path,
          valueKind: PolicyFailureValueKinds.Access,
          flags: PolicyFailureFlags.HasActionableDetails | PolicyFailureFlags.ResourceComplete,
          requestedValue: PolicyFailureAccessValues.ReadWrite,
          requiredValue: PolicyFailureAccessValues.ReadOnly,
          resource: restrictedDirectory,
        }],
      }],
    };
    const requestJson = JSON.stringify(request);
    const storedFailures = serializePolicyFailures(failures);
    const restoredFailures = parsePolicyFailures(storedFailures);
    assert.deepEqual(restoredFailures, failures);
    assert.equal(restoredFailures.results[0].details[0].resource, restrictedDirectory);
    const baseline = await runJson(requestJson);
    assert.equal(baseline.exitCode, 21, baseline.stderr);
    assert.match(fs.readFileSync(restrictedFile, 'utf8'), /UNEXPECTED_RESTRICTED_WRITE/);
    fs.writeFileSync(restrictedFile, seed);
    const prepared = await preparePolicyJson(requestJson, restoredFailures);
    assert.equal(JSON.stringify(request), requestJson);
    assert.equal(serializePolicyFailures(restoredFailures), storedFailures);
    assert.deepEqual(restoredFailures, failures);
    assert.equal(fs.readFileSync(restrictedFile, 'utf8'), seed);
    assert.equal(fs.readFileSync(permittedFile, 'utf8'), permittedSeed);
    assert.deepEqual([...prepared.changes].sort((left, right) => left.path.localeCompare(right.path)), [
      {
        operation: 'replace', path: '/filesystem/readonlyPaths',
        before: [toolDirectory], after: [toolDirectory, restrictedDirectory],
      },
      {
        operation: 'replace', path: '/filesystem/readwritePaths',
        before: [restrictedDirectory, permittedDirectory], after: [permittedDirectory],
      },
      { operation: 'add', path: '/process/cwd', before: null, after: restrictedDirectory },
    ]);
    assert.deepEqual(JSON.parse(prepared.requestJson), {
      ...request,
      filesystem: { readonlyPaths: [toolDirectory, restrictedDirectory], readwritePaths: [permittedDirectory] },
      process: { ...request.process, cwd: restrictedDirectory },
    });
    // The caller accepts this inspected candidate; creation receives no observations.
    const acceptedRequestJson = prepared.requestJson;
    const assertOutput = (stdout: string, stderr: string, input: string, mode: string) => {
      const lines = stdout.split(/\r?\n/).map((line) => line.trim());
      assert.ok(lines.includes('PREPARATION_READY'), stdout);
      assert.ok(lines.includes('PREPARATION_TOOL_READ_OK'), stdout);
      assert.ok(lines.includes('PREPARATION_CWD_MATCHED'), stdout);
      assert.ok(lines.includes(`PREPARATION_INPUT:${input.trim()}`), stdout);
      assert.ok(lines.includes(`PREPARATION_SEED:${seed}`), stdout);
      assert.ok(lines.includes('PREPARATION_ENV:ORIGINAL_VALUE'), stdout);
      assert.ok(stderr.includes(`PREPARATION_STDERR:${mode}`), stderr);
      assert.equal(fs.readFileSync(restrictedFile, 'utf8'), seed);
      assert.equal(fs.readFileSync(permittedFile, 'utf8').trim(), `PERMITTED_WRITE:${mode}`);
    };
    const captured = await runJson(acceptedRequestJson);
    assert.equal(captured.exitCode, 0, captured.stderr);
    assert.equal(captured.timedOut, false);
    assertOutput(captured.stdout, captured.stderr, '', 'run');
    fs.writeFileSync(permittedFile, permittedSeed);
    const spawned = await spawnJson(acceptedRequestJson);
    try {
      assert.ok(spawned.standardInput);
      assert.ok(spawned.standardOutput);
      assert.ok(spawned.standardError);
      const stdout = readAll(spawned.standardOutput);
      const stderr = readAll(spawned.standardError);
      const input = 'PREPARED_STDIN\r\n';
      spawned.standardInput.end(input);
      const outcome = await spawned.wait();
      const output = await stdout;
      const errors = await stderr;
      assert.equal(outcome.exitCode, 0, errors);
      assert.equal(outcome.timedOut, false);
      assertOutput(output, errors, input, 'spawn');
    } finally {
      spawned.dispose();
    }
    assert.equal(JSON.stringify(request), requestJson);
    assert.equal(serializePolicyFailures(restoredFailures), storedFailures);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
