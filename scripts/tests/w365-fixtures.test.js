// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");
const { stripVTControlCharacters } = require("node:util");

const root = resolve(__dirname, "..", "..");
const workflowName = "W365.Fixture.Test.Job.yml";
const workflow = readFileSync(join(root, ".github", "workflows", workflowName), "utf8");
const commonCases = [
  "loopback_tls_fixture_serves_both_address_families",
  "lifecycle_contract_and_recovery_fixture",
  "transport_deadlines_fixture",
  "readiness_contract_fixture",
  "execution::native_execution_streams_fixture",
  "execution::native_execution_backpressure_fixture",
  "execution::native_execution_failure_and_disposal_fixture",
  "execution::execution_upgrade_validation_fixture",
];

function fixtureStep() {
  const match = workflow.match(
    /      - name: Test W365 lifecycle and execution with trusted TLS fixtures\r?\n        run: \|\r?\n([\s\S]*?)\r?\n  result:/
  );
  assert.ok(match, "the native fixture step must exist");
  return match[1].replace(/^          /gm, "");
}

function runFixture(target, mode = "") {
  const directory = mkdtempSync(join(tmpdir(), "mxc-w365-ci-"));
  const script = join(directory, "fixture.ps1");
  const windows = target.endsWith("-windows-msvc");
  const cases = [
    ...commonCases,
    ...(windows
      ? ["lifecycle_fresh_executor_fixture", "execution::execution_fresh_executor_fixture"]
      : ["execution::execution_host_output_fixture"]),
  ];
  writeFileSync(script, `
$ErrorActionPreference = 'Stop'
$global:cases = @($env:MXC_CI_W365_CASES | ConvertFrom-Json)
function global:cargo {
    $arguments = @($args)
    foreach ($required in '--locked', '--target', '--target-dir', '--features', 'test-support') {
        if ($arguments -notcontains $required) { throw "Missing Cargo argument: $required" }
    }
    $targetIndex = [Array]::IndexOf($arguments, '--target')
    if ($arguments[$targetIndex + 1] -ne $env:MXC_CI_W365_TARGET) { throw 'Wrong target' }
    $directoryIndex = [Array]::IndexOf($arguments, '--target-dir')
    if ($arguments[$directoryIndex + 1] -ne 'target/w365-fixture') { throw 'Fixture build is not isolated' }
    $global:LASTEXITCODE = 0
    if ($arguments[0] -eq 'build') {
        Write-Output "MOCK_BUILD $arguments"
        if ($env:MXC_CI_W365_MODE -eq 'build-failure') {
            $global:LASTEXITCODE = 17
            return
        }
        if ($arguments -contains 'wxc') {
            $bin = Join-Path 'target/w365-fixture' "$env:MXC_CI_W365_TARGET/debug"
            New-Item -ItemType Directory -Path $bin -Force | Out-Null
            New-Item -ItemType File -Path (Join-Path $bin 'wxc-exec.exe') | Out-Null
        } elseif ($arguments -notcontains 'w365_execution') {
            throw 'Unexpected build target'
        }
        return
    }
    if ($arguments -notcontains 'w365_lifecycle') { throw 'Wrong integration target' }
    if ($arguments -contains '--list') {
        if ($env:MXC_CI_W365_MODE -eq 'discovery-failure') {
            $global:LASTEXITCODE = 19
            return
        }
        foreach ($case in $global:cases) {
            if ($env:MXC_CI_W365_MODE -ne 'missing-discovery' -or $case -ne $global:cases[-1]) {
                Write-Output "\${case}: test"
            }
        }
        return
    }
    foreach ($required in '--include-ignored', '--format', 'pretty', '--color', 'never') {
        if ($arguments -notcontains $required) { throw "Missing test argument: $required" }
    }
    if ($env:MXC_CI_W365_TARGET.EndsWith('-windows-msvc') -and
        -not (Test-Path $env:MXC_W365_TEST_EXECUTOR)) { throw 'Fixture executor was not selected' }
    Write-Output 'MOCK_EXECUTED'
    if ($env:MXC_CI_W365_MODE -eq 'empty-results') { return }
    foreach ($case in $global:cases) {
        if ($case -eq $global:cases[-1]) {
            if ($env:MXC_CI_W365_MODE -eq 'missing-result') { continue }
            if ($env:MXC_CI_W365_MODE -eq 'ignored-result') {
                Write-Output "test $case ... ignored"
                continue
            }
        }
        Write-Output "test $case ... ok"
    }
    if ($env:MXC_CI_W365_MODE -eq 'test-failure') { $global:LASTEXITCODE = 23 }
}
${fixtureStep().replaceAll("${{ matrix.target }}", target)}
`);
  try {
    const result = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-File", script], {
      cwd: directory,
      env: {
        ...process.env,
        MXC_CI_W365_CASES: JSON.stringify(cases),
        MXC_CI_W365_TARGET: target,
        MXC_CI_W365_MODE: mode,
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.ifError(result.error);
    return {
      status: result.status,
      output: stripVTControlCharacters(result.stdout + result.stderr),
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("native fixture coverage retains every build host and stays off artifact dependencies", () => {
  const lanes = [...workflow.matchAll(/- runner: (\S+)\r?\n +target: (\S+)/g)]
    .map(([, runner, target]) => [runner, target]);
  assert.deepEqual(lanes, [
    ["windows-2025", "x86_64-pc-windows-msvc"],
    ["windows-11-arm", "aarch64-pc-windows-msvc"],
    ["ubuntu-24.04", "x86_64-unknown-linux-gnu"],
    ["ubuntu-26.04", "x86_64-unknown-linux-gnu"],
    ["ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"],
    ["ubuntu-26.04-arm", "aarch64-unknown-linux-gnu"],
    ["macos-15", "aarch64-apple-darwin"],
  ]);
  for (const entry of ["Build.yml", "Validation.Tests.Scheduled.yml"]) {
    const text = readFileSync(join(root, ".github", "workflows", entry), "utf8");
    const caller = text.match(/^  w365-fixture-tests:\r?\n((?:    [^\r\n]*(?:\r?\n|$))+)/m);
    assert.ok(caller, `${entry} must run W365 fixtures`);
    assert.match(caller[1], /needs: dependency-feed-check/);
    assert.ok(caller[1].includes(`uses: ./.github/workflows/${workflowName}`));
    assert.doesNotMatch(text, /needs:[^\r\n]*w365-fixture-tests/);
  }
  for (const platform of ["Windows", "Linux", "MacOS"]) {
    const build = readFileSync(join(root, ".github", "workflows", `Build.${platform}.Job.yml`), "utf8");
    assert.doesNotMatch(build, /w365-fixture|--test w365_lifecycle/);
  }
  const manifest = readFileSync(join(root, "src", "mxc-sdk", "Cargo.toml"), "utf8");
  assert.match(manifest, /\[\[test\]\]\r?\nname = "w365_lifecycle"\r?\npath = "tests\/w365_lifecycle.rs"\r?\nrequired-features = \["test-support"\]/);
  const result = workflow.slice(workflow.indexOf("\n  result:"));
  assert.match(result, /name: W365 fixtures/);
  assert.match(result, /needs: fixture-tests/);
  assert.match(result, /if: \$\{\{ always\(\) \}\}/);
  assert.match(result, /FIXTURE_RESULT: \$\{\{ needs.fixture-tests.result \}\}/);
  assert.match(result, /test "\$FIXTURE_RESULT" = success/);
});

for (const target of [
  "x86_64-pc-windows-msvc",
  "aarch64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "aarch64-apple-darwin",
]) {
  test(`fixture step builds isolated helpers and requires every ${target} case to pass`, () => {
    const result = runFixture(target);
    assert.equal(result.status, 0, result.output);
    assert.match(result.output, /MOCK_BUILD .*--example w365_execution/);
    assert.equal((result.output.match(/MOCK_EXECUTED/g) || []).length, 1);
    assert.equal(/MOCK_BUILD .* -p wxc /.test(result.output), target.endsWith("-windows-msvc"));
  });
}

for (const [mode, error] of [
  ["build-failure", /Building the W365 fixture executor failed/],
  ["discovery-failure", /Listing W365 fixtures failed/],
  ["missing-discovery", /Missing required W365 fixture/],
  ["test-failure", /W365 fixtures failed/],
  ["missing-result", /Required W365 fixture did not pass/],
  ["ignored-result", /Required W365 fixture did not pass/],
  ["empty-results", /Required W365 fixture did not pass/],
]) {
  test(`fixture step rejects ${mode}`, () => {
    const result = runFixture("x86_64-pc-windows-msvc", mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, error);
  });
}

test("Unix fixture discovery requires the host-output regression", () => {
  const result = runFixture("x86_64-unknown-linux-gnu", "missing-discovery");
  assert.notEqual(result.status, 0, result.output);
  assert.match(result.output, /Missing required W365 fixture: execution::execution_host_output_fixture/);
});

test("Windows workspace suites preserve release features and run independently of packaging", () => {
  const tests = readFileSync(join(root, ".github", "workflows", "Test.Windows.Job.yml"), "utf8");
  const builds = readFileSync(join(root, ".github", "workflows", "Build.Windows.Job.yml"), "utf8");
  const shared = readFileSync(join(root, ".github", "workflows", "Build.Windows.Shared.Job.yml"), "utf8");
  const matrix = (text) => [...text.matchAll(
    /- arch: (\S+)\r?\n +runner: (\S+)\r?\n +target: (\S+)\r?\n(?: +#.*\r?\n)* +features: ([^\r\n]+)/g
  )].map(([, arch, runner, target, features]) => ({ arch, runner, target, features }));
  assert.equal(matrix(tests).length, 2);
  assert.deepEqual(matrix(tests), matrix(builds));
  assert.deepEqual(matrix(tests), matrix(shared));
  assert.match(tests, /MXC_W365_TEST_OPENSSL=\$openssl/);
  assert.match(shared, /Force hyperlight-host rebuild/);
  for (const consumer of [tests, builds]) {
    assert.match(consumer, /name: windows-build-snapshot-\$\{\{ matrix.target \}\}/);
    assert.match(consumer, /cargo-build-snapshot\.ps1 -Mode Restore/);
    assert.doesNotMatch(consumer, /cargo clean/);
  }
  const commands = [...tests.matchAll(
    /      - name: (Build|Build module lifetime regression fixture|Test)\r?\n        run: ([\s\S]*?)(?=\r?\n\r?\n|$)/g
  )].map(([, name, command]) => [name, command.replace(/\s+/g, " ").trim()]);
  assert.deepEqual(commands, [
    ["Build", 'cargo build --locked --release --target ${{ matrix.target }} --no-default-features --features "${{ matrix.features }}"'],
    ["Build module lifetime regression fixture", 'cargo build --locked --release --target ${{ matrix.target }} -p mxc-sdk --example module_lifetime_fixture --no-default-features --features "${{ matrix.features }}"'],
    ["Test", 'cargo test --locked --release --target ${{ matrix.target }} --no-default-features --features "${{ matrix.features }}"'],
  ]);
  assert.doesNotMatch(builds, /- name: Test\r?\n/);
  assert.match(tests, /needs: test\r?\n +if: \$\{\{ always\(\) \}\}/);
  assert.match(tests, /TEST_RESULT: \$\{\{ needs.test.result \}\}/);
  assert.match(tests, /test "\$TEST_RESULT" = success/);
  for (const entry of ["Build.yml", "Validation.Tests.Scheduled.yml"]) {
    const text = readFileSync(join(root, ".github", "workflows", entry), "utf8");
    const caller = text.match(/^  windows-workspace-tests:\r?\n((?:    [^\r\n]*(?:\r?\n|$))+)/m);
    assert.ok(caller, `${entry} must run both Windows workspace suites`);
    assert.match(caller[1], /needs: windows-build/);
    assert.match(caller[1], /uses: \.\/\.github\/workflows\/Test\.Windows\.Job\.yml/);
    assert.doesNotMatch(text, /needs:[^\r\n]*windows-workspace-tests/);
    assert.match(text, /windows-build:\r?\n +needs: dependency-feed-check\r?\n +uses: \.\/\.github\/workflows\/Build\.Windows\.Shared\.Job\.yml/);
  }
});

test("default release telemetry tests run once per architecture off the artifact path", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "Build.Windows.Job.yml"), "utf8");
  const [artifact, telemetry] = workflow.split("\n  telemetry-component-check:");
  assert.ok(telemetry, "the native telemetry lanes must exist");
  assert.doesNotMatch(artifact, /--lib mxc_common::telemetry::(?:consent|policy)/);
  const step = telemetry.match(
    /      - name: Test telemetry consent and policy in release mode\r?\n([\s\S]*?)(?=\r?\n  result:)/
  );
  assert.ok(step, "both default-feature release checks must remain required");
  assert.match(step[1], /working-directory: src/);
  assert.match(step[1], /CARGO_TARGET_DIR: target\/telemetry-component-check/);
  for (const module of ["consent", "policy"]) {
    const command = "cargo test --locked --release --target " +
      "${{ matrix.target }} -p mxc-sdk --lib mxc_common::telemetry::" + module;
    assert.equal(workflow.split(command).length - 1, 1, `${module} must run exactly once per matrix host`);
  }
  assert.doesNotMatch(step[1], /--features|--all-features|--no-default-features/);
  assert.match(telemetry, /runner: windows-2025\r?\n +target: x86_64-pc-windows-msvc/);
  assert.match(telemetry, /runner: windows-11-arm\r?\n +target: aarch64-pc-windows-msvc/);
  assert.match(workflow, /needs: \[build, telemetry-component-check\]\r?\n +if: \$\{\{ always\(\) \}\}/);
  assert.match(workflow, /test "\$ARTIFACT_RESULT" = success/);
  assert.match(workflow, /test "\$TELEMETRY_RESULT" = success/);
});

test("Windows workspace consumers cache compiled dependencies for their test feature variants", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "Test.Windows.Job.yml"), "utf8");
  const cache = workflow.match(
    /      - uses: Swatinem\/rust-cache@[^\r\n]+\r?\n([\s\S]*?)(?=\r?\n      - name:)/
  );
  assert.ok(cache);
  assert.match(cache[1], /workspaces: src -> target/);
  assert.match(cache[1], /key: windows-tests-\$\{\{ matrix.target \}\}-v2/);
  assert.match(cache[1], /cache-targets: true/);
  assert.match(cache[1], /cache-on-failure: false/);
  assert.doesNotMatch(cache[1], /cache-(?:all|workspace)-crates: true/);
  assert.ok(workflow.indexOf("Restore shared Windows build") > workflow.indexOf(cache[0]),
    "restore compatible same-run production outputs after the consumer dependency cache");
});

test("shared Windows builds and every consumer select the same pinned linker before caching", () => {
  for (const name of ["Build.Windows.Shared.Job.yml", "Test.Windows.Job.yml", "Build.Windows.Job.yml"]) {
    const workflow = readFileSync(join(root, ".github", "workflows", name), "utf8");
    const jobs = name === "Build.Windows.Job.yml"
      ? workflow.split("\n  telemetry-component-check:") : [workflow];
    for (const job of jobs) {
      const setup = job.indexOf("uses: ./.github/actions/setup-windows-linker");
      const cache = job.indexOf("uses: Swatinem/rust-cache");
      assert.ok(setup >= 0 && cache > setup, `${name} must configure its linker before cache selection`);
      assert.match(job.slice(setup), /target: \$\{\{ matrix.target \}\}/);
    }
  }
});

test("shared Windows snapshots transfer compressed data and its bound metadata without recompression", () => {
  const shared = readFileSync(join(root, ".github", "workflows", "Build.Windows.Shared.Job.yml"), "utf8");
  assert.match(shared, /windows-build\.tar\.zst\r?\n +\$\{\{ runner.temp \}\}\/windows-build\.tar\.zst\.json/);
  assert.match(shared, /compression-level: 0/);
  for (const name of ["Test.Windows.Job.yml", "Build.Windows.Job.yml"]) {
    const consumer = readFileSync(join(root, ".github", "workflows", name), "utf8");
    assert.ok(consumer.includes("windows-build\\windows-build.tar.zst"), name);
  }
});

test("Windows Node versions share one early native fixture build without changing Unix hosts", () => {
  const build = readFileSync(join(root, ".github", "workflows", "Build.yml"), "utf8");
  const producer = readFileSync(join(root, ".github", "workflows", "W365.Node.Fixture.Build.Job.yml"), "utf8");
  const integration = readFileSync(join(root, ".github", "workflows", "SDK.Integration.Test.Job.yml"), "utf8");
  assert.match(build, /w365-node-fixture-build:\r?\n +needs: dependency-feed-check\r?\n +uses: .*W365.Node.Fixture.Build.Job.yml/);
  assert.match(build, /sdk-integration-tests:\r?\n +needs: \[package-lock-check, package-npm-sdk, w365-node-fixture-build\]\r?\n +if: \$\{\{ always\(\) && !cancelled\(\) \}\}/);
  assert.match(build, /windows-fixture-result: \$\{\{ needs.w365-node-fixture-build.result \}\}/);
  assert.match(integration, /FIXTURE_RESULT: \$\{\{ inputs.windows-fixture-result \}\}/);
  assert.match(integration, /if \(\$env:FIXTURE_RESULT -ne 'success'\) \{\r?\n +throw "Windows fixture producer did not succeed:/);
  assert.match(producer, /runs-on: windows-latest/);
  assert.match(producer, /run-w365-node-fixture.ps1 -BuildOnly/);
  assert.match(producer, /workspaces: src -> target\/w365-sdk-fixture/);
  assert.match(producer, /name: w365-node-fixture-windows/);
  assert.match(producer, /path: src\/target\/w365-sdk-fixture\/debug\/mxc_ffi.dll/);
  assert.match(producer, /if-no-files-found: error/);
  assert.doesNotMatch(producer, /--release|setup-windows-linker/);
  assert.match(integration, /setup-rust-toolchain@[^\r\n]+\r?\n +if: matrix.os_label != 'windows'/);
  assert.match(integration, /name: Download the shared Windows native fixture\r?\n +if: matrix.os_label == 'windows'/);
  assert.match(integration, /run-w365-node-fixture.ps1 -NativeDirectory/);
  assert.match(integration, /name: Test W365 Dev JSON with an isolated native TLS fixture\r?\n +if: matrix.os_label != 'windows'/);
  const lanes = [...integration.matchAll(
    /- name_label: (\S+)\r?\n +os_label: (\S+)\r?\n +runner: (\S+)\r?\n +node_version: (\S+)/g
  )].map(([, name, os, runner, node]) => [name, os, runner, node]);
  assert.deepEqual(lanes, [
    ["windows-node24", "windows", "windows-latest", "24.21.0"],
    ["windows-node26", "windows", "windows-latest", "26.8.0"],
    ["linux-ubuntu24.04", "linux", "ubuntu-24.04", "24"],
    ["linux-ubuntu26.04", "linux", "ubuntu-26.04", "24"],
    ["macos", "macos", "macos-26", "24"],
  ]);
});

function runNodeFixture(mode) {
  const directory = mkdtempSync(join(tmpdir(), "mxc-node-fixture-"));
  const helper = join(directory, "scripts", "ci", "run-w365-node-fixture.ps1");
  mkdirSync(join(directory, "scripts", "ci"), { recursive: true });
  mkdirSync(join(directory, "src"));
  mkdirSync(join(directory, "sdk", "node", "tests", "integration", "dist"), { recursive: true });
  copyFileSync(join(root, "scripts", "ci", "run-w365-node-fixture.ps1"), helper);
  writeFileSync(join(directory, "sdk", "node", "tests", "integration", "dist", "w365-fixture.js"), "");
  const script = join(directory, "test.ps1");
  writeFileSync(script, `
$ErrorActionPreference = 'Stop'
$global:builds = 0
$global:tests = 0
$library = if ($IsWindows) { 'mxc_ffi.dll' } elseif ($IsMacOS) { 'libmxc_ffi.dylib' } else { 'libmxc_ffi.so' }
$prebuilt = Join-Path $PSScriptRoot 'downloaded fixture'
New-Item -ItemType Directory -Path $prebuilt | Out-Null
if ($env:MXC_NODE_FIXTURE_MODE -eq 'prebuilt') {
    New-Item -ItemType File -Path (Join-Path $prebuilt $library) | Out-Null
}
function global:cargo {
    if ($env:MXC_NODE_FIXTURE_MODE -in @('prebuilt', 'missing-prebuilt')) { throw 'Prebuilt consumer invoked Cargo' }
    $global:builds++
    $arguments = @($args)
    foreach ($required in 'build', '--locked', '-p', 'mxc_ffi', '--features', 'test-support', '--target-dir') {
        if ($arguments -notcontains $required) { throw "Missing Cargo argument: $required" }
    }
    if ($arguments -contains '--release') { throw 'Fixture profile changed' }
    $global:LASTEXITCODE = 0
    if ($env:MXC_NODE_FIXTURE_MODE -eq 'build-failure') { $global:LASTEXITCODE = 17; return }
    if ($env:MXC_NODE_FIXTURE_MODE -eq 'missing-output') { return }
    $bin = Join-Path $arguments[-1] 'debug'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $bin $library) | Out-Null
}
function global:node {
    $global:tests++
    if ("$args" -ne '--test dist/w365-fixture.js') { throw 'Wrong fixture selection' }
    if (-not (Test-Path -LiteralPath (Join-Path $env:MXC_FFI_DIR $library))) { throw 'Wrong fixture library' }
    if ($env:MXC_NODE_FIXTURE_MODE -eq 'prebuilt' -and $env:MXC_FFI_DIR -ne $prebuilt) { throw 'Downloaded fixture was not selected' }
    $global:LASTEXITCODE = if ($env:MXC_NODE_FIXTURE_MODE -eq 'test-failure') { 23 } else { 0 }
}
$env:MXC_FFI_DIR = 'original-ffi'
$env:MXC_W365_TEST_OPENSSL = 'original-openssl'
$failed = $false
try {
    if ($env:MXC_NODE_FIXTURE_MODE -in @('prebuilt', 'missing-prebuilt')) {
        & '${helper.replaceAll("'", "''")}' -NativeDirectory $prebuilt
    } elseif ($env:MXC_NODE_FIXTURE_MODE -eq 'build-only') {
        & '${helper.replaceAll("'", "''")}' -BuildOnly
    } else {
        & '${helper.replaceAll("'", "''")}'
    }
} catch {
    $failed = $true
    Write-Output $_.Exception.Message
}
if ($env:MXC_FFI_DIR -ne 'original-ffi' -or $env:MXC_W365_TEST_OPENSSL -ne 'original-openssl') { throw 'Caller environment changed' }
Write-Output "COUNTS builds=$global:builds tests=$global:tests"
if ($failed) { exit 1 }
`);
  try {
    const result = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-File", script], {
      cwd: directory,
      env: { ...process.env, MXC_NODE_FIXTURE_MODE: mode },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.ifError(result.error);
    return { status: result.status, output: stripVTControlCharacters(result.stdout + result.stderr) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("Windows Node consumers reject unsuccessful producers even with a retained artifact", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "SDK.Integration.Test.Job.yml"), "utf8");
  const step = workflow.match(
    /      - name: Require the Windows fixture producer to succeed[\s\S]*?        run: \|\r?\n([\s\S]*?)(?=\r?\n      - uses:)/
  );
  assert.ok(step);
  for (const conclusion of ["success", "failure", "cancelled", "skipped"]) {
    const result = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-Command", step[1].replace(/^          /gm, "")], {
      env: { ...process.env, FIXTURE_RESULT: conclusion },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status === 0, conclusion === "success", result.stdout + result.stderr);
    if (conclusion !== "success") {
      assert.match(stripVTControlCharacters(result.stderr), /Windows fixture producer did not succeed:/);
    }
  }
});

for (const [mode, status, expected] of [
  ["default", 0, /COUNTS builds=1 tests=1/],
  ["build-only", 0, /COUNTS builds=1 tests=0/],
  ["prebuilt", 0, /COUNTS builds=0 tests=1/],
  ["missing-prebuilt", 1, /W365 Node fixture native library missing:/],
  ["missing-output", 1, /W365 Node fixture native library missing:/],
  ["build-failure", 1, /W365 Node fixture native build failed/],
  ["test-failure", 1, /W365 Node Dev JSON fixture failed/],
]) {
  test(`Node fixture helper preserves isolation, errors and environment in ${mode} mode`, () => {
    const result = runNodeFixture(mode);
    assert.equal(result.status, status, result.output);
    assert.match(result.output, expected);
    assert.doesNotMatch(result.output, /Caller environment changed|Prebuilt consumer invoked Cargo/);
  });
}
