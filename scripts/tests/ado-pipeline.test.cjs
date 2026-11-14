// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { after, test } = require("node:test");
const assert = require("node:assert/strict");
const { mkdtempSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");

const root = resolve(__dirname, "..", "..");
const scratch = mkdtempSync(join(tmpdir(), "mxc-ado-pipeline-"));
const bash = process.platform === "win32"
  ? join(process.env.ProgramFiles, "Git", "bin", "bash.exe")
  : "bash";
const integration = readFileSync(
  join(root, ".azure-pipelines", "templates", "SDK.Integration.Test.Job.yml"),
  "utf8"
);

after(() => rmSync(scratch, { recursive: true, force: true }));

test("integration installation matches the lockfile and stops on npm failures", () => {
  const match = integration.match(
    /      - pwsh: \|\r?\n((?:          .*\r?\n)+)        workingDirectory: .*?\r?\n        displayName: Install dependencies and SDK from artifact/
  );
  assert.ok(match, "the packed SDK installation step must be present");
  writeFileSync(join(scratch, "sdk.tgz"), "fixture");
  const script = join(scratch, "install.ps1");
  const mock = `
function npm {
    if ($args[0] -eq 'ci') {
        if ($args -notcontains '--install-links') { throw 'npm ci must match the packed file dependency lockfile' }
        $global:LASTEXITCODE = [int]$env:MXC_CI_NPM_EXIT
    } elseif ($args[0] -eq 'install') {
        Write-Output SDK_INSTALLED
        $global:LASTEXITCODE = [int]$env:MXC_CI_NPM_INSTALL_EXIT
    } else { throw 'Unexpected npm command' }
}
`;
  writeFileSync(script, mock + match[1].replace(/^          /gm, "")
    .replaceAll("$(sdkPkgDirectory)", scratch.replaceAll("'", "''")));
  for (const [ciExit, installExit] of [[0, 0], [17, 0], [0, 19]]) {
    const result = spawnSync("pwsh", ["-NoProfile", "-File", script], {
      cwd: root,
      env: {
        ...process.env,
        MXC_CI_NPM_EXIT: String(ciExit),
        MXC_CI_NPM_INSTALL_EXIT: String(installExit),
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.ifError(result.error);
    const output = result.stdout + result.stderr;
    assert.equal(result.status, ciExit || installExit, output);
    assert.equal(output.includes("SDK_INSTALLED"), ciExit === 0, output);
  }
});

test("Linux integration keeps the selected Node toolchain through sudo", () => {
  const match = integration.match(
    /        - script: (.*(?:\r?\n            .*)*)\r?\n          workingDirectory: .*?\r?\n          displayName: npm test \(sudo, with LXC\)/
  );
  assert.ok(match, "the Linux integration step must be present");
  const script = match[1].replace(/^\|\r?\n/, "").replace(/^            /gm, "")
    .replaceAll("${{ parameters.debug }}", "false");
  const mock = `
set -euo pipefail
selected="$(mktemp -d)"
trap 'rm -f "$selected/npm"; rmdir "$selected"' EXIT
printf '%s\\n' '#!/bin/sh' 'test "$1" = test && test "$MXC_SKIP_LXC_NETWORK_TESTS" = 1 && test "$MXC_DEBUG" = false && echo SELECTED_NODE_TOOLCHAIN' > "$selected/npm"
chmod +x "$selected/npm"
export PATH="$selected:$PATH"
sudo() {
  [[ "$1" == env ]] || { echo 'sudo must explicitly preserve the selected PATH' >&2; return 91; }
  /usr/bin/env PATH=/usr/bin:/bin "$@"
}
`;
  const result = spawnSync(bash, ["-s"], {
    input: mock + script + "\n",
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /SELECTED_NODE_TOOLCHAIN/);
});

test("ARM64 dependency setup uses permitted mirrors and propagates update failures", () => {
  const pipeline = readFileSync(
    join(root, ".azure-pipelines", "templates", "Rust.Build.Job.yml"),
    "utf8"
  );
  const match = pipeline.match(
    /      - script: \|\r?\n((?:          .*\r?\n)+)        displayName: Install ARM64 toolchain and target OpenSSL/
  );
  assert.ok(match, "the ARM64 setup step must be present");
  const script = match[1].replace(/^          /gm, "");
  const mock = `
function . {
  [[ "$1" == /etc/os-release ]] || return 91
  VERSION_CODENAME=jammy
}
sudo() {
  case "$*" in
    "apt-get install -y gcc-aarch64-linux-gnu") return 0 ;;
    "dpkg --add-architecture arm64") return 0 ;;
  esac
  [[ "$1" == apt-get ]] || return 92
  shift
  local sources=
  for arg in "$@"; do
    case "$arg" in Dir::Etc::sourcelist=*) sources="\${arg#*=}" ;; esac
  done
  [[ -f "$sources" && " $* " == *" Dir::Etc::sourceparts=- "* ]] || return 93
  if [[ "\${!#}" == update ]]; then
    while IFS= read -r line; do
      case "$line" in
        "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://azure.archive.ubuntu.com/ubuntu "*) ;;
        "deb [arch=arm64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://ports.ubuntu.com/ubuntu-ports "*) ;;
        *) echo "Network isolation or signature policy rejected: $line" >&2; return 100 ;;
      esac
      echo "SOURCE $line"
    done < "$sources"
    [[ "$FIXTURE_FAIL_UPDATE" != 1 ]] || return 100
  elif [[ " $* " == *" install -y --no-install-recommends libssl-dev:arm64 " ]]; then
    echo ARM64_OPENSSL_INSTALLED
  else
    return 94
  fi
}
`;
  for (const failUpdate of ["0", "1"]) {
    const result = spawnSync(bash, ["-s"], {
      input: mock + script,
      env: { ...process.env, FIXTURE_FAIL_UPDATE: failUpdate },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.ifError(result.error);
    const output = result.stdout + result.stderr;
    assert.equal(result.status, failUpdate === "1" ? 100 : 0, output);
    assert.equal(result.stdout.includes("ARM64_OPENSSL_INSTALLED"), failUpdate === "0", output);
    assert.equal((result.stdout.match(/^SOURCE /gm) ?? []).length, 6, output);
  }
});
