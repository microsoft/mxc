'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const childProcess = require('node:child_process');
const { normalized, noAliases } = require('./candidates.cjs');
const { digest, loadReference } = require('./reference.cjs');
const { validateCaptureProbe } = require('./runtime.cjs');

const usage = 'Usage: node mxc-setup.cjs --sdk-prefix <absolute-project-or-tools-directory> | --sdk-root <absolute-package-directory> | --executable <absolute-wxc-exec-path>';

function fail(status, message) {
  const error = new Error(message);
  error.setupStatus = status;
  throw error;
}

function hostArchitecture(platform, machine) {
  if (platform !== 'win32') fail('blocked', 'This setup helper is only for the Windows ProcessContainer loop');
  const architecture = {
    arm64: 'arm64', aarch64: 'arm64', x64: 'x64', x86_64: 'x64', amd64: 'x64',
  }[machine.toLowerCase()];
  if (!architecture) fail('blocked', `Unsupported Windows host architecture: ${machine}`);
  return architecture;
}

function parseArgs(args) {
  if (args.length !== 2 || !['--sdk-prefix', '--sdk-root', '--executable'].includes(args[0])) {
    fail('blocked', usage);
  }
  normalized(args[1]);
  return { selector: args[0], location: args[1] };
}

function selectRuntime({ selector, location }, architecture) {
  noAliases(location);
  if (selector === '--executable') {
    return { mxcExecutable: location, source: { kind: 'explicit' } };
  }
  const root = selector === '--sdk-root' ? location :
    path.join(location, 'node_modules', '@microsoft', 'mxc-sdk');
  const manifestPath = path.join(root, 'package.json');
  noAliases(manifestPath);
  let text;
  try {
    text = fs.readFileSync(manifestPath, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    fail('sdk_missing', `SDK package metadata not found at ${manifestPath}; supply its exact location or approve a separate installation`);
  }
  let manifest;
  try {
    manifest = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch (error) {
    fail('blocked', `Invalid SDK package metadata at ${manifestPath}: ${error.message}`);
  }
  if (manifest?.name !== '@microsoft/mxc-sdk' ||
    typeof manifest.version !== 'string' || !manifest.version.trim() ||
    (manifest.engines?.node !== undefined && typeof manifest.engines.node !== 'string')) {
    fail('blocked', `Expected @microsoft/mxc-sdk package metadata at ${manifestPath}`);
  }
  return {
    mxcExecutable: path.join(root, 'bin', architecture, 'wxc-exec.exe'),
    source: {
      kind: 'sdk', package: manifest.name, version: manifest.version,
      packageRoot: root, nodeRequirement: manifest.engines?.node ?? null,
    },
  };
}

function tail(text) {
  return { text: text.slice(-4000), truncated: text.length > 4000 };
}

function inspectCommand(report, argument) {
  const result = childProcess.spawnSync(report.mxcExecutable, [argument], {
    cwd: report.runtimeDirectory, windowsHide: true, shell: false,
    encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
  });
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  report.diagnostics.push({
    argument, exitCode: result.status, signal: result.signal,
    error: result.error?.message ?? null, stdout: tail(stdout), stderr: tail(stderr),
  });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) {
    fail('incompatible_runtime', `${argument} failed; inspect diagnostics before choosing any replacement`);
  }
  return stdout;
}

function setup(args) {
  const report = { status: 'blocked', purpose: 'windows-processcontainer-loop', diagnostics: [] };
  try {
    const options = parseArgs(args);
    report.hostArchitecture = hostArchitecture(process.platform, os.machine());
    report.referenceDigest = loadReference().digest;
    Object.assign(report, selectRuntime(options, report.hostArchitecture));
    noAliases(report.mxcExecutable);
    let stat;
    try {
      stat = fs.statSync(report.mxcExecutable);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      fail('runtime_missing', `Executor not found at ${report.mxcExecutable}; no other location was searched`);
    }
    if (!stat.isFile()) fail('blocked', `Executor is not a file: ${report.mxcExecutable}`);
    report.runtimeDirectory = path.dirname(report.mxcExecutable);
    report.executableDigest = digest(fs.readFileSync(report.mxcExecutable));
    const help = inspectCommand(report, '--help');
    for (const flag of ['--config', '--dry-run', '--probe']) {
      if (!new RegExp(`${flag}\\b`).test(help)) {
        fail('incompatible_runtime', `Selected executor does not advertise ${flag}`);
      }
    }
    const text = inspectCommand(report, '--probe');
    try {
      report.hostProbe = JSON.parse(text.replace(/^\uFEFF/, ''));
      validateCaptureProbe(report.hostProbe, 'diagnostics and hostProbe in this setup result');
    } catch (error) {
      fail('incompatible_runtime', error.message);
    }
    if (digest(fs.readFileSync(report.mxcExecutable)) !== report.executableDigest) {
      fail('blocked', 'Selected executor changed during setup; no runtime was approved');
    }
    report.status = 'ready';
    report.reason = 'Capture compatibility checks passed; init must still validate the agreed baseline. No workload was executed.';
  } catch (error) {
    report.status = error.setupStatus ?? 'blocked';
    report.reason = error.message;
    report.errorCode = error.code ?? null;
  }
  return report;
}

if (require.main === module) {
  const result = setup(process.argv.slice(2));
  console.log(JSON.stringify(result, null, 2));
  if (result.status !== 'ready') process.exitCode = 1;
}

module.exports = { setup, hostArchitecture };
