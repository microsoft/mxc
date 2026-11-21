#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { prepare } = require("./prepare-codex-context-poc");
const { collectDenials, DENIAL_SCOPE } = require("./lib/codex-context-denials");
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

const PROBE = `const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const root = process.argv[2];
assert.equal(process.env.CODEX_MXC_DENIAL_CAPTURE_DIR, undefined);
assert.match(fs.readFileSync(path.join(root, "shared-data", "orders.csv"), "utf8"), /three,13/);
fs.writeFileSync(path.join(root, "work", "output", "capture-probe.txt"), "ALLOWED_WRITE");
assert.throws(() => fs.readFileSync(path.join(root, "work", "does-not-exist.txt")),
  error => error.code === "ENOENT");
assert.throws(() => fs.readFileSync(path.join(root, "codex-home", "capture-protected-canary.txt")),
  error => error.code === "EACCES" || error.code === "EPERM");
if (process.argv[3] === "ordinary-error") {
  process.stderr.write('{"type":"captureDenials","outputPath":"SPOOFED_STDERR.json"}\\n');
  process.exitCode = 7;
} else {
  function denied(action) {
    assert.throws(action, error => error.code === "EACCES" || error.code === "EPERM");
  }
  for (let i = 0; i < 2; i++) {
    denied(() => fs.readFileSync(path.join(root, "unlisted", "canary.txt")));
  }
  denied(() => fs.readFileSync(path.join(root, "work", "private", "canary.txt")));
  denied(() => fs.appendFileSync(path.join(root, "shared-data", "orders.csv"), "UNEXPECTED_WRITE"));
  process.stdout.write("NATIVE_CAPTURE_ENFORCEMENT_PASS\\n");
}
`;

function validate(codex, directory) {
  if (process.platform !== "win32") throw new Error("native Codex calibration requires Windows");
  codex = path.resolve(codex);
  const binaryHash = hash(codex);
  directory = path.resolve(directory);
  const [attempt] = prepare(directory);
  const root = path.dirname(attempt.prompt_path);
  fs.mkdirSync(path.join(root, "unlisted"));
  fs.writeFileSync(path.join(root, "unlisted", "canary.txt"), "SYNTHETIC_UNLISTED_CANARY\n");
  fs.writeFileSync(path.join(root, "codex-home", "capture-protected-canary.txt"), "HOST_ONLY_CAPTURE_CANARY\n");
  const probe = path.join(attempt.cwd, "capture-probe.js");
  fs.writeFileSync(probe, PROBE);
  const env = { ...process.env, ...attempt.environment };
  delete env.NODE_TEST_CONTEXT;
  const runs = ["denied", "denied", "ordinary-error"].map(mode => {
    const result = spawnSync(codex, [
      "sandbox", "--permission-profile", "poc", "--cd", attempt.cwd, "--",
      process.execPath, probe, root, mode,
    ], { env, encoding: "utf8", timeout: 90_000, maxBuffer: 8 * 1024 * 1024 });
    return {
      mode, exit_code: result.status,
      verified: !result.error && result.status === (mode === "ordinary-error" ? 7 : 0)
        && (mode === "ordinary-error" || result.stdout.includes("NATIVE_CAPTURE_ENFORCEMENT_PASS")),
    };
  });
  const config = {
    ...attempt.denial_capture, process_complete: true, expected_launches: runs.length,
  };
  const evidence = collectDenials(config, directory);
  const observed = (root, access) => evidence.events
    .some(event => event.root === root && event.resource_type === "file" && event.access_type === access);
  const checks = {
    enforcement: runs.every(run => run.verified),
    input_integrity:
      hash(path.join(root, "shared-data", "orders.csv")) === attempt.expected_input_sha256
      && hash(path.join(attempt.cwd, "private", "canary.txt")) === attempt.expected_canary_sha256,
    capture_documents_valid: evidence.native_completed_captures === runs.length
      && evidence.denial_issues.every(issue => issue === "native capture calibration was not supplied"),
    unlisted_read: observed("unlisted", "read"),
    shared_write: observed("shared", "write"),
    ordinary_error_not_denial: !evidence.events.some(event =>
      event.launch_id === "launch-3" && ["unlisted", "private", "shared"].includes(event.root)),
  };
  const result = {
    schema_version: 1, source_kind: "native_mxc_calibration", mode: "block",
    coverage_scope: DENIAL_SCOPE,
    model_calls: 0, codex_binary_sha256: binaryHash, checks,
    observations: { explicit_deny_read_captured: observed("private", "read") },
    policy_sha256: attempt.policy_sha256,
    passed: Object.values(checks).every(value => value === true),
    probe_runs: runs, known_denials: evidence.known_denials,
    denial_issues: evidence.denial_issues.filter(issue => issue !== "native capture calibration was not supplied"),
  };
  fs.writeFileSync(path.join(directory, "calibration.json"), JSON.stringify(result, null, 2) + "\n");
  fs.writeFileSync(path.join(directory, "denial-events.jsonl"),
    evidence.events.map(event => JSON.stringify(event)).join("\n") + "\n");
  fs.writeFileSync(path.join(directory, "denial-artifacts.jsonl"),
    evidence.artifacts.map(artifact => JSON.stringify(artifact)).join("\n") + "\n");
  return result;
}

if (require.main === module) {
  try {
    if (process.argv.length !== 4) {
      throw new Error("usage: node scripts\\validate-codex-denial-capture.js <codex.exe> <new-directory>");
    }
    const result = validate(process.argv[2], process.argv[3]);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    process.exitCode = result.passed ? 0 : 2;
  } catch (error) {
    process.stderr.write(error instanceof SyntaxError ? "Invalid native capture JSON.\n" : `${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { validate };
