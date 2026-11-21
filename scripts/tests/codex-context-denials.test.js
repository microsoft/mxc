// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { collectDenials, DENIAL_SCOPE } = require("../lib/codex-context-denials");
const { collectManifest, comparisonCsv } = require("../lib/codex-context-usage");
const { validate } = require("../validate-codex-denial-capture");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-native-denials-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const capture = path.join(directory, "native");
  fs.mkdirSync(capture);
  const calibration = {
    schema_version: 1, source_kind: "native_mxc_calibration", mode: "block", passed: true,
    coverage_scope: DENIAL_SCOPE,
    codex_binary_sha256: "a".repeat(64),
    policy_sha256: "1".repeat(64),
    checks: {
      enforcement: true, input_integrity: true, capture_documents_valid: true,
      unlisted_read: true, shared_write: true, ordinary_error_not_denial: true,
    },
    observations: { explicit_deny_read_captured: false },
  };
  const calibrationPath = path.join(directory, "calibration.json");
  fs.writeFileSync(calibrationPath, JSON.stringify(calibration));
  const config = {
    directory: capture, process_complete: true, expected_launches: 0,
    calibration_path: calibrationPath, codex_binary_sha256: "a".repeat(64),
    policy_sha256: "1".repeat(64),
    roots: { private: "C:\\fixture\\private", shared: "C:\\fixture\\shared" },
  };
  const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value));
  function launch(readCount = 0, writeCount = 0) {
    config.expected_launches++;
    // Deliberately reverse PID order; receipt timestamps determine chronology.
    const root = path.join(capture, `launch-${100 - config.expected_launches}-${config.expected_launches}`);
    fs.mkdirSync(root);
    const policyPath = path.join(root, "denials.synthetic_1.json");
    const policy = { denials: [], summary: {
      exitCode: 0, totalDenials: 0, deniedResourcesTruncated: false,
    } };
    const verbose = { version: 6, signatures: [], summary: {
      totalOccurrences: readCount + writeCount, overflowOccurrences: 0,
      actionableOverflowOccurrences: 0, aggregateGroupsTruncated: false,
      processedEventsTruncated: false, actionableLimitReached: false,
    } };
    for (const [access, count, resource] of [
      ["read", readCount, "C:\\fixture\\private\\PRIVATE_PATH.txt"],
      ["write", writeCount, "C:\\fixture\\shared\\PRIVATE_INPUT.csv"],
    ]) {
      if (!count) continue;
      policy.denials.push({ resource, resourceType: "file", accessType: access,
        pid: 98765, filetime: "134000000000000000" });
      verbose.signatures.push({ count, signature: {
        reason: "actionable", resourceType: "file", accessType: access,
        properties: [["Secret", "PRIVATE_DIAGNOSTIC"]],
      } });
    }
    policy.summary.totalDenials = policy.denials.length;
    const started = { schema_version: 1, backend: "process_container", mode: "block" };
    const finished = { ...started, wait_succeeded: true, capture_failed: false,
      capture: { type: "captureDenials", outputPath: policyPath, ...policy.summary } };
    const files = {
      started: path.join(root, "started.json"), finished: path.join(root, "completed.json"),
      policy: policyPath, verbose: policyPath.replace(/\.json$/, ".verbose.json"),
    };
    const save = () => {
      for (const [key, value] of Object.entries({ started, finished, policy, verbose })) {
        write(files[key], value);
      }
    };
    save();
    return { started, finished, policy, verbose, files, save };
  }
  return { directory, config, calibration, calibrationPath, launch, write };
}

test("native occurrences, unique resources and repeat launches are separate and redacted", t => {
  const f = fixture(t);
  f.launch(3, 1);
  const second = f.launch(5);
  second.policy.denials[0].resource = "\\\\?\\c:\\FIXTURE\\PRIVATE\\PRIVATE_PATH.txt";
  second.save();
  const result = collectDenials(f.config, f.directory);
  assert.equal(result.denial_capture_complete, true);
  assert.equal(result.filesystem_read_denial_occurrences, 8);
  assert.equal(result.filesystem_write_denial_occurrences, 1);
  assert.equal(result.filesystem_unique_read_resources, 1);
  assert.equal(result.repeated_read_resource_launches, 1);
  assert.equal(result.repeated_read_root_launches, 1);
  assert.equal(result.events[0].resource_id, result.events[2].resource_id);
  assert.equal(result.events[0].root, "private");
  assert.match(result.artifacts[0].policy_sha256, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(result).includes("PRIVATE"));
  assert.ok(!JSON.stringify(result).includes("98765"));
});

test("only complete native evidence can establish zero denials", t => {
  assert.equal(collectDenials(null, ".").filesystem_read_denial_occurrences, null);
  const f = fixture(t);
  f.launch();
  const complete = collectDenials(f.config, f.directory);
  assert.equal(complete.denial_capture_complete, true);
  assert.equal(complete.filesystem_read_denial_occurrences, 0);
  fs.rmSync(f.calibrationPath);
  const missing = collectDenials(f.config, f.directory);
  assert.equal(missing.denial_capture_complete, false);
  assert.equal(missing.filesystem_read_denial_occurrences, null);
});

test("failed, truncated, uncalibrated or mismatched native evidence stays incomplete", t => {
  for (const mutate of [
    f => { f.config.process_complete = false; },
    f => { f.config.expected_launches++; },
    f => { f.config.codex_binary_sha256 = "b".repeat(64); },
    f => { f.config.policy_sha256 = "2".repeat(64); },
    f => { f.calibration.passed = false; f.write(f.calibrationPath, f.calibration); },
    f => { delete f.calibration.coverage_scope; f.write(f.calibrationPath, f.calibration); },
    f => { f.calibration.coverage_scope = "all-blocked-operations";
      f.write(f.calibrationPath, f.calibration); },
    ...["enforcement", "unlisted_read", "shared_write", "ordinary_error_not_denial"]
      .map(key => f => { f.calibration.checks[key] = false; f.write(f.calibrationPath, f.calibration); }),
    (f, l) => { l.started.mode = "allow"; l.save(); },
    (f, l) => { l.finished.capture_failed = true; l.save(); },
    (f, l) => { l.finished.wait_succeeded = false; l.save(); },
    (f, l) => { l.policy.summary.deniedResourcesTruncated = true;
      l.finished.capture.deniedResourcesTruncated = true; l.save(); },
    (f, l) => { l.verbose.summary.aggregateGroupsTruncated = true; l.save(); },
    (f, l) => { l.verbose.summary.actionableOverflowOccurrences = 2; l.save(); },
    (f, l) => { l.verbose.version = 999; l.save(); },
    (f, l) => { l.verbose.summary.totalOccurrences++; l.save(); },
    (f, l) => { fs.rmSync(l.files.finished); },
    (f, l) => { fs.writeFileSync(l.files.verbose, '{"PRIVATE_TRUNCATION"'); },
    (f, l) => { l.finished.capture.outputPath = path.join(f.directory, "outside.json"); l.save(); },
  ]) {
    const f = fixture(t);
    const l = f.launch(2);
    mutate(f, l);
    const result = collectDenials(f.config, f.directory);
    assert.equal(result.denial_capture_complete, false);
    assert.equal(result.filesystem_read_denial_occurrences, null);
    assert.ok(result.denial_issues.length > 0);
    assert.ok(!JSON.stringify(result).includes("PRIVATE"));
  }
});

test("per-attempt reports charge failed native retries and retain negative reductions", t => {
  const f = fixture(t);
  f.launch(2);
  const g = fixture(t);
  g.launch(3);
  const h = fixture(t);
  h.launch(1);
  const runs = ["A", "B", "B"].map((arm, index) => {
    const eventsPath = path.join(f.directory, `events-${index}.jsonl`);
    fs.writeFileSync(eventsPath, [
      { type: "thread.started", thread_id: "PRIVATE_THREAD" }, { type: "turn.started" },
      { type: "item.completed", item: { type: "command_execution", exit_code: 1,
        aggregated_output: "EACCES PRIVATE_ERROR" } },
      { type: "turn.completed", usage: { input_tokens: 100, cached_input_tokens: 0, output_tokens: 10 } },
    ].map(JSON.stringify).join("\n") + "\n");
    return {
      test_id: "native-test", repetition: 1, attempt: index === 2 ? 2 : 1,
      run_id: `run-${index}`, arm, outcome: index === 1 ? "failed" : "passed",
      events_path: eventsPath, capture_complete: true, fresh_thread: true, helpers_disabled: true,
      policy_sha256: "1".repeat(64), fixture_sha256: "2".repeat(64),
      denial_capture: [f.config, g.config, h.config][index],
    };
  });
  const manifest = {
    schema_version: 1, source_kind: "synthetic_events", usage_semantics: "codex-thread-cumulative",
    provenance: { model: "test-model", codex_revision: "a".repeat(40), mxc_revision: "b".repeat(40),
      codex_patch_sha256: "c".repeat(64), mxc_patch_sha256: "d".repeat(64), settings_sha256: "e".repeat(64) },
    runs,
  };
  const report = collectManifest(manifest, f.directory);
  const pair = report.comparisons[0];
  assert.equal(pair.denials_comparable, true);
  assert.equal(pair.denial_metric_scope, DENIAL_SCOPE);
  assert.equal(report.summary.denial_metric_scope, DENIAL_SCOPE);
  assert.equal(pair.baseline_filesystem_read_denial_occurrences, 2);
  assert.equal(pair.treatment_filesystem_read_denial_occurrences, 4);
  assert.equal(pair.filesystem_read_denial_occurrences_reduced, -2);
  assert.equal(report.summary.comparisons.B.native_denials
    .all_complete_attempts.filesystem_read_denial_occurrences_reduced, -2);
  assert.ok(comparisonCsv(report.comparisons).includes("denials_comparable"));
  assert.ok(!JSON.stringify(report).includes("PRIVATE"));
  const manifestPath = path.join(f.directory, "manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  const output = path.join(f.directory, "report");
  const cli = spawnSync(process.execPath, [
    path.resolve(__dirname, "..", "measure-codex-context.js"), manifestPath, output,
  ], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  for (const file of ["denial-events.jsonl", "denial-artifacts.jsonl"]) {
    const text = fs.readFileSync(path.join(output, file), "utf8");
    assert.ok(text.trim().length > 0);
    assert.ok(!text.includes("PRIVATE"));
  }
  runs[1].denial_capture = null;
  const incomplete = collectManifest(manifest, f.directory);
  assert.equal(incomplete.comparisons[0].denials_comparable, false);
  assert.equal(incomplete.comparisons[0].filesystem_read_denial_occurrences_reduced, null);
  assert.equal(incomplete.comparisons[0].comparable, true);
  assert.equal(incomplete.summary.comparisons.B.native_denials
    .all_complete_attempts.filesystem_read_denial_occurrences_reduced, null);
  runs[1].denial_capture = f.config;
  const reused = collectManifest(manifest, f.directory);
  assert.equal(reused.runs[1].denial_capture_complete, false);
  assert.match(reused.runs[1].denial_issues.join(" "), /reused/);
});

test("the calibration CLI rejects missing arguments without starting a model", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-native-calibration-cli-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cli = path.resolve(__dirname, "..", "validate-codex-denial-capture.js");
  const result = spawnSync(process.execPath, [cli], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage:/);
});

test("real Codex capture qualifies actionable denials while preserving explicit blocks", {
  skip: !process.env.MXC_POC_CODEX,
}, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-native-calibration-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const trial = path.join(root, "trial");
  const result = validate(process.env.MXC_POC_CODEX, trial);
  assert.equal(result.model_calls, 0);
  assert.equal(result.checks.enforcement, true);
  assert.equal(result.checks.input_integrity, true);
  assert.equal(result.checks.capture_documents_valid, true);
  assert.equal(result.passed, true, JSON.stringify(result.checks));
  const [attempt] = JSON.parse(fs.readFileSync(path.join(trial, "attempts.json"))).attempts;
  const evidence = collectDenials({
    ...attempt.denial_capture, process_complete: true, expected_launches: 3,
    calibration_path: "calibration.json", codex_binary_sha256: result.codex_binary_sha256,
  }, trial);
  assert.equal(evidence.denial_capture_complete, true);
  assert.ok(evidence.filesystem_read_denial_occurrences > 0);
  assert.ok(evidence.filesystem_write_denial_occurrences > 0);
  assert.throws(() => validate(process.env.MXC_POC_CODEX, trial), /EEXIST/);
});
