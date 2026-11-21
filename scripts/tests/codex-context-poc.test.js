// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { prepare } = require("../prepare-codex-context-poc");
const { collectManifest } = require("../lib/codex-context-usage");

test("preparation randomizes complete A/B/C blocks with equivalent policy and fixture inputs", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-context-prepare-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const output = path.join(root, "trial");
  const attempts = prepare(output, 2);
  assert.equal(attempts.length, 6);
  for (const repetition of [1, 2]) {
    const block = attempts.filter(attempt => attempt.repetition === repetition);
    assert.deepEqual(block.map(attempt => attempt.arm).sort(), ["A", "B", "C"]);
    assert.equal(new Set(block.map(attempt => attempt.policy_sha256)).size, 1);
    assert.equal(new Set(block.map(attempt => attempt.fixture_sha256)).size, 1);
  }
  assert.equal(new Set(attempts.map(attempt => attempt.environment.CODEX_HOME)).size, 6);
  const metadata = JSON.parse(fs.readFileSync(path.join(output, "attempts.json")));
  assert.equal(metadata.model_calls, 0);
  assert.equal(metadata.prepared_only, true);
  const manifest = JSON.parse(fs.readFileSync(path.join(output, "usage-manifest.template.json")));
  assert.deepEqual(manifest.runs.map(run => run.run_id), attempts.map(attempt => attempt.run_id));
  assert.throws(() => collectManifest(manifest, output), /mxc_revision must be a Git commit/);
  assert.throws(() => prepare(output), /EEXIST/);
  for (const attempt of attempts) {
    const prompt = fs.readFileSync(attempt.prompt_path, "utf8");
    assert.ok(!prompt.includes("denied") && !prompt.includes("read-only") && !prompt.includes("arm"));
    const config = fs.readFileSync(path.join(attempt.environment.CODEX_HOME, "config.toml"), "utf8");
    assert.ok(config.includes('sandbox = "mxc"'));
    assert.ok(config.includes('inherit = "none"'));
    assert.ok(fs.statSync(attempt.environment.CODEX_MXC_DENIAL_CAPTURE_DIR).isDirectory());
    assert.equal(attempt.denial_capture.process_complete, false);
    assert.equal(attempt.denial_capture.calibration_path, null);
    assert.ok(!config.includes("CODEX_MXC_DENIAL_CAPTURE_DIR"));
    assert.ok(!fs.existsSync(path.join(path.dirname(attempt.prompt_path), "events.jsonl")));
  }
});

test("the public fixture reproduces the relative-path bug and accepts a minimal fix", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-context-fixture-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const [attempt] = prepare(path.join(root, "trial"));
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const run = () => spawnSync(process.execPath, ["--test", "app.test.js"], {
    cwd: attempt.cwd, encoding: "utf8", env,
  });
  const broken = run();
  assert.notEqual(broken.status, 0, broken.stdout + broken.stderr);
  const file = path.join(attempt.cwd, "app.js");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8")
    .replace("fs.readFileSync(config.csvPath,", "fs.readFileSync(path.resolve(path.dirname(configFile), config.csvPath),"));
  const fixed = run();
  assert.equal(fixed.status, 0, fixed.stdout + fixed.stderr);
  const report = spawnSync(process.execPath, [
    "app.js", "config/import.json", "output/validation.json",
  ], { cwd: attempt.cwd, encoding: "utf8" });
  assert.equal(report.status, 0, report.stderr);
  // Only trusted reference code is executed here. Live agent edits require native MXC grading.
  const graded = spawnSync(process.execPath, attempt.grader_args.slice(3), { encoding: "utf8" });
  assert.equal(graded.status, 0, graded.stderr);
  assert.match(graded.stdout, /HELD_OUT_PASS/);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(attempt.cwd, "output", "validation.json"))),
    { count: 3, total: 15 });
});

test("the fixture and held-out grader run inside native MXC", {
  skip: !process.env.MXC_POC_EXECUTOR,
}, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-context-native-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const [attempt] = prepare(path.join(root, "trial"));
  const policy = attempt.grader_args[0];
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const run = args => spawnSync(process.env.MXC_POC_EXECUTOR, args, {
    encoding: "utf8", env, timeout: 60_000,
  });
  const dryRun = run(["--dry-run", policy]);
  assert.equal(dryRun.status, 0, dryRun.stdout + dryRun.stderr);
  const broken = run([policy, "--", process.execPath, "--test", "app.test.js"]);
  assert.notEqual(broken.status, 0);
  assert.match(broken.stdout + broken.stderr, /ENOENT/);
  const file = path.join(attempt.cwd, "app.js");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8")
    .replace("fs.readFileSync(config.csvPath,", "fs.readFileSync(path.resolve(path.dirname(configFile), config.csvPath),"));
  const report = run([policy, "--", process.execPath, "app.js",
    "config/import.json", "output/validation.json"]);
  assert.equal(report.status, 0, report.stdout + report.stderr);
  const graded = run(attempt.grader_args);
  assert.equal(graded.status, 0, graded.stdout + graded.stderr);
  assert.match(graded.stdout, /HELD_OUT_PASS/);
});
