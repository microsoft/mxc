// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { collectManifest, readUsage, sanitizeUsageEvents } = require("../lib/codex-context-usage");

function events(...totals) {
  return [
    { type: "thread.started", thread_id: "fresh-test-thread" },
    ...totals.flatMap(([input, cached, output]) => [
      { type: "turn.started" },
      { type: "item.completed", item: { type: "agent_message", text: "PRIVATE_TRANSCRIPT" } },
      { type: "turn.completed", usage: { input_tokens: input, cached_input_tokens: cached, output_tokens: output } },
    ]),
  ].map(event => JSON.stringify(event)).join("\n") + "\n";
}

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mxc-context-usage-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const manifest = {
    schema_version: 1,
    source_kind: "synthetic_events",
    usage_semantics: "codex-thread-cumulative",
    provenance: {
      model: "test-model",
      codex_revision: "a".repeat(40),
      mxc_revision: "b".repeat(40),
      codex_patch_sha256: "c".repeat(64),
      mxc_patch_sha256: "d".repeat(64),
      settings_sha256: "e".repeat(64),
    },
    runs: [],
  };
  function add(arm, total, overrides = {}) {
    const id = `run-${manifest.runs.length}`;
    const record = {
      test_id: "csv-import",
      repetition: 1,
      attempt: 1,
      arm,
      run_id: id,
      events_path: `${id}.jsonl`,
      outcome: "passed",
      capture_complete: true,
      fresh_thread: true,
      helpers_disabled: true,
      policy_sha256: "f".repeat(64),
      fixture_sha256: "0".repeat(64),
      ...overrides,
    };
    fs.writeFileSync(path.join(directory, record.events_path), events([total, 0, 10]));
    manifest.runs.push(record);
    return record;
  }
  return { directory, manifest, add };
}

test("thread snapshots count once, cached and reasoning tokens are subsets", () => {
  const text = events([100, 40, 20], [300, 150, 70]);
  const usage = readUsage(text);
  assert.equal(usage.usage_complete, true);
  assert.equal(usage.total_tokens, 370);
  assert.equal(usage.cached_input_tokens, 150);
  assert.equal(usage.completed_turns, 2);
  const duplicate = text + text.trimEnd().split("\n").at(-1) + "\n";
  assert.equal(readUsage(duplicate).total_tokens, 370);
  assert.equal(readUsage(duplicate).duplicate_snapshots, 1);
});

test("interrupted, failed, malformed, or decreasing streams retain partial usage", () => {
  for (const ending of [
    '{"type":"turn.started"}\n',
    '{"type":"turn.failed","error":{"message":"PRIVATE_ERROR"}}\n',
    '{"type":"turn.started"',
    events([50, 0, 5]).split("\n").slice(1).join("\n"),
  ]) {
    const usage = readUsage(events([100, 20, 10]) + ending);
    assert.equal(usage.usage_complete, false);
    assert.equal(usage.total_tokens, 110);
    assert.ok(!JSON.stringify(usage).includes("PRIVATE"));
  }
  assert.equal(readUsage("").total_tokens, null);
});

test("invalid or imprecise counters cannot become a zero-cost success", () => {
  for (const usage of [
    { input_tokens: -1, cached_input_tokens: 0, output_tokens: 0 },
    { input_tokens: 1, cached_input_tokens: 2, output_tokens: 0 },
    { input_tokens: 1, cached_input_tokens: 0 },
    { input_tokens: Number.MAX_SAFE_INTEGER, cached_input_tokens: 0, output_tokens: 1 },
    { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1, reasoning_output_tokens: 2 },
  ]) {
    const text = events().trimEnd() + '\n{"type":"turn.started"}\n'
      + JSON.stringify({ type: "turn.completed", usage });
    assert.equal(readUsage(text).usage_complete, false);
    assert.equal(readUsage(text).total_tokens, null);
  }
});

test("compares A/B/C per test and charges failed retries", t => {
  const { directory, manifest, add } = fixture(t);
  add("A", 100);
  add("B", 20, { outcome: "failed" });
  add("B", 40, { attempt: 2 });
  add("C", 150);
  const report = collectManifest(manifest, directory);
  assert.equal(report.comparisons[0].baseline_tokens, 110);
  assert.equal(report.comparisons[0].treatment_tokens, 80);
  assert.equal(report.comparisons[0].tokens_saved, 30);
  assert.equal(report.comparisons[0].savings_percent, 100 * 30 / 110);
  assert.equal(report.comparisons[1].tokens_saved, -50);
  assert.equal(report.runs.length, 4);
  assert.equal(report.summary.comparisons.B.both_tasks_passed.pairs, 1);
  assert.ok(!JSON.stringify(report).includes("PRIVATE_TRANSCRIPT"));
});

test("incomplete captures, unknown helpers and resumed threads exclude comparisons", t => {
  for (const flags of [
    { capture_complete: false }, { fresh_thread: false }, { helpers_disabled: false },
  ]) {
    const { directory, manifest, add } = fixture(t);
    add("A", 100);
    add("B", 30, flags);
    const report = collectManifest(manifest, directory);
    assert.equal(report.comparisons[0].comparable, false);
    assert.equal(report.comparisons[0].tokens_saved, null);
    assert.equal(report.summary.incomplete_known_tokens, 40);
  }
});

test("mismatched policies/fixtures and missing arms cannot claim savings", t => {
  for (const key of ["policy_sha256", "fixture_sha256"]) {
    const { directory, manifest, add } = fixture(t);
    add("A", 100);
    add("B", 20, { [key]: "1".repeat(64) });
    const report = collectManifest(manifest, directory);
    assert.equal(report.comparisons[0].comparable, false);
    assert.equal(report.comparisons[1].exclusion_reason, "missing arm");
  }
});

test("zero baseline percentages are unavailable and failed tasks stay visible", t => {
  const { directory, manifest, add } = fixture(t);
  const a = add("A", 0);
  fs.writeFileSync(path.join(directory, a.events_path), events([0, 0, 0]));
  add("B", 10, { outcome: "failed" });
  const report = collectManifest(manifest, directory);
  assert.equal(report.comparisons[0].savings_percent, null);
  assert.equal(report.comparisons[0].treatment_passed, false);
  assert.equal(report.summary.comparisons.B.both_tasks_passed.pairs, 0);
});

test("the CLI persists auditable per-attempt and paired reports without overwriting", t => {
  const { directory, manifest, add } = fixture(t);
  add("A", 100);
  add("B", 60);
  add("C", 80);
  const manifestFile = path.join(directory, "manifest.json");
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
  const output = path.join(directory, "report");
  const cli = path.resolve(__dirname, "..", "measure-codex-context.js");
  const run = () => spawnSync(process.execPath, [cli, manifestFile, output], { encoding: "utf8" });
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  const records = fs.readFileSync(path.join(output, "runs.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(records.length, 3);
  assert.equal(records[0].total_tokens, 110);
  const runCsv = fs.readFileSync(path.join(output, "runs.csv"), "utf8");
  assert.ok(runCsv.includes("input_tokens,cached_input_tokens,output_tokens,total_tokens"));
  assert.equal(runCsv.trim().split("\n").length, 4);
  assert.match(records[0].events_sha256, /^[a-f0-9]{64}$/);
  const audit = fs.readFileSync(path.join(output, "usage-events.jsonl"), "utf8");
  assert.ok(audit.includes("turn.completed"));
  assert.ok(!audit.includes("PRIVATE_TRANSCRIPT"));
  const csv = fs.readFileSync(path.join(output, "comparisons.csv"), "utf8");
  assert.ok(csv.includes("tokens_saved,savings_percent"));
  assert.ok(csv.includes('"40"'));
  assert.equal(JSON.parse(fs.readFileSync(path.join(output, "summary.json"))).source_kind, "synthetic_events");
  assert.notEqual(run().status, 0);
});

test("extra metadata is not copied into usage reports", t => {
  const { directory, manifest, add } = fixture(t);
  add("A", 100, { secret: "PRIVATE_RECORD" });
  manifest.provenance.secret = "PRIVATE_METADATA";
  assert.ok(!JSON.stringify(collectManifest(manifest, directory)).includes("PRIVATE"));
});

test("sanitized usage evidence retains cumulative totals without transcript or error text", () => {
  for (const text of [
    events([100, 40, 20], [300, 150, 70]),
    events([100, 40, 20]) + '{"type":"turn.started"}\n',
    events([100, 40, 20]) + '{"type":"turn.failed","error":{"message":"PRIVATE_ERROR"}}\n',
    events([100, 40, 20]) + '{"type":"turn.started"',
  ]) {
    const audit = sanitizeUsageEvents(text).map(event => JSON.stringify(event)).join("\n");
    const before = readUsage(text);
    const after = readUsage(audit);
    assert.equal(after.total_tokens, before.total_tokens);
    assert.equal(after.cached_input_tokens, before.cached_input_tokens);
    assert.equal(after.usage_complete, before.usage_complete);
    assert.ok(!audit.includes("PRIVATE"));
  }
});
