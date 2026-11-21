// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { collectDenials, DENIAL_SCOPE, METRICS: DENIAL_METRICS } = require("./codex-context-denials");

const COUNTERS = [
  "input_tokens",
  "cached_input_tokens",
  "output_tokens",
  "cache_write_input_tokens",
  "reasoning_output_tokens",
];

function counters(usage) {
  const result = {};
  for (const key of COUNTERS) {
    const value = usage?.[key] ?? (COUNTERS.indexOf(key) >= 3 ? 0 : undefined);
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("invalid token counter");
    }
    result[key] = value;
  }
  if (result.cached_input_tokens > result.input_tokens
      || result.reasoning_output_tokens > result.output_tokens
      || !Number.isSafeInteger(result.input_tokens + result.output_tokens)) {
    throw new Error("inconsistent token counters");
  }
  return result;
}

// The pinned Codex JSONL processor emits thread totals, despite the event's
// turn.completed name. Adding these snapshots would overcount resumed turns.
function readUsage(text) {
  let usage = null;
  let thread = null;
  let activeTurn = false;
  let terminal = null;
  let completedTurns = 0;
  let duplicates = 0;
  const issues = [];
  for (const [index, line] of text.replace(/^\uFEFF/, "").split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      issues.push(`invalid JSON at line ${index + 1}`);
      break;
    }
    if (!event || typeof event.type !== "string") {
      issues.push(`invalid event at line ${index + 1}`);
      break;
    }
    if (event.type === "thread.started") {
      if (thread !== null || typeof event.thread_id !== "string") {
        issues.push("expected one fresh thread");
        break;
      }
      thread = event.thread_id;
    } else if (event.type === "turn.started") {
      if (thread === null || activeTurn) {
        issues.push("invalid turn start");
        break;
      }
      activeTurn = true;
      terminal = null;
    } else if (event.type === "turn.completed") {
      let next;
      try {
        next = counters(event.usage);
      } catch {
        issues.push(`invalid usage at line ${index + 1}`);
        break;
      }
      if (!activeTurn) {
        if (terminal === "completed" && JSON.stringify(usage) === JSON.stringify(next)) {
          duplicates++;
          continue;
        }
        issues.push("completion without a turn start");
        break;
      }
      if (usage && COUNTERS.some(key => next[key] < usage[key])) {
        issues.push("thread usage decreased; cumulative semantics do not match");
        break;
      }
      usage = next;
      completedTurns++;
      activeTurn = false;
      terminal = "completed";
    } else if (event.type === "turn.failed" || event.type === "error") {
      activeTurn = false;
      terminal = "failed";
      issues.push("Codex did not report complete usage for a failed turn");
    }
  }
  return {
    ...(usage ?? Object.fromEntries(COUNTERS.map(key => [key, null]))),
    total_tokens: usage ? usage.input_tokens + usage.output_tokens : null,
    usage_complete: usage !== null && terminal === "completed"
      && !activeTurn && issues.length === 0,
    completed_turns: completedTurns,
    duplicate_snapshots: duplicates,
    issues,
  };
}

function sanitizeUsageEvents(text) {
  const events = [];
  let threads = 0;
  for (const [index, line] of text.replace(/^\uFEFF/, "").split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line);
      if (!event || typeof event.type !== "string") throw new Error();
      if (event.type === "thread.started") {
        if (typeof event.thread_id !== "string") throw new Error();
        events.push({ type: event.type, thread_id: `redacted-thread-${++threads}` });
      } else if (event.type === "turn.started") {
        events.push({ type: event.type });
      } else if (event.type === "turn.completed") {
        events.push({ type: event.type, usage: counters(event.usage) });
      } else if (event.type === "turn.failed" || event.type === "error") {
        events.push({ type: event.type, error: { message: "upstream failure (details omitted)" } });
      }
    } catch {
      events.push({ type: "error", error: { message: `invalid event or usage at line ${index + 1}` } });
      break;
    }
  }
  return events;
}

function identifier(value, label) {
  if (typeof value !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$/.test(value)) {
    throw new Error(`${label} must be a nonempty identifier without whitespace`);
  }
}

function digest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 digest`);
  }
}

function checkedSum(values) {
  const total = values.reduce((sum, value) => sum + value, 0);
  if (!Number.isSafeInteger(total)) throw new Error("aggregate total exceeds safe integer range");
  return total;
}

function aggregate(runs) {
  return {
    attempts: runs.length,
    passed: runs.some(run => run.outcome === "passed"),
    usage_complete: runs.length > 0 && runs.every(run => run.usage_complete),
    known_tokens: checkedSum(runs.map(run => run.total_tokens ?? 0)),
  };
}

function compare(runs) {
  const groups = new Map();
  for (const run of runs) {
    const key = JSON.stringify([run.test_id, run.repetition]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(run);
  }
  const comparisons = [];
  for (const group of groups.values()) {
    for (const arm of ["B", "C"]) {
      const baseline = group.filter(run => run.arm === "A");
      const treatment = group.filter(run => run.arm === arm);
      const a = aggregate(baseline);
      const b = aggregate(treatment);
      const pair = [...baseline, ...treatment];
      let reason = "";
      if (!baseline.length || !treatment.length) reason = "missing arm";
      else if (!a.usage_complete || !b.usage_complete) reason = "incomplete usage";
      else if (new Set(pair.map(run => run.policy_sha256)).size !== 1) reason = "policy mismatch";
      else if (new Set(pair.map(run => run.fixture_sha256)).size !== 1) reason = "fixture mismatch";
      const eligible = reason === "";
      const saved = eligible ? a.known_tokens - b.known_tokens : null;
      const denialsComparable = baseline.length > 0 && treatment.length > 0
        && pair.every(run => run.denial_capture_complete)
        && new Set(pair.map(run => run.policy_sha256)).size === 1
        && new Set(pair.map(run => run.fixture_sha256)).size === 1;
      const denialTotals = {};
      for (const key of DENIAL_METRICS) {
        const baselineTotal = denialsComparable ? checkedSum(baseline.map(run => run[key])) : null;
        const treatmentTotal = denialsComparable ? checkedSum(treatment.map(run => run[key])) : null;
        denialTotals[`baseline_${key}`] = baselineTotal;
        denialTotals[`treatment_${key}`] = treatmentTotal;
        denialTotals[`${key}_reduced`] = denialsComparable ? baselineTotal - treatmentTotal : null;
      }
      comparisons.push({
        test_id: group[0].test_id,
        repetition: group[0].repetition,
        treatment: arm,
        baseline_attempts: a.attempts,
        treatment_attempts: b.attempts,
        baseline_passed: a.passed,
        treatment_passed: b.passed,
        comparable: eligible,
        exclusion_reason: reason,
        baseline_tokens: a.usage_complete ? a.known_tokens : null,
        treatment_tokens: b.usage_complete ? b.known_tokens : null,
        tokens_saved: saved,
        savings_percent: eligible && a.known_tokens !== 0
          ? 100 * saved / a.known_tokens : null,
        denial_metric_scope: DENIAL_SCOPE,
        denials_comparable: denialsComparable,
        ...denialTotals,
      });
    }
  }
  return comparisons;
}

function summarize(comparisons) {
  return Object.fromEntries(["B", "C"].map(arm => {
    const rows = comparisons.filter(row => row.treatment === arm);
    const complete = rows.filter(row => row.comparable);
    const successful = complete.filter(row => row.baseline_passed && row.treatment_passed);
    const native = rows.filter(row => row.denials_comparable);
    const nativeTotals = selected => ({
      pairs: selected.length,
      ...Object.fromEntries(DENIAL_METRICS.flatMap(key =>
        [`baseline_${key}`, `treatment_${key}`, `${key}_reduced`].map(column => [
          column, selected.length ? checkedSum(selected.map(row => row[column])) : null,
        ]))),
    });
    const totals = selected => {
      const baseline = checkedSum(selected.map(row => row.baseline_tokens));
      const treatment = checkedSum(selected.map(row => row.treatment_tokens));
      return {
        pairs: selected.length,
        baseline_tokens: baseline,
        treatment_tokens: treatment,
        tokens_saved: baseline - treatment,
        savings_percent: baseline === 0 ? null : 100 * (baseline - treatment) / baseline,
      };
    };
    return [arm, {
      excluded_pairs: rows.length - complete.length,
      all_complete_attempts: totals(complete),
      both_tasks_passed: totals(successful),
      native_denials: {
        excluded_pairs: rows.length - native.length,
        all_complete_attempts: nativeTotals(native),
        both_tasks_passed: nativeTotals(native.filter(row => row.baseline_passed && row.treatment_passed)),
      },
    }];
  }));
}

function collectManifest(manifest, directory) {
  if (manifest.schema_version !== 1 || manifest.usage_semantics !== "codex-thread-cumulative") {
    throw new Error("expected schema_version 1 and codex-thread-cumulative usage");
  }
  if (!["synthetic_events", "live_codex"].includes(manifest.source_kind)) {
    throw new Error("source_kind must distinguish synthetic_events from live_codex");
  }
  const provenance = manifest.provenance;
  if (!provenance) throw new Error("provenance is required");
  identifier(provenance.model, "model");
  for (const key of ["codex_revision", "mxc_revision"]) {
    if (!/^[a-f0-9]{40}$/.test(provenance[key] ?? "")) throw new Error(`${key} must be a Git commit`);
  }
  for (const key of ["codex_patch_sha256", "mxc_patch_sha256", "settings_sha256"]) {
    digest(provenance[key], key);
  }
  if (!Array.isArray(manifest.runs) || manifest.runs.length === 0) {
    throw new Error("runs must be a nonempty array");
  }
  const ids = new Set();
  const attempts = new Set();
  const usageEvents = [];
  const denialEvents = [];
  const denialArtifacts = [];
  const nativeReceipts = new Map();
  const reusedCaptureRuns = new Set();
  const runs = manifest.runs.map(record => {
    for (const key of ["test_id", "run_id"]) identifier(record[key], key);
    for (const key of ["repetition", "attempt"]) {
      if (!Number.isSafeInteger(record[key]) || record[key] < 1) {
        throw new Error(`${key} must be a positive integer`);
      }
    }
    if (!["A", "B", "C"].includes(record.arm)) throw new Error("arm must be A, B or C");
    if (!["passed", "failed", "timed_out", "abandoned"].includes(record.outcome)) {
      throw new Error("outcome must be the independently graded task result");
    }
    for (const key of ["policy_sha256", "fixture_sha256"]) digest(record[key], key);
    const attempt = JSON.stringify([record.test_id, record.repetition, record.arm, record.attempt]);
    if (ids.has(record.run_id) || attempts.has(attempt)) throw new Error("duplicate run or attempt");
    ids.add(record.run_id);
    attempts.add(attempt);
    if (typeof record.events_path !== "string" || !record.events_path) {
      throw new Error("events_path is required");
    }
    let usage;
    let eventsHash = null;
    try {
      const text = fs.readFileSync(path.resolve(directory, record.events_path), "utf8");
      eventsHash = crypto.createHash("sha256").update(text).digest("hex");
      usage = readUsage(text);
      for (const event of sanitizeUsageEvents(text)) {
        usageEvents.push({ run_id: record.run_id, event });
      }
    } catch {
      usage = readUsage("");
      usage.issues.push("event file could not be read");
    }
    for (const [key, message] of [
      ["capture_complete", "event capture is incomplete"],
      ["fresh_thread", "fresh-thread usage was not confirmed"],
      ["helpers_disabled", "helper/subagent usage is not accounted for"],
    ]) {
      if (record[key] !== true) {
        usage.usage_complete = false;
        usage.issues.push(message);
      }
    }
    if (record.billed_cost != null
        && (typeof record.billed_cost !== "number" || !Number.isFinite(record.billed_cost)
          || record.billed_cost < 0)) {
      throw new Error("billed_cost must be null or a nonnegative amount");
    }
    const { events: nativeEvents, artifacts, ...denials } =
      collectDenials(record.denial_capture, directory);
    if (record.denial_capture && record.denial_capture.policy_sha256 !== record.policy_sha256) {
      denials.denial_issues.push("native capture policy fingerprint does not match the attempt");
    }
    for (const artifact of artifacts) {
      if (nativeReceipts.has(artifact.completed_sha256)) {
        denials.denial_issues.push("native capture receipt was reused across attempts");
        reusedCaptureRuns.add(nativeReceipts.get(artifact.completed_sha256));
        reusedCaptureRuns.add(record.run_id);
      }
      nativeReceipts.set(artifact.completed_sha256, record.run_id);
    }
    if (denials.denial_issues.length > 0) {
      denials.denial_capture_complete = false;
      for (const key of DENIAL_METRICS) denials[key] = null;
    }
    denialEvents.push(...nativeEvents.map(event => ({ run_id: record.run_id, ...event })));
    denialArtifacts.push(...artifacts.map(artifact => ({ run_id: record.run_id, ...artifact })));
    return {
      test_id: record.test_id,
      repetition: record.repetition,
      attempt: record.attempt,
      arm: record.arm,
      run_id: record.run_id,
      model: provenance.model,
      policy_sha256: record.policy_sha256,
      fixture_sha256: record.fixture_sha256,
      outcome: record.outcome,
      billed_cost: record.billed_cost ?? null,
      events_sha256: eventsHash,
      ...usage,
      ...denials,
    };
  });
  for (const run of runs.filter(run => reusedCaptureRuns.has(run.run_id))) {
    run.denial_capture_complete = false;
    if (!run.denial_issues.includes("native capture receipt was reused across attempts")) {
      run.denial_issues.push("native capture receipt was reused across attempts");
    }
    for (const key of DENIAL_METRICS) run[key] = null;
  }
  const comparisons = compare(runs);
  return {
    runs,
    comparisons,
    usage_events: usageEvents,
    denial_events: denialEvents,
    denial_artifacts: denialArtifacts,
    summary: {
      schema_version: 1,
      source_kind: manifest.source_kind,
      provenance: Object.fromEntries([
        "model", "codex_revision", "mxc_revision", "codex_patch_sha256",
        "mxc_patch_sha256", "settings_sha256",
      ].map(key => [key, provenance[key]])),
      usage_semantics: manifest.usage_semantics,
      denial_metric_scope: DENIAL_SCOPE,
      runs: runs.length,
      incomplete_runs: runs.filter(run => !run.usage_complete).length,
      incomplete_denial_runs: runs.filter(run => !run.denial_capture_complete).length,
      incomplete_known_tokens: checkedSum(runs.filter(run => !run.usage_complete)
        .map(run => run.total_tokens ?? 0)),
      comparisons: summarize(comparisons),
    },
  };
}

function comparisonCsv(rows) {
  const columns = [
    "test_id", "repetition", "treatment", "baseline_attempts", "treatment_attempts",
    "baseline_passed", "treatment_passed", "comparable", "exclusion_reason",
    "baseline_tokens", "treatment_tokens", "tokens_saved", "savings_percent",
    "denial_metric_scope", "denials_comparable",
    ...DENIAL_METRICS.flatMap(key => [`baseline_${key}`, `treatment_${key}`, `${key}_reduced`]),
  ];
  return csv(columns, rows);
}

function runCsv(rows) {
  return csv([
    "test_id", "repetition", "attempt", "arm", "run_id", "model", "outcome",
    "usage_complete", "input_tokens", "cached_input_tokens", "output_tokens",
    "total_tokens", "cache_write_input_tokens", "reasoning_output_tokens", "billed_cost",
    "denial_metric_scope", "denial_capture_complete",
    "native_launches", "native_completed_captures", ...DENIAL_METRICS,
  ], rows);
}

function csv(columns, rows) {
  const cell = value => value == null ? "" : `"${String(value).replaceAll('"', '""')}"`;
  return [columns.join(","), ...rows.map(row => columns.map(key => cell(row[key])).join(","))]
    .join("\n") + "\n";
}

module.exports = { collectManifest, comparisonCsv, readUsage, runCsv, sanitizeUsageEvents };
