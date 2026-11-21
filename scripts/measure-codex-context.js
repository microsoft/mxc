#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const fs = require("node:fs");
const path = require("node:path");
const { collectManifest, comparisonCsv, runCsv } = require("./lib/codex-context-usage");

function main(args) {
  if (args.length !== 2) {
    throw new Error("Usage: node scripts\\measure-codex-context.js <manifest.json> <new-output-directory>");
  }
  const manifestPath = path.resolve(args[0]);
  const report = collectManifest(JSON.parse(fs.readFileSync(manifestPath, "utf8")), path.dirname(manifestPath));
  const output = path.resolve(args[1]);
  fs.mkdirSync(output);
  fs.writeFileSync(path.join(output, "runs.jsonl"), report.runs.map(run => JSON.stringify(run)).join("\n") + "\n");
  fs.writeFileSync(path.join(output, "runs.csv"), runCsv(report.runs));
  fs.writeFileSync(path.join(output, "usage-events.jsonl"),
    report.usage_events.map(event => JSON.stringify(event)).join("\n") + "\n");
  fs.writeFileSync(path.join(output, "denial-events.jsonl"),
    report.denial_events.map(event => JSON.stringify(event)).join("\n") + "\n");
  fs.writeFileSync(path.join(output, "denial-artifacts.jsonl"),
    report.denial_artifacts.map(artifact => JSON.stringify(artifact)).join("\n") + "\n");
  fs.writeFileSync(path.join(output, "comparisons.csv"), comparisonCsv(report.comparisons));
  fs.writeFileSync(path.join(output, "summary.json"), JSON.stringify(report.summary, null, 2) + "\n");
  process.stdout.write(`Recorded ${report.runs.length} attempts (${report.summary.incomplete_runs} incomplete); ${report.summary.source_kind}.\n`);
}

try {
  main(process.argv.slice(2));
} catch (error) {
  // Do not echo arbitrary JSON parser errors, which can include transcript text.
  process.stderr.write(error instanceof SyntaxError ? "Invalid manifest JSON.\n" : `${error.message}\n`);
  process.exitCode = 1;
}
