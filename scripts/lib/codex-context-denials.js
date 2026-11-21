// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const DENIAL_SCOPE = "native-actionable-denials";
const METRICS = [
  "filesystem_read_denial_occurrences", "filesystem_write_denial_occurrences",
  "filesystem_other_denial_occurrences", "other_actionable_denial_occurrences",
  "filesystem_unique_read_resources", "repeated_read_resource_launches",
  "repeated_read_root_launches",
];
const ROOTS = ["private", "shared", "unlisted", "workspace", "temp"];
const TYPES = ["file", "ui", "network", "capability", "other"];
const ACCESS = ["read", "write", "execute", "unknown"];
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const nativePath = value => path.win32.normalize(value
  .replace(/^\\\\\?\\UNC\\/i, "\\\\").replace(/^\\\\\?\\/, "")).toLowerCase();

function check(condition) {
  if (!condition) throw new Error("invalid native capture");
}

function number(value) {
  check(Number.isSafeInteger(value) && value >= 0);
  return value;
}

function add(target, key, value) {
  target[key] = number(target[key] + number(value));
}

function document(file) {
  check(fs.statSync(file).isFile() && fs.statSync(file).size <= 64 * 1024 * 1024);
  const bytes = fs.readFileSync(file);
  return { value: JSON.parse(bytes.toString("utf8")), sha256: hash(bytes) };
}

function receipt(value) {
  check(value?.schema_version === 1 && value.backend === "process_container" && value.mode === "block");
}

function rootLabel(resource, roots) {
  const candidate = nativePath(resource);
  return ROOTS.find(key => {
    if (typeof roots?.[key] !== "string") return false;
    const root = nativePath(roots[key]).replace(/\\+$/, "");
    return candidate === root || candidate.startsWith(root + "\\");
  }) ?? "other";
}

// Only trusted helper receipts and native documents are read; command stderr
// (including JSON-looking output) is never treated as denial evidence.
function collectDenials(config, directory) {
  const known = Object.fromEntries(METRICS.map(key => [key, 0]));
  const issues = [];
  const events = [];
  const artifacts = [];
  const resources = new Map();
  const readResources = new Set();
  const readRoots = new Set();
  let launches = [];
  let completed = 0;
  if (!config) issues.push("native denial capture not configured");
  else {
    if (config.process_complete !== true) issues.push("native launcher capture is not sealed");
    try {
      check(typeof config.directory === "string" && config.directory.length > 0);
      const captureRoot = path.resolve(directory, config.directory);
      launches = fs.readdirSync(captureRoot);
      check(launches.length <= 10000);
      check(launches.every(name => /^launch-[0-9]+-[0-9]+$/.test(name)));
      launches.sort((left, right) => {
        const a = BigInt(left.split("-").at(-1));
        const b = BigInt(right.split("-").at(-1));
        return a < b ? -1 : a > b ? 1 : left.localeCompare(right);
      });
      if (!Number.isSafeInteger(config.expected_launches) || config.expected_launches < 0
          || config.expected_launches !== launches.length) {
        issues.push("native launch count was not confirmed or does not match");
      }
      for (const [index, name] of launches.entries()) {
        const launchId = `launch-${index + 1}`;
        try {
          const launch = path.join(captureRoot, name);
          const started = document(path.join(launch, "started.json"));
          const finished = document(path.join(launch, "completed.json"));
          receipt(started.value);
          receipt(finished.value);
          check(finished.value.wait_succeeded === true && finished.value.capture_failed === false);
          const pointer = finished.value.capture;
          check(pointer?.type === "captureDenials" && typeof pointer.outputPath === "string");
          check(path.dirname(path.resolve(pointer.outputPath)) === path.resolve(launch));
          check(/^denials\.[a-zA-Z0-9_]+\.json$/.test(path.basename(pointer.outputPath)));
          const policy = document(pointer.outputPath);
          const verbose = document(pointer.outputPath.replace(/\.json$/, ".verbose.json"));
          const p = policy.value;
          const v = verbose.value;
          check(Array.isArray(p.denials) && p.denials.length <= 10000);
          check(p.summary?.totalDenials === p.denials.length);
          check(p.summary.exitCode === pointer.exitCode && pointer.totalDenials === p.denials.length);
          check(typeof p.summary.deniedResourcesTruncated === "boolean");
          check(pointer.deniedResourcesTruncated === p.summary.deniedResourcesTruncated);
          check([3, 4, 5, 6].includes(v.version) && Array.isArray(v.signatures));
          check(v.signatures.length <= 4096);
          const partial = Object.fromEntries(METRICS.map(key => [key, 0]));
          let occurrences = 0;
          for (const entry of v.signatures) {
            const count = number(entry.count);
            occurrences = number(occurrences + count);
            const signature = entry.signature;
            check(signature && typeof signature.reason === "string");
            if (signature.reason !== "actionable") continue;
            check(TYPES.includes(signature.resourceType) && ACCESS.includes(signature.accessType));
            const key = signature.resourceType !== "file" ? "other_actionable_denial_occurrences"
              : signature.accessType === "read" ? "filesystem_read_denial_occurrences"
                : signature.accessType === "write" ? "filesystem_write_denial_occurrences"
                  : "filesystem_other_denial_occurrences";
            add(partial, key, count);
          }
          const s = v.summary;
          check(s && number(s.totalOccurrences) === occurrences + number(s.overflowOccurrences));
          number(s.actionableOverflowOccurrences);
          for (const flag of ["aggregateGroupsTruncated", "processedEventsTruncated", "actionableLimitReached"]) {
            check(typeof s[flag] === "boolean");
          }
          if (p.summary.deniedResourcesTruncated || s.overflowOccurrences !== 0
              || s.actionableOverflowOccurrences !== 0 || s.aggregateGroupsTruncated
              || s.processedEventsTruncated || s.actionableLimitReached) {
            issues.push(`${launchId}: native analysis is truncated`);
          }
          const unique = new Set();
          const currentReads = new Set();
          const currentRoots = new Set();
          const currentEvents = [];
          const policyCounts = { read: 0, write: 0, other: 0, non_file: 0 };
          for (const denial of p.denials) {
            check(TYPES.includes(denial.resourceType) && ACCESS.includes(denial.accessType));
            check(typeof denial.resource === "string" && denial.resource.length > 0);
            const resource = denial.resourceType === "file" ? nativePath(denial.resource) : denial.resource;
            const key = JSON.stringify([denial.resourceType, resource]);
            const pair = JSON.stringify([key, denial.accessType]);
            check(!unique.has(pair));
            unique.add(pair);
            if (!resources.has(key)) resources.set(key, `resource-${resources.size + 1}`);
            const root = denial.resourceType === "file" ? rootLabel(denial.resource, config.roots) : "other";
            currentEvents.push({
              launch_id: launchId, resource_id: resources.get(key), root,
              resource_type: denial.resourceType, access_type: denial.accessType,
            });
            if (denial.resourceType !== "file") policyCounts.non_file++;
            else if (denial.accessType === "read") policyCounts.read++;
            else if (denial.accessType === "write") policyCounts.write++;
            else policyCounts.other++;
            if (denial.resourceType === "file" && denial.accessType === "read") {
              currentReads.add(key);
              if (root !== "other") currentRoots.add(root);
            }
          }
          check(currentReads.size <= partial.filesystem_read_denial_occurrences);
          check(policyCounts.write <= partial.filesystem_write_denial_occurrences);
          check(policyCounts.other <= partial.filesystem_other_denial_occurrences);
          check(policyCounts.non_file <= partial.other_actionable_denial_occurrences);
          for (const key of currentReads) {
            if (readResources.has(key)) partial.repeated_read_resource_launches++;
            readResources.add(key);
          }
          for (const root of currentRoots) {
            if (readRoots.has(root)) partial.repeated_read_root_launches++;
            readRoots.add(root);
          }
          for (const key of METRICS) add(known, key, partial[key]);
          events.push(...currentEvents);
          artifacts.push({
            launch_id: launchId, started_sha256: started.sha256, completed_sha256: finished.sha256,
            policy_sha256: policy.sha256, verbose_sha256: verbose.sha256,
          });
          completed++;
        } catch {
          issues.push(`${launchId}: native capture is missing, invalid or failed`);
        }
      }
    } catch {
      issues.push("native capture directory is missing or invalid");
    }
    if (config.calibration_path) {
      try {
        const calibration = document(path.resolve(directory, config.calibration_path)).value;
        check(calibration.schema_version === 1 && calibration.source_kind === "native_mxc_calibration");
        check(calibration.passed === true && calibration.mode === "block");
        check(calibration.coverage_scope === DENIAL_SCOPE);
        check(typeof config.codex_binary_sha256 === "string"
          && /^[a-f0-9]{64}$/.test(config.codex_binary_sha256)
          && calibration.codex_binary_sha256 === config.codex_binary_sha256);
        check(typeof config.policy_sha256 === "string" && /^[a-f0-9]{64}$/.test(config.policy_sha256)
          && calibration.policy_sha256 === config.policy_sha256);
        check(["enforcement", "input_integrity", "capture_documents_valid",
          "unlisted_read", "shared_write", "ordinary_error_not_denial"]
          .every(key => calibration.checks?.[key] === true));
      } catch {
        issues.push("native capture calibration is missing, invalid or failed");
      }
    } else issues.push("native capture calibration was not supplied");
  }
  known.filesystem_unique_read_resources = readResources.size;
  const complete = issues.length === 0;
  return {
    denial_metric_scope: DENIAL_SCOPE,
    denial_capture_complete: complete,
    native_launches: launches.length,
    native_completed_captures: completed,
    ...Object.fromEntries(METRICS.map(key => [key, complete ? known[key] : null])),
    known_denials: known,
    denial_issues: issues,
    events,
    artifacts,
  };
}

module.exports = { collectDenials, DENIAL_SCOPE, METRICS };
