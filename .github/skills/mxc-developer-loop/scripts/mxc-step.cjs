'use strict';

const fs = require('node:fs');
const path = require('node:path');
const childProcess = require('node:child_process');
const { isDeepStrictEqual } = require('node:util');
const {
  normalized, within, overlaps, noAliases, capabilityName, uiPermissions, networkEndpoint,
  reviewCandidate, checkFilesystem, checkEnumeration,
} = require('./candidates.cjs');
const { loadReference, digest } = require('./reference.cjs');
const { validateCaptureProbe } = require('./runtime.cjs');

const clone = value => structuredClone(value);
const parseJson = value => JSON.parse(value.toString('utf8').replace(/^\uFEFF/, ''));
const readJson = file => parseJson(fs.readFileSync(file));
const serialize = value => `${JSON.stringify(value, null, 2)}\n`;
const writeJson = (file, value) => fs.writeFileSync(file, serialize(value), { flag: 'wx' });
const internalPath = (dir, ...parts) => path.join(dir, '.internal', ...parts);
const reserved = /^(learningModeLogging|permissiveLearningMode)$/i;
const terminalStatuses = new Set([
  'succeeded', 'verification_failed', 'verification_incomplete', 'verification_error',
  'budget_exhausted', 'execution_error', 'capture_failed', 'setup_failed', 'declined', 'stopped',
]);

function replaceFile(file, contents) {
  const temp = `${file}.next`;
  fs.writeFileSync(temp, contents, { flag: 'wx' });
  fs.renameSync(temp, file);
}

function recordEvent(state, type, details = {}) {
  state.history.push({
    ...clone(details), sequence: state.history.length + 1, type, recordedAt: new Date().toISOString(),
  });
}

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function strings(value, label) {
  requireValue(Array.isArray(value) && value.every(v => typeof v === 'string' && v.length > 0),
    `${label} must be an array of nonempty strings`);
  return value;
}

function starter() {
  return {
    version: '1.0.0',
    containment: 'processcontainer',
    fallback: { allowDaclMutation: false },
    filesystem: { readonlyPaths: [], readwritePaths: [], deniedPaths: [] },
    processContainer: { capabilities: [] },
    network: {
      egress: { default: 'deny' },
      ingress: { default: 'deny', hostLoopback: 'deny' },
    },
  };
}

function prepare(spec, source, resultsDir) {
  requireValue(spec && typeof spec === 'object' && !Array.isArray(spec), 'Request must be an object');
  requireValue(spec.replaySafe === true, 'Caller must confirm replaySafe for this workload before initialization');
  const result = {
    expectedExitCode: 0, functionalChecks: [], maxRuns: 3, maxWorkloadMs: 120000, ...clone(spec),
  };
  requireValue(Number.isInteger(result.expectedExitCode) &&
    result.expectedExitCode >= -2147483648 && result.expectedExitCode <= 2147483647, 'Invalid expectedExitCode');
  requireValue(Array.isArray(result.functionalChecks), 'functionalChecks must be an array');
  const checkIds = new Set();
  for (const check of result.functionalChecks) {
    requireValue(check && typeof check === 'object' && !Array.isArray(check) &&
      Object.keys(check).every(key => ['id', 'description'].includes(key)) &&
      typeof check.id === 'string' && /^[a-z][a-z0-9_-]*$/.test(check.id) &&
      typeof check.description === 'string' && check.description.trim(),
    'Each functional check requires an id (lowercase letters/digits/_/-) and a nonempty description; no other fields');
    requireValue(!checkIds.has(check.id), `Duplicate functional check id: ${check.id}`);
    checkIds.add(check.id);
  }
  requireValue(Number.isSafeInteger(result.maxRuns) && result.maxRuns > 0, 'maxRuns must be a positive integer');
  requireValue(Number.isSafeInteger(result.maxWorkloadMs) && result.maxWorkloadMs > 0 &&
    result.maxWorkloadMs <= 2147453647, 'maxWorkloadMs must be between 1 and 2147453647');
  requireValue(typeof result.commandLine === 'string' && result.commandLine.trim(), 'commandLine is required');
  for (const key of ['mxcExecutable', 'applicationPath', 'cwd']) normalized(result[key]);
  const scopes = result.allowedChanges;
  requireValue(scopes && typeof scopes === 'object', 'allowedChanges is required; use empty arrays for no additions');
  for (const key of ['readonlyPaths', 'readwritePaths', 'capabilities']) strings(scopes[key], `allowedChanges.${key}`);
  for (const file of [...scopes.readonlyPaths, ...scopes.readwritePaths]) {
    requireValue(normalized(file).length > 2, 'A whole drive is not an approved addition scope');
    requireValue(!overlaps(normalized(file), normalized(resultsDir)), 'Grant scopes must not overlap result artifacts');
    noAliases(file);
  }
  requireValue(!within(normalized(resultsDir), normalized(result.cwd)), 'Results must be outside the workload cwd');
  requireValue(scopes.capabilities.every(capabilityName), 'Only explicit non-reserved capability names may be approved');
  strings(scopes.ui ??= [], 'allowedChanges.ui');
  requireValue(scopes.ui.every(permission => uiPermissions.includes(permission)), 'Unknown allowedChanges.ui permission');
  strings(scopes.networkEgress ??= [], 'allowedChanges.networkEgress');
  for (const endpoint of scopes.networkEgress) networkEndpoint(endpoint);
  strings(scopes.enumeratePaths ??= [], 'allowedChanges.enumeratePaths');
  for (const file of scopes.enumeratePaths) noAliases(file);
  for (const root of scopes.readwritePaths) {
    requireValue(!protectedPaths(result).some(file => overlaps(normalized(root), normalized(file))),
      'Write scopes must not overlap the helper or native runtime');
  }

  requireValue(source === null || (source && typeof source === 'object' && !Array.isArray(source)), 'Baseline must be an object');
  const baseline = source === null ? starter() : clone(source);
  requireValue(baseline.version === '1.0.0', 'Only the 1.0.0 MXC contract is supported');
  requireValue(!baseline.containment || baseline.containment === 'processcontainer', 'ProcessContainer is required');
  requireValue(baseline.fallback?.allowDaclMutation !== true, 'DACL mutation is outside this POC');
  baseline.fallback = { ...baseline.fallback, allowDaclMutation: false };
  baseline.containment = 'processcontainer';
  baseline.processContainer ??= {};
  requireValue(typeof baseline.processContainer === 'object' && !Array.isArray(baseline.processContainer),
    'processContainer must be an object');
  requireValue(!baseline.processContainer.captureDenials?.mode ||
    baseline.processContainer.captureDenials.mode === 'block', 'Permissive capture is not supported');
  requireValue(baseline.processContainer.learningMode !== true, 'Use enforced capture, not legacy learningMode');
  const caps = strings(baseline.processContainer.capabilities ?? [], 'baseline capabilities');
  requireValue(caps.every(c => !reserved.test(c)), 'Reserved learning capabilities are not supported');
  for (const key of ['readonlyPaths', 'readwritePaths', 'deniedPaths']) {
    for (const file of strings(baseline.filesystem?.[key] ?? [], `filesystem.${key}`)) {
      noAliases(file);
      if (key !== 'deniedPaths') {
        requireValue(!overlaps(normalized(file), normalized(resultsDir)), 'Baseline grants overlap result artifacts');
      }
    }
  }
  baseline.process = { ...baseline.process, commandLine: result.commandLine, cwd: result.cwd };
  requireValue(baseline.process.timeout === undefined ||
    (Number.isInteger(baseline.process.timeout) && baseline.process.timeout >= 0 &&
      baseline.process.timeout <= 4294967295), 'Invalid baseline process.timeout');
  baseline.processContainer.captureDenials = { mode: 'block', retainEtl: false };
  checkFilesystem(baseline, { resultsDir, protectedPaths: protectedPaths(result) });
  return { spec: result, baseline };
}

function protectedPaths(spec) {
  return [path.resolve(__dirname, '..'), path.win32.dirname(spec.mxcExecutable)];
}

function invoke(exe, args, cwd, prefix, timeout) {
  const out = fs.openSync(`${prefix}.stdout.txt`, 'wx');
  const err = fs.openSync(`${prefix}.stderr.txt`, 'wx');
  const start = performance.now();
  let processResult;
  try {
    processResult = childProcess.spawnSync(exe, args, {
      cwd, windowsHide: true, shell: false, timeout, stdio: ['ignore', out, err],
    });
  } finally {
    fs.closeSync(out);
    fs.closeSync(err);
  }
  return {
    exitCode: processResult.status === null ? null : processResult.status | 0,
    elapsedMs: Math.ceil(performance.now() - start),
    error: processResult.error?.message ?? (processResult.signal ? `Terminated: ${processResult.signal}` : null),
    stdout: `${prefix}.stdout.txt`, stderr: `${prefix}.stderr.txt`,
  };
}

function jsonLines(file) {
  requireValue(fs.statSync(file).size <= 8 * 1024 * 1024, `Output too large to inspect automatically: ${file}`);
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).flatMap(line => {
    // Native startup diagnostics can precede their JSON envelope without a newline.
    for (const match of line.matchAll(/\{\s*"(?:type|error)"\s*:/g)) {
      try { return [JSON.parse(line.slice(match.index))]; } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
      }
    }
    return [];
  });
}

function checkDocument(document) {
  requireValue(document && Array.isArray(document.denials) && document.summary, 'Malformed actionable document');
  const summary = document.summary;
  requireValue(Number.isInteger(summary.exitCode) && summary.totalDenials === document.denials.length &&
    typeof summary.deniedResourcesTruncated === 'boolean', 'Inconsistent actionable summary');
  for (const denial of document.denials) {
    requireValue(denial && typeof denial.resource === 'string' && typeof denial.resourceType === 'string' &&
      typeof denial.accessType === 'string', 'Malformed actionable denial');
  }
  return document;
}

function startupError(errors, exitCode) {
  return exitCode === -1073741502 && errors.length === 1 &&
    errors[0].error?.code === 'backend_error' &&
    typeof errors[0].error.message === 'string' &&
    errors[0].error.message.includes('STATUS_DLL_INIT_FAILED');
}

function readCapture(run) {
  const lines = jsonLines(run.stderr);
  const errors = lines.filter(line => line.error || line.type === 'captureDenialsError');
  const startupFailure = startupError(errors, run.exitCode);
  requireValue(errors.length === 0 || startupFailure, `MXC error: ${JSON.stringify(errors)}`);
  const pointers = lines.filter(line => line.type === 'captureDenials');
  requireValue(pointers.length === 1, 'Expected exactly one captureDenials pointer on stderr');
  const pointer = pointers[0];
  requireValue(typeof pointer.outputPath === 'string' &&
    path.win32.dirname(pointer.outputPath).toLowerCase() === path.win32.dirname(run.request).toLowerCase() &&
    /^denials\.[^.]+\.json$/i.test(path.win32.basename(pointer.outputPath)),
  'Capture pointer is not the unique output requested for this run');
  const bytes = fs.readFileSync(pointer.outputPath);
  const document = checkDocument(parseJson(bytes));
  requireValue(!startupFailure || document.denials.some(d => d.resourceType === 'ui' && d.resource === 'ConvertToGui'),
    'DLL initialization failure has no actionable ConvertToGui evidence; do not infer a UI grant');
  requireValue(document.summary.exitCode === run.exitCode, 'Capture exit code does not match executor exit code');
  for (const key of ['exitCode', 'totalDenials', 'deniedResourcesTruncated']) {
    requireValue(pointer[key] === document.summary[key], `Capture pointer mismatch: ${key}`);
  }
  return { pointer, document, startupFailure, errors, digest: digest(bytes) };
}

function evaluateFunctionalChecks(checks, stdout) {
  const records = new Map();
  const duplicates = new Set();
  const errors = [];
  const ids = new Set(checks.map(check => check.id));
  if (fs.statSync(stdout).size > 8 * 1024 * 1024) {
    errors.push('stdout exceeds the 8 MiB verification limit; functional checks were not evaluated');
  } else {
    const lines = fs.readFileSync(stdout, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      const prefix = 'MXC_FUNCTIONAL_CHECK ';
      if (!line.startsWith(prefix)) continue;
      const location = `stdout line ${index + 1}`;
      let record;
      try {
        record = JSON.parse(line.slice(prefix.length));
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
        errors.push(`${location}: malformed functional-check JSON`);
        continue;
      }
      if (!record || typeof record !== 'object' || Array.isArray(record) ||
        !ids.has(record.id) || typeof record.passed !== 'boolean' ||
        typeof record.evidence !== 'string' || !record.evidence.trim() ||
        !Object.keys(record).every(key => ['id', 'passed', 'evidence'].includes(key))) {
        errors.push(`${location}: expected an agreed id, boolean passed, and nonempty evidence; no other fields`);
        continue;
      }
      if (records.has(record.id)) {
        duplicates.add(record.id);
        errors.push(`${location}: duplicate functional check ${record.id}`);
      } else {
        records.set(record.id, { ...record, line: index + 1 });
      }
    }
  }
  const results = checks.map(check => {
    const record = records.get(check.id);
    const status = !record || duplicates.has(check.id) ? 'not_assessed' : record.passed ? 'verified' : 'failed';
    if (!record) errors.push(`No result for functional check ${check.id}`);
    return { ...check, status, evidence: record?.evidence ?? null, line: record?.line ?? null };
  });
  const status = results.some(check => check.status === 'failed') ? 'failed' :
    errors.length ? 'not_assessed' : 'verified';
  return {
    status,
    reason: status === 'verified' ? 'All agreed checks reported passing results; not independent host verification' :
      status === 'failed' ? 'At least one agreed functional check reported failure; diagnose before any further execution' :
        'Functional verification is incomplete or invalid; do not infer success',
    checks: results, errors,
  };
}

function resultOf(state) {
  const last = state.runs.at(-1);
  const tested = [...state.runs].reverse().find(run => run.completed);
  return {
    ...(state.formatVersion === 5 ? {
      artifacts: {
        baseline: state.initial,
        finalConfig: terminalStatuses.has(state.status) && tested ?
          path.join(path.dirname(state.initial), 'final-config.json') : null,
        history: path.join(path.dirname(state.initial), 'history.jsonl'),
        summary: path.join(path.dirname(state.initial), 'summary.json'),
        workingConfig: internalPath(path.dirname(state.initial), 'working-config.json'),
      },
      proposalId: state.proposal?.proposalId ?? null,
    } : {}),
    status: state.status,
    reason: state.reason ?? null,
    expectedExitCode: state.spec.expectedExitCode,
    observedExitCode: last?.exitCode ?? null,
    metExpectedExitCode: last?.metExpectedExitCode ?? state.status === 'succeeded',
    functionalCorrectness: last?.functionalVerification?.status ?? 'not_assessed',
    functionalVerification: last?.functionalVerification ?? {
      status: 'not_assessed',
      reason: state.spec.functionalChecks?.length ? 'No completed functional verification for this execution' :
        'No functional checks were agreed; exit-code-only verification',
      checks: [], errors: [],
    },
    requestedFunctionalChecks: state.spec.functionalChecks ?? [],
    runsUsed: state.runs.length,
    maxRuns: state.spec.maxRuns,
    executionMsCharged: state.usedMs,
    maxWorkloadMs: state.spec.maxWorkloadMs,
    lastTestedConfig: tested?.request ?? null,
    lastTestedPolicy: tested?.policy ?? null,
    lastExecutionAttempt: last?.request ?? null,
    untestedCandidate: state.current !== tested?.policy ? state.current : null,
    rejectedCandidate: state.rejectedCandidate ?? null,
    latestProposal: state.latestProposal ?? null,
    latestApproval: state.latestApproval ?? null,
    pendingApproval: state.status === 'awaiting_approval' ?
      (state.formatVersion >= 3 ? state.proposal.permissions.filter(permission =>
        state.formatVersion === 5 || !permission.preapproved) :
        state.proposal.pendingApproval ?? []) : [],
    pendingCandidate: state.status === 'awaiting_approval' ? state.proposal.candidatePath ?? null : null,
    proposalContext: state.context ?? null,
    reference: state.reference ?? null,
    runtime: state.runtime ?? null,
    runs: state.runs,
  };
}

function summaryOf(state) {
  const { runs, proposalContext, reference, runtime, ...result } = resultOf(state);
  const testedIndex = state.runs.findLastIndex(run => run.completed);
  const tested = state.runs[testedIndex];
  return {
    ...result,
    proposalsUsed: state.proposalCount,
    unresolved: state.proposal?.submission.unresolved ?? null,
    finalConfiguration: result.artifacts.finalConfig ? {
      runNumber: testedIndex + 1, policyDigest: tested.policyDigest,
      metExpectedExitCode: tested.metExpectedExitCode,
      functionalCorrectness: tested.functionalVerification?.status ?? 'not_assessed',
      functionalVerification: tested.functionalVerification ?? null,
    } : null,
  };
}

function logTail(file) {
  const limit = 2000;
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const buffer = Buffer.alloc(Math.min(size, limit * 4));
    const start = size - buffer.length;
    const length = fs.readSync(fd, buffer, 0, buffer.length, start);
    const text = buffer.subarray(0, length).toString('utf8');
    return { path: file, text: text.slice(-limit), truncated: start > 0 || text.length > limit };
  } finally {
    fs.closeSync(fd);
  }
}

function denialSummary(run) {
  const bytes = fs.readFileSync(run.denialsPath);
  requireValue(digest(bytes) === run.denialsDigest, 'Captured evidence changed; cannot summarize denials');
  const groups = new Map();
  for (const [index, denial] of checkDocument(parseJson(bytes)).denials.entries()) {
    const { resourceType, accessType, resource, pid } = denial;
    const key = JSON.stringify([resourceType, accessType, resource]);
    if (!groups.has(key)) groups.set(key, { resourceType, accessType, resource, indices: [], pids: [] });
    const group = groups.get(key);
    group.indices.push(index);
    if (pid !== undefined && !group.pids.includes(pid)) group.pids.push(pid);
  }
  return [...groups.values()];
}

function policyView(file, expectedDigest) {
  const bytes = fs.readFileSync(file);
  requireValue(digest(bytes) === expectedDigest, `Saved configuration changed; cannot display it as tested/reviewed: ${file}`);
  return { path: file, configuration: parseJson(bytes) };
}

function viewOf(state) {
  if (state.formatVersion !== 5) return resultOf(state);
  const view = { ...summaryOf(state), proposalContext: state.context ?? null };
  const last = state.runs.at(-1);
  if (view.finalConfiguration?.runNumber === state.runs.length) {
    delete view.finalConfiguration.functionalVerification;
  }
  if (last) {
    const { functionalVerification, stdout, stderr, stdoutDigest, stderrDigest, ...run } = last;
    view.lastRun = {
      ...run,
      ...(stdout ? { stdout: logTail(stdout) } : {}),
      ...(stderr ? { stderr: logTail(stderr) } : {}),
      ...(last.captureCompleted ? { denials: denialSummary(last) } : {}),
    };
  } else {
    view.hostProbe = state.runtime.probe ?? null;
    if (state.status === 'ready') view.preparedBaseline = policyView(state.initial, state.initialDigest);
  }
  const proposal = state.proposal;
  if (proposal && (['ready', 'awaiting_approval'].includes(state.status) ||
    last?.proposalId === proposal.proposalId)) {
    view.proposal = {
      proposalId: proposal.proposalId,
      basePolicy: proposal.basePolicy, baseDigest: proposal.baseDigest,
      candidatePath: proposal.candidatePath, candidateDigest: proposal.candidateDigest,
      requiresApproval: proposal.requiresApproval,
      diff: proposal.diff, permissions: proposal.permissions,
      changes: proposal.submission.changes, unresolved: proposal.submission.unresolved,
    };
    const approval = state.history.findLast(event =>
      event.type === 'approval_recorded' && event.proposalId === proposal.proposalId);
    if (approval) view.proposal.approval = {
      approvedByCaller: approval.approvedByCaller,
      retryApproved: approval.retryApproved === true, reason: approval.reason,
    };
  }
  if (view.artifacts.finalConfig) {
    view.testedPolicy = policyView(view.artifacts.finalConfig, view.finalConfiguration.policyDigest);
  } else if (terminalStatuses.has(state.status) && last && !view.lastTestedPolicy) {
    view.attemptedConfiguration = policyView(last.request, last.requestDigest);
  }
  return view;
}

function persist(dir, state) {
  const summary = summaryOf(state);
  if (summary.artifacts.finalConfig) {
    const policy = fs.readFileSync(summary.lastTestedPolicy);
    requireValue(digest(policy) === summary.finalConfiguration.policyDigest,
      'Last tested policy changed; cannot publish final-config.json');
    replaceFile(summary.artifacts.finalConfig, policy);
  }
  replaceFile(internalPath(dir, 'state.json'), serialize(state));
  replaceFile(path.join(dir, 'history.jsonl'),
    state.history.map(event => `${JSON.stringify(event)}\n`).join(''));
  replaceFile(path.join(dir, 'summary.json'), serialize(summary));
}

function terminal(state, status, reason) {
  state.status = status;
  state.reason = reason;
}

function initialize(specFile, dir) {
  requireValue(!fs.existsSync(dir), 'Results directory must be new');
  const spec = readJson(specFile);
  requireValue(spec && typeof spec === 'object' && !Array.isArray(spec), 'Request must be an object');
  if (Object.hasOwn(spec, 'commandLineFile')) {
    requireValue(!Object.hasOwn(spec, 'commandLine'), 'Use commandLine or commandLineFile, not both');
    normalized(spec.commandLineFile);
    requireValue(fs.statSync(spec.commandLineFile).isFile(), 'commandLineFile must be an existing file');
    spec.commandLine = fs.readFileSync(spec.commandLineFile, 'utf8').replace(/^\uFEFF/, '').replace(/\r?\n$/, '');
  }
  const source = spec.baselinePath ? readJson(spec.baselinePath) : null;
  if (spec.baselinePath) requireValue(source !== null, 'Supplied baseline must not be null');
  const prepared = prepare(spec, source, dir);
  const reference = loadReference();
  for (const key of ['mxcExecutable', 'applicationPath']) {
    requireValue(fs.statSync(prepared.spec[key]).isFile(), `Executable not found: ${key}`);
  }
  requireValue(fs.statSync(prepared.spec.cwd).isDirectory(), 'cwd must exist');
  fs.mkdirSync(internalPath(dir), { recursive: true });
  writeJson(internalPath(dir, 'request.json'), spec);
  if (source !== null) writeJson(internalPath(dir, 'supplied-baseline.json'), source);
  const current = path.join(dir, 'baseline.json');
  writeJson(current, prepared.baseline);
  writeJson(internalPath(dir, 'working-config.json'), prepared.baseline);
  const policyDigest = digest(fs.readFileSync(current));
  const state = {
    formatVersion: 5, spec: prepared.spec, initial: current, current, currentProposalId: null,
    initialDigest: policyDigest, currentDigest: policyDigest, reference,
    runtime: { executableDigest: digest(fs.readFileSync(prepared.spec.mxcExecutable)) },
    status: 'generating', runs: [], usedMs: 0, proposalCount: 0, history: [],
  };
  recordEvent(state, 'session_created', {
    baseline: current, baselineDigest: policyDigest,
    expectedExitCode: state.spec.expectedExitCode, functionalChecks: state.spec.functionalChecks,
  });
  persist(dir, state);
  try {
    probeHost(state, internalPath(dir, 'setup-probe'));
    checkEnumeration(prepared.baseline, state.runtime.probe);
    validatePolicy(state, current, internalPath(dir, 'setup-validation'));
    state.status = 'ready';
  } catch (error) {
    terminal(state, 'setup_failed', error.message);
  }
  recordEvent(state, 'setup_finished', { status: state.status, reason: state.reason ?? null });
  persist(dir, state);
  return state;
}

function probeHost(state, prefix) {
  state.runtime.probe = null;
  const result = invoke(state.spec.mxcExecutable, ['--probe'], state.spec.cwd, prefix, 30000);
  requireValue(!result.error && result.exitCode === 0, `Host probe failed; see ${result.stderr}`);
  const probe = readJson(result.stdout);
  state.runtime.probe = probe;
  validateCaptureProbe(probe, result.stdout);
}

function validatePolicy(state, file, prefix) {
  const result = invoke(state.spec.mxcExecutable, ['--config', file, '--dry-run'], state.spec.cwd, prefix, 30000);
  requireValue(!result.error && result.exitCode === 0 && !jsonLines(result.stderr).some(line => line.error),
    `Native validation failed; see ${result.stdout} and ${result.stderr}`);
}

function verifySession(state, dir) {
  requireValue(digest(fs.readFileSync(state.spec.mxcExecutable)) === state.runtime.executableDigest,
    'Selected executor changed; start a new approved session');
  requireValue(loadReference().digest === state.reference.digest, 'Bundled reference changed during this session');
  requireValue(digest(fs.readFileSync(state.initial)) === state.initialDigest, 'Initial policy changed');
  requireValue(digest(fs.readFileSync(state.current)) === state.currentDigest, 'Current policy changed');
  requireValue(isDeepStrictEqual(state.spec.functionalChecks, readJson(internalPath(dir, 'request.json')).functionalChecks ?? []),
    'Functional checks changed; start a new approved session rather than changing the success criteria');
  checkFilesystem(readJson(state.current), { resultsDir: dir, protectedPaths: protectedPaths(state.spec) });
}

function runOnce(dir, state) {
  requireValue(state.status === 'ready', `Cannot run from status ${state.status}`);
  const remaining = state.spec.maxWorkloadMs - state.usedMs;
  if (state.runs.length >= state.spec.maxRuns || remaining < 1) {
    terminal(state, 'budget_exhausted', 'No further workload execution is authorized');
    return;
  }
  verifySession(state, dir);
  const runDir = internalPath(dir, `run-${state.runs.length + 1}`);
  fs.mkdirSync(runDir);
  const request = readJson(state.current);
  probeHost(state, path.join(runDir, 'probe'));
  checkEnumeration(request, state.runtime.probe);
  const originalTimeout = request.process.timeout;
  request.process.timeout = Math.min(remaining, originalTimeout > 0 ? originalTimeout : remaining);
  request.processContainer.captureDenials = {
    mode: 'block', retainEtl: false, outputPath: path.join(runDir, 'denials.json'),
  };
  const requestPath = path.join(runDir, 'request.json');
  writeJson(requestPath, request);
  validatePolicy(state, requestPath, path.join(runDir, 'validation'));
  const run = {
    request: requestPath, requestDigest: digest(fs.readFileSync(requestPath)),
    policy: state.current, policyDigest: state.currentDigest, proposalId: state.currentProposalId,
    completed: false, timeoutMs: request.process.timeout,
  };
  state.runs.push(run);
  state.status = 'running';
  recordEvent(state, 'run_started', { runNumber: state.runs.length, ...run });
  persist(dir, state);
  Object.assign(run, invoke(state.spec.mxcExecutable, ['--config', requestPath],
    state.spec.cwd, path.join(runDir, 'execution'), request.process.timeout + 30000));
  state.usedMs += run.elapsedMs;
  if (run.error) {
    terminal(state, 'execution_error', run.error);
    return;
  }
  const envelopes = jsonLines(run.stderr).filter(line => line.error);
  if (envelopes.length && !startupError(envelopes, run.exitCode)) {
    terminal(state, 'execution_error', JSON.stringify(envelopes));
    return;
  }
  state.status = 'capturing';
  const capture = readCapture(run);
  const { pointer, document, startupFailure, errors } = capture;
  run.completed = !startupFailure;
  run.captureCompleted = true;
  run.startupFailure = startupFailure;
  if (errors.length) run.executionErrors = errors;
  run.denialsPath = pointer.outputPath;
  run.denialsDigest = capture.digest;
  run.stdoutDigest = digest(fs.readFileSync(run.stdout));
  run.stderrDigest = digest(fs.readFileSync(run.stderr));
  run.totalDenials = document.summary.totalDenials;
  run.truncated = document.summary.deniedResourcesTruncated;
  if (pointer.etlPath) run.sourceEtlPath = pointer.etlPath;
  run.metExpectedExitCode = !startupFailure && run.exitCode === state.spec.expectedExitCode;
  if (!startupFailure && state.spec.functionalChecks.length) {
    state.status = 'verifying';
    persist(dir, state);
    run.functionalVerification = evaluateFunctionalChecks(state.spec.functionalChecks, run.stdout);
  }
  if (run.functionalVerification?.status === 'failed') {
    terminal(state, 'verification_failed', run.functionalVerification.reason);
  } else if (run.metExpectedExitCode) {
    if (state.spec.functionalChecks.length && run.functionalVerification?.status !== 'verified') {
      terminal(state, 'verification_incomplete', run.functionalVerification.reason);
    } else {
      terminal(state, 'succeeded', state.spec.functionalChecks.length ?
        'This invocation met the expected exit code and all agreed functional checks reported passing results' :
        'This invocation met the expected exit code under enforced capture; functional outcome not assessed');
    }
  } else if (run.truncated) {
    terminal(state, 'capture_failed', 'Actionable evidence is truncated; no configuration will be generated');
  } else if (state.runs.length >= state.spec.maxRuns || state.usedMs >= state.spec.maxWorkloadMs) {
    terminal(state, 'budget_exhausted', 'Expected exit code was not reached within the agreed budget');
  } else {
    state.status = 'needs_proposal';
    state.reason = startupFailure ? 'Captured Win32k startup denial; review a UI proposal, not a successful execution' :
      'Inspect the failed execution before proposing changes';
    state.context = proposalContext(state);
  }
}

function proposalContext(state) {
  const run = state.runs.at(-1);
  requireValue(run?.captureCompleted, 'A completed, correlated capture is required');
  const capture = readCapture(run);
  requireValue(!capture.document.summary.deniedResourcesTruncated, 'Truncated evidence cannot generate a configuration');
  requireValue(capture.digest === run.denialsDigest, 'Captured evidence changed after execution');
  requireValue(digest(fs.readFileSync(run.stdout)) === run.stdoutDigest &&
    digest(fs.readFileSync(run.stderr)) === run.stderrDigest, 'Execution logs changed after capture');
  return {
    basePolicy: state.current, baseDigest: state.currentDigest,
    evidence: run.denialsPath, evidenceDigest: run.denialsDigest,
    stdout: run.stdout, stderr: run.stderr,
    referenceDigest: state.reference.digest,
  };
}

function buildProposal(dir, state, submission) {
  verifySession(state, dir);
  const context = proposalContext(state);
  requireValue(submission && typeof submission === 'object', 'Agent-authored candidate JSON is required');
  for (const key of ['baseDigest', 'evidenceDigest', 'referenceDigest']) {
    requireValue(submission[key] === context[key], `Candidate ${key} is missing or stale`);
  }
  const review = reviewCandidate(readJson(state.current), submission.configuration, state.spec.allowedChanges, {
    ceiling: readJson(state.initial), probe: state.runtime.probe, resultsDir: dir,
    protectedPaths: protectedPaths(state.spec),
  });
  requireValue(Array.isArray(submission.changes) && submission.changes.length === review.diff.length,
    'Explain every changed field exactly once in changes');
  const fields = new Set();
  const count = readJson(context.evidence).denials.length;
  for (const change of submission.changes) {
    requireValue(change && review.diff.some(edit => edit.field === change.field) && !fields.has(change.field),
      'Change explanation has a duplicate or unmatched field');
    fields.add(change.field);
    requireValue(typeof change.reason === 'string' && change.reason.trim() &&
      typeof change.uncertainty === 'string' && change.uncertainty.trim(), 'Each change needs reason and uncertainty');
    requireValue(Array.isArray(change.evidence) && change.evidence.length > 0 &&
      change.evidence.every(index => ['stdout', 'stderr'].includes(index) ||
        (Number.isInteger(index) && index >= 0 && index < count)), 'Invalid or missing evidence reference');
    requireValue(state.reference.files.includes(change.reference?.file) &&
      typeof change.reference.section === 'string' && change.reference.section.trim(),
    'Cite a bundled reference file and section for every change');
  }
  strings(submission.unresolved, 'unresolved');
  return {
    proposalId: state.proposalCount, ...context, ...review, submission,
    candidateDigest: digest(serialize(submission.configuration)),
  };
}

function activateCandidate(state) {
  state.current = state.proposal.candidatePath;
  state.currentDigest = state.proposal.candidateDigest;
  state.currentProposalId = state.proposal.proposalId;
  state.context = null;
  state.status = 'ready';
  state.reason = 'Exact agent-authored candidate validated and authorized, but not executed';
}

function propose(dir, state, file) {
  requireValue(file, 'propose requires an agent-authored candidate JSON file; no automatic mapper is available');
  let submission = readJson(file);
  const number = ++state.proposalCount;
  state.status = 'generating';
  state.proposal = null;
  state.latestProposal = null;
  state.latestApproval = null;
  recordEvent(state, 'proposal_submitted', {
    proposalId: number, baseDigest: submission?.baseDigest ?? null,
    requestedChanges: submission?.changes ?? null, unresolved: submission?.unresolved ?? null,
  });
  persist(dir, state);
  replaceFile(internalPath(dir, 'submission.json'), serialize(submission));
  requireValue(submission && typeof submission === 'object' && !Array.isArray(submission),
    'Agent-authored candidate JSON must be an object');
  if (!Object.hasOwn(submission, 'configuration')) {
    submission = { ...submission, configuration: readJson(internalPath(dir, 'working-config.json')) };
  }
  const proposal = buildProposal(dir, state, submission);
  proposal.candidatePath = internalPath(dir, `config-${number}.json`);
  writeJson(proposal.candidatePath, submission.configuration);
  state.rejectedCandidate = proposal.candidatePath;
  validatePolicy(state, proposal.candidatePath, internalPath(dir, `candidate-${number}-validation`));
  requireValue(isDeepStrictEqual(readJson(internalPath(dir, 'working-config.json')), readJson(proposal.candidatePath)),
    'Saved candidate does not match working-config.json; review the draft and submit a matching candidate');
  state.rejectedCandidate = null;
  state.proposal = proposal;
  state.latestProposal = internalPath(dir, 'proposal.json');
  replaceFile(state.latestProposal, serialize(state.proposal));
  const { submission: authored, ...reviewed } = proposal;
  recordEvent(state, 'proposal_reviewed', {
    ...reviewed, changes: authored.changes, unresolved: authored.unresolved,
    authorization: 'awaiting_approval',
  });
  state.status = 'awaiting_approval';
  state.reason = 'Approve these exact configuration changes and rerun once; the candidate is not active';
}

function approvalDecision(dir, state, file) {
  requireValue(file, 'An approval decision JSON file is required');
  const decision = readJson(file);
  requireValue(typeof decision?.approvedByCaller === 'boolean', 'Record the actual caller decision');
  requireValue(decision.retryApproved === undefined || typeof decision.retryApproved === 'boolean',
    'retryApproved must be a boolean');
  requireValue(!(decision.retryApproved && !decision.approvedByCaller), 'A declined candidate cannot be retried');
  requireValue(!Object.hasOwn(decision, 'approvedChangeIds'), 'Approval covers the whole candidate; submit a revision for a subset');
  requireValue(typeof decision.proposalPath === 'string' &&
    normalized(decision.proposalPath) === normalized(state.latestProposal) &&
    decision.proposalId === state.proposal.proposalId, 'Decision is for a different or stale proposal');
  requireValue(decision.candidateDigest === state.proposal.candidateDigest, 'Approval candidate digest is missing or stale');
  requireValue(typeof decision.reason === 'string' && decision.reason.trim(), 'A caller decision reason is required');
  const { candidatePath, ...saved } = state.proposal;
  requireValue(digest(fs.readFileSync(candidatePath)) === state.proposal.candidateDigest, 'Candidate changed after review');
  requireValue(isDeepStrictEqual(readJson(state.latestProposal), state.proposal) &&
    isDeepStrictEqual(buildProposal(dir, state, state.proposal.submission), saved),
  'Proposal or its evidence/baseline changed; do not apply stale approvals');
  return decision;
}

function approve(dir, state, decision) {
  state.latestApproval = internalPath(dir, 'approval.json');
  const approval = { ...decision, recordedAt: new Date().toISOString() };
  replaceFile(state.latestApproval, serialize(approval));
  recordEvent(state, 'approval_recorded', approval);
  if (!decision.approvedByCaller) terminal(state, 'declined', 'Caller declined the exact candidate; no changes activated');
  else activateCandidate(state);
}

function main(args, approvedRetry = null) {
  const [action, first, second] = args;
  requireValue(['init', 'run', 'propose', 'approve', 'status', 'stop'].includes(action) && first,
    'Usage: mxc-step.cjs init REQUEST NEW_RESULTS | run/status RESULTS | propose RESULTS CANDIDATE | approve RESULTS DECISION | stop RESULTS REASON');
  if (action === 'init') {
    requireValue(second, 'New results directory is required');
    return resultOf(initialize(path.resolve(first), path.resolve(second)));
  }
  const dir = path.resolve(first);
  const statePath = fs.existsSync(internalPath(dir, 'state.json')) ?
    internalPath(dir, 'state.json') : path.join(dir, 'state.json');
  if (action === 'status') return resultOf(readJson(statePath));
  const lock = path.join(dir, '.step.lock');
  const fd = fs.openSync(lock, 'wx');
  let result;
  let chainRun = null;
  try {
    const state = readJson(statePath);
    if (approvedRetry) requireValue(action === 'run' &&
      state.currentProposalId === approvedRetry.proposalId && state.currentDigest === approvedRetry.candidateDigest,
    'Approved retry was superseded; inspect status instead of executing a different candidate');
    requireValue(!['running', 'capturing', 'generating', 'verifying'].includes(state.status),
      'Prior operation was interrupted; do not replay it. Inspect side effects and start a new approved session');
    if (action === 'stop') {
      requireValue(state.formatVersion === 5, 'Start a new results directory with this helper version; old sessions remain readable');
      requireValue(second && second.trim(), 'A stop reason is required');
      terminal(state, 'stopped', second);
      recordEvent(state, 'stopped', { reason: second });
    } else {
      const expected = action === 'run' ? ['ready'] : action === 'approve' ? ['awaiting_approval'] :
        ['needs_proposal', 'awaiting_approval', 'candidate_rejected'];
      requireValue(expected.includes(state.status), `Cannot ${action} from status ${state.status}`);
      requireValue(state.formatVersion === 5, 'Start a new results directory with this helper version; old sessions remain readable');
      const decision = action === 'approve' ? approvalDecision(dir, state, second) : null;
      const runsBefore = state.runs.length;
      const proposalsBefore = state.proposalCount;
      try {
        if (action === 'run') runOnce(dir, state);
        else if (action === 'propose') propose(dir, state, second);
        else {
          approve(dir, state, decision);
          if (state.status === 'ready' && decision.retryApproved === true) chainRun = {
            proposalId: decision.proposalId, candidateDigest: decision.candidateDigest,
          };
        }
      } catch (error) {
        terminal(state, action !== 'run' ? 'candidate_rejected' :
          state.status === 'capturing' ? 'capture_failed' :
            state.status === 'verifying' ? 'verification_error' : 'execution_error', error.message);
        if (action === 'propose') recordEvent(state, 'proposal_rejected', {
          proposalId: state.proposalCount > proposalsBefore ? state.proposalCount : null, reason: error.message,
        });
      }
      if (action === 'run') recordEvent(state, state.runs.length > runsBefore ? 'run_finished' : 'run_not_started', {
        ...(state.runs.length > runsBefore ? { runNumber: state.runs.length, ...state.runs.at(-1) } : {}),
        status: state.status, reason: state.reason ?? null,
      });
    }
    persist(dir, state);
    result = resultOf(state);
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(lock);
  }
  return chainRun ? main(['run', dir], chainRun) : result;
}

function cli(args) {
  const full = args.at(-1) === '--full';
  const command = full ? args.slice(0, -1) : args;
  const result = main(command);
  if (full || !result.artifacts) return result;
  const dir = path.resolve(command[0] === 'init' ? command[2] : command[1]);
  return viewOf(readJson(internalPath(dir, 'state.json')));
}

if (require.main === module) {
  try {
    requireValue(process.platform === 'win32', 'MXC developer-loop execution requires Windows');
    console.log(JSON.stringify(cli(process.argv.slice(2)), null, 2));
  } catch (error) {
    console.error(JSON.stringify({ error: error.message }));
    process.exitCode = 1;
  }
}

module.exports = { prepare, starter, normalized, readCapture, checkDocument, resultOf, viewOf, main, cli };
