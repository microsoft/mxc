'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { isIP } = require('node:net');
const { isDeepStrictEqual } = require('node:util');

const reserved = /^(learningModeLogging|permissiveLearningMode)$/i;
const uiPermissions = [
  'win32k', 'clipboardRead', 'clipboardWrite', 'inputInjection', 'externalUiObjects',
  'globalUiNamespace', 'desktopSystemControl', 'systemParameters', 'displaySettings', 'ime',
];

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function normalized(file) {
  requireValue(typeof file === 'string' && /^[a-z]:\\/i.test(file), `Absolute local Windows path required: ${file}`);
  const parts = file.slice(3).replace(/\\$/, '').split('\\');
  requireValue(!/[\x00-\x1f<>:"|?*/]/.test(file.slice(2)) &&
    (file.length === 3 || parts.every(p => p && p !== '.' && p !== '..' &&
      !/[. ]$/.test(p) && !/~\d+(?:\.|$)/.test(p))),
  `Ambiguous/unsupported path: ${file}`);
  return file.replace(/\\$/, '').toLowerCase();
}

const within = (file, root) => file === root || file.startsWith(`${root}\\`);
const overlaps = (a, b) => within(a, b) || within(b, a);
const capabilityName = value => typeof value === 'string' && /^[a-z][a-z0-9._-]*$/i.test(value) &&
  !/^S-1-/i.test(value) && !reserved.test(value);

function noAliases(file) {
  normalized(file);
  let current = path.win32.parse(file).root;
  for (const part of file.slice(current.length).split('\\').filter(Boolean)) {
    current = path.win32.join(current, part);
    try {
      requireValue(!fs.lstatSync(current).isSymbolicLink(), `Path alias requires manual review: ${current}`);
    } catch (error) {
      if (error.code === 'ENOENT') break;
      throw error;
    }
  }
}

function ipNumber(address) {
  const family = isIP(address);
  requireValue(family && !address.includes('%'), `Unsupported numeric IP address: ${address}`);
  if (family === 4) {
    return { bits: 32, value: address.split('.').reduce((value, part) => (value << 8n) | BigInt(part), 0n) };
  }
  const canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  const halves = canonical.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 1 ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return { bits: 128, value: words.reduce((value, word) => (value << 16n) | BigInt(`0x${word}`), 0n) };
}

function cidrContains(cidr, address) {
  requireValue(typeof cidr === 'string' && /^[^/]+\/\d+$/.test(cidr), `Unsupported baseline CIDR: ${cidr}`);
  const [host, length] = cidr.split('/');
  const network = ipNumber(host);
  const target = ipNumber(address);
  const prefix = Number(length);
  requireValue(prefix <= network.bits, `Invalid baseline CIDR: ${cidr}`);
  if (network.bits !== target.bits) return false;
  const shift = BigInt(network.bits - prefix);
  return (network.value >> shift) === (target.value >> shift);
}

function networkEndpoint(resource) {
  const match = /^(tcp|udp|icmp|icmpv6):\/\/(?:\[([0-9a-f:.]+)\]|([0-9.]+))(?::([0-9]+))?$/i.exec(resource);
  requireValue(match, 'Network evidence needs an exact numeric IP and supported protocol; TCP/UDP also need a port');
  const scheme = match[1].toLowerCase();
  const rawHost = match[2] ?? match[3];
  const family = isIP(rawHost);
  requireValue(family && (family === 6) === Boolean(match[2]), 'Malformed numeric network endpoint');
  const host = family === 6 ? new URL(`http://[${rawHost}]/`).hostname.slice(1, -1) : rawHost;
  const transport = scheme === 'tcp' || scheme === 'udp';
  const port = match[4] === undefined ? undefined : Number(match[4]);
  requireValue(transport ? Number.isInteger(port) && port > 0 && port <= 65535 :
    port === undefined && (scheme === 'icmpv6' ? family === 6 : family === 4), 'Incomplete or inconsistent network endpoint');
  return {
    host, protocol: transport ? scheme : 'icmp', port,
    resource: `${scheme}://${family === 6 ? `[${host}]` : host}${transport ? `:${port}` : ''}`,
    rule: { to: [{ cidr: `${host}/${family === 6 ? 128 : 32}` }], ports: [{ protocol: transport ? scheme : 'icmp', ...(transport ? { port } : {}) }] },
  };
}

function portsMatch(rule, endpoint) {
  return rule.ports === undefined || rule.ports.some(selector =>
    (selector.protocol === undefined || selector.protocol === 'any' || selector.protocol === endpoint.protocol) &&
    (selector.port === undefined || (endpoint.port !== undefined &&
      endpoint.port >= selector.port && endpoint.port <= (selector.endPort ?? selector.port))));
}

function ruleMatches(rule, endpoint) {
  return portsMatch(rule, endpoint) && (rule.to === undefined || rule.to.some(peer =>
    cidrContains(peer.cidr, endpoint.host) && !(peer.except ?? []).some(cidr => cidrContains(cidr, endpoint.host))));
}

function networkConflict(base, endpoint) {
  if (base.runtimeConfig?.networkProxy) return 'Direct egress cannot be added to a proxy-based configuration';
  const egress = base.network?.egress ?? {};
  if ((egress.deny ?? []).some(rule => ruleMatches(rule, endpoint))) return 'Conflicts with an explicit network deny';
  if ((egress.allow ?? []).some(rule => portsMatch(rule, endpoint) &&
    (rule.to ?? []).some(peer => (peer.except ?? []).some(cidr => cidrContains(cidr, endpoint.host))))) {
    return 'Conflicts with an explicit network allow exclusion';
  }
  const numeric = ipNumber(endpoint.host);
  const loopback = numeric.bits === 32 ? (numeric.value >> 24n) === 127n :
    numeric.value === 1n || ((numeric.value >> 32n) === 65535n && ((numeric.value >> 24n) & 255n) === 127n);
  if (loopback && base.network?.ingress?.hostLoopback !== 'allow') {
    return 'Host-loopback access needs a separately approved baseline; an egress rule is not sufficient';
  }
  return null;
}

function configuredUi(config) {
  const ui = config.ui ?? {};
  const processUi = config.processContainer?.ui ?? {};
  const result = new Set();
  if (ui.disable === false) result.add('win32k');
  if (['read', 'all'].includes(ui.clipboard)) result.add('clipboardRead');
  if (['write', 'all'].includes(ui.clipboard)) result.add('clipboardWrite');
  if (ui.injection === true) result.add('inputInjection');
  if (['atoms', 'desktop'].includes(processUi.isolation)) result.add('externalUiObjects');
  if (['handles', 'desktop'].includes(processUi.isolation)) result.add('globalUiNamespace');
  if (processUi.desktopSystemControl === true) result.add('desktopSystemControl');
  if (['parameters', 'all'].includes(processUi.systemSettings)) result.add('systemParameters');
  if (['display', 'all'].includes(processUi.systemSettings)) result.add('displaySettings');
  if (processUi.ime === true) result.add('ime');
  return result;
}

function uiConflict(ceiling, permissions) {
  const explicit = {
    win32k: ceiling.ui?.disable,
    clipboardRead: ceiling.ui?.clipboard,
    clipboardWrite: ceiling.ui?.clipboard,
    inputInjection: ceiling.ui?.injection,
    externalUiObjects: ceiling.processContainer?.ui?.isolation,
    globalUiNamespace: ceiling.processContainer?.ui?.isolation,
    desktopSystemControl: ceiling.processContainer?.ui?.desktopSystemControl,
    systemParameters: ceiling.processContainer?.ui?.systemSettings,
    displaySettings: ceiling.processContainer?.ui?.systemSettings,
    ime: ceiling.processContainer?.ui?.ime,
  };
  const configured = configuredUi(ceiling);
  return permissions.find(permission => explicit[permission] !== undefined && !configured.has(permission));
}

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const valueAt = (value, field) => field.split('.').reduce((part, key) => part?.[key], value);
const uiFields = {
  'ui.disable': [false],
  'ui.clipboard': ['none', 'read', 'write', 'all'],
  'ui.injection': [true],
  'processContainer.ui.isolation': ['container', 'desktop', 'handles', 'atoms'],
  'processContainer.ui.desktopSystemControl': [true],
  'processContainer.ui.systemSettings': ['none', 'parameters', 'display', 'all'],
  'processContainer.ui.ime': [true],
};
const pathFields = {
  'filesystem.readonlyPaths': 'readonlyPaths',
  'filesystem.readwritePaths': 'readwritePaths',
  'processContainer.filesystem.enumeratePaths': 'enumeratePaths',
};

function differences(before, after, prefix = '') {
  if (isDeepStrictEqual(before, after)) return [];
  if (object(after) && (object(before) || before === undefined) && Object.keys(after).length) {
    return [...new Set([...Object.keys(before ?? {}), ...Object.keys(after)])].flatMap(key => {
      requireValue(!['__proto__', 'prototype', 'constructor'].includes(key) && !key.includes('.'),
        `Unsupported configuration property: ${key}`);
      return differences(before?.[key], after[key], prefix ? `${prefix}.${key}` : key);
    });
  }
  return [{ field: prefix, ...(before === undefined ? {} : { before }), ...(after === undefined ? {} : { after }) }];
}

function additions(edit) {
  const before = edit.before ?? [];
  requireValue(Array.isArray(before) && Array.isArray(edit.after) &&
    edit.after.length > before.length && isDeepStrictEqual(edit.after.slice(0, before.length), before),
  `Only append-only additions are supported: ${edit.field}`);
  const added = edit.after.slice(before.length);
  const seen = new Set(before.map(value => typeof value === 'string' ? value.toLowerCase() : JSON.stringify(value)));
  for (const value of added) {
    const key = typeof value === 'string' ? value.toLowerCase() : JSON.stringify(value);
    requireValue(!seen.has(key), `Duplicate addition: ${edit.field}`);
    seen.add(key);
  }
  return added;
}

function contentAdditions(edit, candidate, { ceiling, probe, checkAlias = noAliases }) {
  const before = edit.before ?? [];
  requireValue(Array.isArray(before) && Array.isArray(edit.after), `Expected path arrays: ${edit.field}`);
  const retained = before.filter(file => edit.after.includes(file));
  const removed = before.filter(file => !edit.after.includes(file));
  if (!removed.length) return additions(edit);
  requireValue(object(ceiling), 'The initial policy is required to identify generated content grants');
  const initial = new Set((valueAt(ceiling, edit.field) ?? []).map(normalized));
  requireValue(removed.every(file => !initial.has(normalized(file))),
    'Cannot remove initial content grants; only generated children can be consolidated');
  requireValue(isDeepStrictEqual(edit.after.slice(0, retained.length), retained),
    `Retain existing entries in order; new additions remain append-only: ${edit.field}`);
  const added = edit.after.length === retained.length ? [] : additions({ ...edit, before: retained });
  const previous = new Set(before.map(normalized));
  requireValue(added.every(file => !previous.has(normalized(file))),
    'Do not rename or re-add existing content grants during consolidation');
  requireValue(probe?.tier === 'base-container',
    'Generated-child consolidation requires a confirmed BaseContainer host');
  const denies = (candidate.filesystem?.deniedPaths ?? []).map(normalized);
  const otherGrants = Object.keys(pathFields).filter(field => field !== edit.field)
    .flatMap(field => valueAt(candidate, field) ?? []).map(normalized);
  for (const file of removed) {
    const child = normalized(file);
    const covered = edit.after.some(parent => {
      const root = normalized(parent);
      if (root.length <= 2 || child === root || !within(child, root) ||
        denies.some(deny => overlaps(root, deny)) ||
        otherGrants.some(other => within(other, root) && within(child, other))) return false;
      checkAlias(parent);
      return fs.lstatSync(parent, { throwIfNoEntry: false })?.isDirectory() === true;
    });
    requireValue(covered,
      `Removing ${file} requires an existing non-root directory parent in the same access list, without overlapping denied paths or intervening different-access grants`);
    checkAlias(file);
  }
  return added;
}

function endpointFromRule(rule) {
  requireValue(object(rule) && rule.to?.length === 1 && rule.ports?.length === 1,
    'Only single-destination, single-port/protocol egress additions are supported');
  const selector = rule.ports[0];
  const match = /^([^/]+)\/(32|128)$/.exec(rule.to[0].cidr ?? '');
  requireValue(match && isIP(match[1]) === (match[2] === '32' ? 4 : 6), 'Exact /32 or /128 egress destination required');
  const host = match[1];
  const scheme = selector.protocol === 'icmp' && isIP(host) === 6 ? 'icmpv6' : selector.protocol;
  const endpoint = networkEndpoint(`${scheme}://${isIP(host) === 6 ? `[${host}]` : host}${selector.port === undefined ? '' : `:${selector.port}`}`);
  requireValue(isDeepStrictEqual(rule, endpoint.rule), 'Egress additions must use canonical exact rules without extra fields');
  return endpoint;
}

function checkFilesystem(config, { resultsDir, protectedPaths = [], checkAlias = noAliases }) {
  const lists = Object.fromEntries([...Object.keys(pathFields), 'filesystem.deniedPaths'].map(field => {
    const values = valueAt(config, field) ?? [];
    requireValue(Array.isArray(values), `Expected path array: ${field}`);
    const normalizedValues = values.map(value => {
      checkAlias(value);
      return normalized(value);
    });
    requireValue(new Set(normalizedValues).size === normalizedValues.length, `Duplicate filesystem path: ${field}`);
    return [field, normalizedValues];
  }));
  const grants = Object.keys(pathFields);
  for (let i = 0; i < grants.length; i++) {
    for (const other of grants.slice(i + 1)) {
      requireValue(!lists[grants[i]].some(file => lists[other].includes(file)),
        'Same-path file intents conflict; MXC may normalize away the requested permission');
    }
  }
  for (const field of grants.slice(0, 2)) {
    for (const file of lists[field]) {
      requireValue(!overlaps(file, normalized(resultsDir)), 'Content grants must not overlap result artifacts');
      if (field === 'filesystem.readwritePaths') {
        requireValue(!protectedPaths.some(protectedPath => overlaps(file, normalized(protectedPath))),
          'Write grants must not overlap the helper or native runtime');
      }
    }
  }
}

function checkEnumeration(config, probe) {
  const paths = config.processContainer?.filesystem?.enumeratePaths ?? [];
  if (!paths.length) return;
  requireValue(config.processContainer.leastPrivilege !== true, 'enumeratePaths cannot combine with leastPrivilege');
  requireValue(probe?.tier === 'base-container' && probe.probes?.baseContainerSupportsEnumeratePaths === true,
    'Host probe does not confirm BaseContainer enumeratePaths support');
}

// This validates permission boundaries, not a denial-to-setting mapping.
function reviewCandidate(base, candidate, scopes, options) {
  requireValue(object(candidate), 'Candidate configuration must be an object');
  const diff = differences(base, candidate);
  requireValue(diff.length, 'Candidate must change the current configuration');
  const permissions = [];
  const denies = (base.filesystem?.deniedPaths ?? []).map(normalized);
  let uiChanged = false;
  for (const edit of diff) {
    const { field } = edit;
    if (Object.hasOwn(pathFields, field)) {
      const kind = pathFields[field];
      const added = kind === 'enumeratePaths' ? additions(edit) : contentAdditions(edit, candidate, options);
      for (const file of added) {
        const norm = normalized(file);
        requireValue(!denies.some(deny => overlaps(norm, deny)), 'Conflicts with an explicit denied path');
        let withinScope;
        if (kind === 'enumeratePaths') {
          withinScope = (scopes.enumeratePaths ?? []).some(root => normalized(root) === norm);
        } else {
          requireValue(norm.length > 2, 'Drive-root content grants are outside this POC');
          const roots = kind === 'readonlyPaths' ? [...scopes.readonlyPaths, ...scopes.readwritePaths] : scopes.readwritePaths;
          requireValue(roots.some(root => within(norm, normalized(root))),
            'Content path/access outside approved scope; use a separately approved session');
          withinScope = true;
        }
        permissions.push({
          field, kind, resource: file, withinScope,
          warning: kind === 'enumeratePaths' ?
            'Allows path queries and directory enumeration, not file-content reads. Names/metadata may be visible outside content-read scopes; not limited to one lstat.' :
            'Content access within an approved scope; directory grants may cover descendants. Necessity is not established by validation.',
        });
      }
    } else if (field === 'processContainer.capabilities') {
      for (const name of additions(edit)) {
        requireValue(capabilityName(name), 'Unsupported, unresolved, or reserved capability');
        permissions.push({
          field, kind: 'capability', resource: name,
          withinScope: scopes.capabilities.some(c => c.toLowerCase() === name.toLowerCase()),
          warning: name.toLowerCase() === 'registryread' ?
            'Broad registry-read capability, NOT a per-key grant.' :
            'Named capability effects require documented meaning and caller review; not a per-event permission.',
        });
      }
    } else if (Object.hasOwn(uiFields, field)) {
      requireValue(uiFields[field].includes(edit.after), `Unsupported UI value: ${field}`);
      uiChanged = true;
    } else if (field === 'network.egress.allow') {
      for (const rule of additions(edit)) {
        const endpoint = endpointFromRule(rule);
        const conflict = networkConflict(base, endpoint);
        requireValue(!conflict, conflict);
        requireValue(base.network?.egress?.default !== 'allow' &&
          !(base.network?.egress?.allow ?? []).some(existing => ruleMatches(existing, endpoint)),
        'Egress permission is already configured; investigate another cause');
        permissions.push({
          field, kind: 'network', resource: endpoint.resource,
          withinScope: (scopes.networkEgress ?? []).some(resource => networkEndpoint(resource).resource === endpoint.resource),
          warning: 'Exact numeric egress only; not hostname-wide permission. Defaults, ingress and proxy posture are unchanged.',
        });
      }
    } else {
      throw new Error(`Field is immutable or its permission effects are not supported for review: ${field}`);
    }
  }
  if (uiChanged) {
    const before = configuredUi(base);
    const after = configuredUi(candidate);
    requireValue([...before].every(permission => after.has(permission)), 'Do not remove or replace existing UI permissions');
    const added = [...after].filter(permission => !before.has(permission));
    requireValue(added.length, 'UI change adds no permission; remove unrelated edits');
    // Activating Win32k can activate permissions already present in the baseline.
    const activated = added.includes('win32k') ? [...after] : added;
    const conflict = uiConflict(options.ceiling, activated);
    requireValue(!conflict, `Conflicts with an explicit baseline UI restriction: ${conflict}`);
    for (const permission of activated) {
      permissions.push({
        kind: 'ui', resource: permission,
        withinScope: (scopes.ui ?? []).includes(permission),
        warning: permission === 'desktopSystemControl' ?
          'Includes both desktop management and logoff/shutdown.' :
          'UI operation-class access; enabling Win32k can activate other configured UI permissions.',
      });
    }
  }
  checkFilesystem(candidate, options);
  checkEnumeration(candidate, options.probe);
  return { diff, permissions, requiresApproval: true };
}

module.exports = {
  normalized, within, overlaps, noAliases, capabilityName, uiPermissions, networkEndpoint,
  reviewCandidate, checkFilesystem, checkEnumeration,
};
