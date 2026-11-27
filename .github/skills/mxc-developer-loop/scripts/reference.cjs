'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const digest = value => createHash('sha256').update(value).digest('hex');
const directory = path.resolve(__dirname, '..', 'references');

function loadReference(root = directory) {
  const bytes = fs.readFileSync(path.join(root, 'manifest.json'));
  const manifest = JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
  if (manifest.contractVersion !== '1.0.0' || !Array.isArray(manifest.files) ||
    !manifest.files.length || !/^[a-f0-9]{40}$/.test(manifest.sourceRevision)) {
    throw new Error('Unsupported or incomplete bundled MXC reference manifest');
  }
  const files = [];
  for (const entry of manifest.files) {
    if (typeof entry.file !== 'string' || !/^[a-z0-9.-]+$/i.test(entry.file) ||
      digest(fs.readFileSync(path.join(root, entry.file))) !== entry.sha256) {
      throw new Error(`Bundled MXC reference integrity failure: ${entry.file}`);
    }
    files.push(entry.file);
  }
  if (!files.includes('mxc-config.schema.1.0.0.json') || !files.includes('policy-1.0.0.md') ||
    !files.includes('configuration-notes.md')) throw new Error('Required MXC reference files are missing');
  return { directory: root, digest: digest(bytes), contractVersion: manifest.contractVersion,
    sourceRevision: manifest.sourceRevision, files };
}

module.exports = { loadReference, digest };
