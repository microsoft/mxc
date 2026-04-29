const { readdirSync } = require('fs');
const { join } = require('path');
const { execFileSync } = require('child_process');

const files = readdirSync('dist')
  .filter(f => f.endsWith('.test.js'))
  .map(f => join('dist', f));

if (!files.length) {
  console.error('No test files found in dist/');
  process.exit(1);
}

execFileSync(process.execPath, [
  '--test', '--test-reporter', 'spec', '--test-force-exit', ...files
], { stdio: 'inherit' });
