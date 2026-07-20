/**
 * Test script for platform detection
 * Run with: node test-platform.js
 */

const { getPlatformSupport } = require('./dist/index');

console.log('WXC Platform Detection Test');
console.log('='.repeat(60));
console.log();

// Test getPlatformSupport()
const platformInfo = getPlatformSupport();
const supported = platformInfo.isSupported;
console.log('getPlatformSupport():');
console.log('  Supported:', supported);
console.log('  Available Methods:', platformInfo.availableMethods.join(', ') || 'None');

if (platformInfo.reason) {
  console.log('  Reason:', platformInfo.reason);
}

console.log();
console.log('='.repeat(60));

// Exit with appropriate code
process.exit(supported ? 0 : 1);
