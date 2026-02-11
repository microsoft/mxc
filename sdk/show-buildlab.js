/**
 * Display BuildLab registry value
 */

const { execSync } = require('child_process');

try {
  const command = 'reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion" /v BuildLab';
  const output = execSync(command, { encoding: 'utf-8' });
  console.log('Registry Query Output:');
  console.log(output);

  // Parse the value
  const lines = output.split('\n');
  for (const line of lines) {
    if (line.includes('BuildLab')) {
      const match = line.match(/REG_\w+\s+(.+)/);
      if (match) {
        const buildLab = match[1].trim();
        console.log('BuildLab value:', buildLab);

        const parts = buildLab.split('.');
        console.log('  Build Number:', parts[0]);
        console.log('  Branch:', parts[1]);
        console.log('  Build Date:', parts[2]);

        const buildNumber = parseInt(parts[0], 10);
        console.log('\nValidation:');
        console.log('  Build >= 26559?', buildNumber >= 26559);
        console.log('  Branch = ge_current_directwinai?', parts[1] === 'ge_current_directwinai');
      }
    }
  }
} catch (error) {
  console.error('Error querying registry:', error.message);
  process.exit(1);
}
