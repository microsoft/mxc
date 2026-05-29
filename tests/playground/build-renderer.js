// Build script: copies static files to dist/renderer
const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, 'src', 'renderer');
const distDir = path.join(__dirname, 'dist', 'renderer');

fs.mkdirSync(distDir, { recursive: true });

// Copy HTML and CSS
for (const file of ['index.html', 'styles.css']) {
  fs.copyFileSync(path.join(srcDir, file), path.join(distDir, file));
}

console.log('Renderer static files copied.');
