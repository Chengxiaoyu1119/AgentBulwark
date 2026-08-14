const fs = require('node:fs');
const path = require('node:path');

const target = path.join(__dirname, '..', 'node_modules', 'gray-matter', 'lib', 'engines.js');

if (!fs.existsSync(target)) {
  console.warn(`[docs postinstall] gray-matter engines file not found: ${target}`);
  process.exit(0);
}

const source = fs.readFileSync(target, 'utf8');
let patched = source
  .replace('parse: yaml.safeLoad.bind(yaml),', 'parse: (yaml.load || yaml.safeLoad).bind(yaml),')
  .replace('stringify: yaml.safeDump.bind(yaml)', 'stringify: (yaml.dump || yaml.safeDump).bind(yaml)');

if (patched === source) {
  const alreadyPatched =
    source.includes('(yaml.load || yaml.safeLoad).bind(yaml)') &&
    source.includes('(yaml.dump || yaml.safeDump).bind(yaml)');
  if (!alreadyPatched) {
    throw new Error('[docs postinstall] gray-matter engines file did not match expected content');
  }
}

fs.writeFileSync(target, patched);
console.log('[docs postinstall] patched gray-matter for js-yaml 4 compatibility');
