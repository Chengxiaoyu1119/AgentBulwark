import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('apps/api/agent_supervisor');
const requiredDirectories = [
  'adapters',
  'adapters/integrations',
  'adapters/models',
  'adapters/proxy',
  'commands',
  'config',
  'domains',
  'domains/evidence',
  'domains/governance',
  'domains/runtime',
  'mcp_gateway',
  'routers',
  'schemas',
  'storage'
];
const forbiddenNames = [
  'sandbox',
  'attacks',
  'evaluations',
  'reports',
  'openclaw',
  'docker',
  'target_lab',
  'attack_lab',
  'redteam_lab'
];
const requiredFiles = [
  'main.py',
  'auth.py',
  'paths.py',
  'routers/core.py',
  'routers/integrations.py',
  'routers/mcp.py',
  'routers/proxy.py',
  'domains/runtime/tools.py',
  'domains/runtime/events.py',
  'domains/runtime/execution_receipts.py',
  'domains/governance/supervisor.py',
  'domains/governance/tool_contract.py'
];

const relative = (file) => path.relative(process.cwd(), file).replaceAll(path.sep, '/');
const isCachePath = (file) => file.split(path.sep).some((segment) => ['__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'].includes(segment));
const walk = (directory) => {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    if (['__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'].includes(entry.name)) return [];
    if (entry.isDirectory()) return walk(full);
    return [full];
  });
};

const missingDirectories = requiredDirectories.filter((entry) => !fs.existsSync(path.join(root, entry)));
const missingFiles = requiredFiles.filter((entry) => !fs.existsSync(path.join(root, entry)));
const forbiddenFiles = walk(root)
  .filter((file) => forbiddenNames.some((name) => path.basename(file).toLowerCase().includes(name)))
  .map(relative);
const pycacheFiles = walk(root).filter((file) => file.endsWith('.pyc')).map(relative);
const sourceText = walk(root)
  .filter((file) => file.endsWith('.py'))
  .map((file) => fs.readFileSync(file, 'utf8'))
  .join('\n');
const forbiddenSourceMarkers = ['openclaw', 'docker', 'code.run', 'wsl'];
const sourceMarkerHits = forbiddenSourceMarkers.filter((marker) => sourceText.toLowerCase().includes(marker.toLowerCase()));

const violations = [
  ...missingDirectories.map((entry) => `missing directory: ${entry}`),
  ...missingFiles.map((entry) => `missing file: ${entry}`),
  ...forbiddenFiles.map((entry) => `forbidden file: ${entry}`),
  ...pycacheFiles.map((entry) => `cache file: ${entry}`),
  ...sourceMarkerHits.map((entry) => `forbidden source marker: ${entry}`)
];

const result = {
  checked_at: new Date().toISOString(),
  root: relative(root),
  missing_directories: missingDirectories,
  missing_files: missingFiles,
  forbidden_files: forbiddenFiles,
  pycache_files: pycacheFiles,
  source_marker_hits: sourceMarkerHits,
  budget_status: violations.length ? 'failed' : 'passed',
  violations
};
console.log(JSON.stringify(result, null, 2));
if (violations.length) process.exit(1);
