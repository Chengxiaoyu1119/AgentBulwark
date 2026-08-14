import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const apiRoot = path.join(root, 'apps', 'api', 'agent_supervisor');

const ignoredDirectories = new Set(['__pycache__']);
const allowedDirectories = new Set(['adapters', 'commands', 'config', 'domains', 'mcp_gateway', 'routers', 'schemas', 'services', 'storage']);
const coreRootPythonFiles = new Set(['__init__.py', 'auth.py', 'main.py', 'paths.py']);
const movedModules = {
  ablation: 'domains/evaluations/ablation.py',
  agent_integrations: 'adapters/integrations/agent_integrations.py',
  agents: 'domains/attacks/agents.py',
  anomaly: 'domains/governance/anomaly.py',
  approvals: 'domains/governance/approvals.py',
  assessment: 'domains/evaluations/assessment.py',
  attack_chains: 'domains/attacks/attack_chains.py',
  attack_lab: 'domains/attacks/attack_lab.py',
  attack_testsets: 'domains/attacks/attack_testsets.py',
  benign: 'domains/evaluations/benign.py',
  benign_cases_data: 'domains/evaluations/benign_cases_data.py',
  benign_cases_group1: 'domains/evaluations/benign_cases_group1.py',
  benign_cases_group2: 'domains/evaluations/benign_cases_group2.py',
  benign_workflows: 'domains/evaluations/benign_workflows.py',
  briefing_export: 'domains/reports/briefing_export.py',
  calibration: 'domains/evaluations/calibration.py',
  capability_replay: 'domains/attacks/capability_replay.py',
  cli: 'commands/cli.py',
  correlation: 'domains/governance/correlation.py',
  data: 'storage/data.py',
  database: 'storage/database.py',
  datasets: 'domains/evaluations/datasets.py',
  demo_drill: 'domains/evaluations/demo_drill.py',
  event_stream: 'domains/runtime/event_stream.py',
  events: 'domains/runtime/events.py',
  evidence: 'domains/evaluations/evidence.py',
  external_agent_demo: 'adapters/integrations/external_agent_demo.py',
  gap_rerun: 'domains/evaluations/gap_rerun.py',
  integrity: 'domains/governance/integrity.py',
  main_models: 'schemas/main_models.py',
  memory_governance: 'domains/runtime/memory_governance.py',
  model_adapter: 'adapters/models/model_adapter.py',
  model_runtime_config: 'adapters/models/model_runtime_config.py',
  openai_proxy: 'adapters/proxy/openai_proxy.py',
  openclaw_adapter: 'adapters/integrations/openclaw_adapter.py',
  openclaw_plugin_package: 'adapters/integrations/openclaw_plugin_package.py',
  openclaw_plugin_templates: 'adapters/integrations/openclaw_plugin_templates.py',
  penetration_lab: 'domains/attacks/penetration_lab.py',
  proxy_security: 'adapters/proxy/proxy_security.py',
  readiness: 'domains/reports/readiness.py',
  readiness_checks: 'domains/reports/readiness_checks.py',
  redteam_lab: 'domains/attacks/redteam_lab.py',
  risk_score: 'domains/governance/risk_score.py',
  roadmap: 'domains/reports/roadmap.py',
  runtime_evaluation: 'domains/runtime/runtime_evaluation.py',
  runtime_status: 'domains/runtime/runtime_status.py',
  supervisor: 'domains/governance/supervisor.py',
  surface_pack: 'domains/reports/surface_pack.py',
  surface_pack_html: 'domains/reports/surface_pack_html.py',
  target_lab: 'domains/attacks/target_lab.py',
  tools: 'domains/runtime/tools.py'
};
const allowedRootPythonFiles = new Set(coreRootPythonFiles);
const allowedDomainDirectories = new Set(['attacks', 'evaluations', 'governance', 'reports', 'runtime']);
const allowedAdapterDirectories = new Set(['integrations', 'models', 'proxy']);
const allowedTopLevelPackageFiles = new Set(['__init__.py']);

function readMaybe(file) {
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
}

function countLines(file) {
  const text = readMaybe(file);
  return text ? text.split(/\r?\n/).length : 0;
}

function listEntries(dir) {
  return fs.existsSync(dir) ? fs.readdirSync(dir, { withFileTypes: true }) : [];
}

function relative(file) {
  return path.relative(root, file).replaceAll(path.sep, '/');
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) return [];
      return walkFiles(fullPath);
    }
    return [fullPath];
  });
}

const rootEntries = listEntries(apiRoot);
const unexpectedRootDirectories = rootEntries
  .filter((entry) => entry.isDirectory() && !ignoredDirectories.has(entry.name) && !allowedDirectories.has(entry.name))
  .map((entry) => `apps/api/agent_supervisor/${entry.name}`);
const unexpectedRootPythonFiles = rootEntries
  .filter((entry) => entry.isFile() && entry.name.endsWith('.py') && !allowedRootPythonFiles.has(entry.name))
  .map((entry) => `apps/api/agent_supervisor/${entry.name}`);
const rootNonPythonFiles = rootEntries
  .filter((entry) => entry.isFile() && !entry.name.endsWith('.py'))
  .map((entry) => `apps/api/agent_supervisor/${entry.name}`);

const domainsRoot = path.join(apiRoot, 'domains');
const unexpectedDomainDirectories = listEntries(domainsRoot)
  .filter((entry) => entry.isDirectory() && !ignoredDirectories.has(entry.name) && !allowedDomainDirectories.has(entry.name))
  .map((entry) => `apps/api/agent_supervisor/domains/${entry.name}`);
const unexpectedDomainFiles = listEntries(domainsRoot)
  .filter((entry) => entry.isFile() && !allowedTopLevelPackageFiles.has(entry.name))
  .map((entry) => `apps/api/agent_supervisor/domains/${entry.name}`);

const adaptersRoot = path.join(apiRoot, 'adapters');
const unexpectedAdapterDirectories = listEntries(adaptersRoot)
  .filter((entry) => entry.isDirectory() && !ignoredDirectories.has(entry.name) && !allowedAdapterDirectories.has(entry.name))
  .map((entry) => `apps/api/agent_supervisor/adapters/${entry.name}`);
const unexpectedAdapterFiles = listEntries(adaptersRoot)
  .filter((entry) => entry.isFile() && !allowedTopLevelPackageFiles.has(entry.name))
  .map((entry) => `apps/api/agent_supervisor/adapters/${entry.name}`);

const missingMovedModules = Object.entries(movedModules)
  .filter(([, relativeTarget]) => !fs.existsSync(path.join(apiRoot, relativeTarget)))
  .map(([name, relativeTarget]) => ({ name, target: `apps/api/agent_supervisor/${relativeTarget}` }));

const legacyWrapperFiles = Object.entries(movedModules)
  .filter(([name]) => fs.existsSync(path.join(apiRoot, `${name}.py`)))
  .map(([name, relativeTarget]) => ({
    file: `apps/api/agent_supervisor/${name}.py`,
    target: `apps/api/agent_supervisor/${relativeTarget}`
  }));

const rootPythonSummary = rootEntries
  .filter((entry) => entry.isFile() && entry.name.endsWith('.py'))
  .map((entry) => {
    const fullPath = path.join(apiRoot, entry.name);
    const moduleName = entry.name.replace(/\.py$/, '');
    return {
      file: relative(fullPath),
      lines: countLines(fullPath),
      kind: coreRootPythonFiles.has(entry.name) ? 'core' : 'unexpected'
    };
  })
  .sort((a, b) => b.lines - a.lines || a.file.localeCompare(b.file));
const oversizedRootFiles = rootPythonSummary.filter((item) => item.kind === 'core' && item.lines > 120);

const packageInitMissing = [];
for (const dir of ['adapters', 'adapters/integrations', 'adapters/models', 'adapters/proxy', 'commands', 'domains', 'domains/attacks', 'domains/evaluations', 'domains/governance', 'domains/reports', 'domains/runtime', 'mcp_gateway', 'schemas', 'storage']) {
  const initPath = path.join(apiRoot, dir, '__init__.py');
  if (!fs.existsSync(initPath)) packageInitMissing.push(`apps/api/agent_supervisor/${dir}/__init__.py`);
}

const pycacheFiles = walkFiles(apiRoot).filter((file) => file.endsWith('.pyc')).map(relative);

const budgets = {
  unexpected_root_directory_max: 0,
  unexpected_root_python_file_max: 0,
  root_non_python_file_max: 0,
  unexpected_domain_directory_max: 0,
  unexpected_domain_file_max: 0,
  unexpected_adapter_directory_max: 0,
  unexpected_adapter_file_max: 0,
  missing_moved_module_max: 0,
  legacy_wrapper_file_max: 0,
  oversized_root_file_max: 0,
  package_init_missing_max: 0,
  pycache_file_max: 0
};

const violations = [];
if (unexpectedRootDirectories.length) violations.push(`Unexpected backend root directories: ${unexpectedRootDirectories.join(', ')}`);
if (unexpectedRootPythonFiles.length) violations.push(`Unexpected backend root Python files: ${unexpectedRootPythonFiles.join(', ')}`);
if (rootNonPythonFiles.length) violations.push(`Unexpected backend root non-Python files: ${rootNonPythonFiles.join(', ')}`);
if (unexpectedDomainDirectories.length) violations.push(`Unexpected backend domain directories: ${unexpectedDomainDirectories.join(', ')}`);
if (unexpectedDomainFiles.length) violations.push(`Unexpected files under domains root: ${unexpectedDomainFiles.join(', ')}`);
if (unexpectedAdapterDirectories.length) violations.push(`Unexpected backend adapter directories: ${unexpectedAdapterDirectories.join(', ')}`);
if (unexpectedAdapterFiles.length) violations.push(`Unexpected files under adapters root: ${unexpectedAdapterFiles.join(', ')}`);
if (missingMovedModules.length) violations.push(`Missing moved backend modules: ${missingMovedModules.map((item) => item.target).join(', ')}`);
if (legacyWrapperFiles.length) violations.push(`Legacy compatibility wrappers must be removed: ${legacyWrapperFiles.map((item) => `${item.file} -> ${item.target}`).join(', ')}`);
if (oversizedRootFiles.length) violations.push(`Oversized backend root files: ${oversizedRootFiles.map((item) => `${item.file} ${item.lines} lines`).join(', ')}`);
if (packageInitMissing.length) violations.push(`Missing package __init__.py files: ${packageInitMissing.join(', ')}`);
if (pycacheFiles.length) violations.push(`Python cache files should not be committed: ${pycacheFiles.join(', ')}`);

const result = {
  checked_at: new Date().toISOString(),
  moved_module_count: Object.keys(movedModules).length,
  root_python_file_count: rootPythonSummary.length,
  core_root_files: Array.from(coreRootPythonFiles).sort().map((name) => `apps/api/agent_supervisor/${name}`),
  legacy_wrapper_count: legacyWrapperFiles.length,
  unexpected_root_directories: unexpectedRootDirectories,
  unexpected_root_python_files: unexpectedRootPythonFiles,
  root_non_python_files: rootNonPythonFiles,
  unexpected_domain_directories: unexpectedDomainDirectories,
  unexpected_domain_files: unexpectedDomainFiles,
  unexpected_adapter_directories: unexpectedAdapterDirectories,
  unexpected_adapter_files: unexpectedAdapterFiles,
  missing_moved_modules: missingMovedModules,
  legacy_wrapper_files: legacyWrapperFiles,
  oversized_root_files: oversizedRootFiles,
  package_init_missing: packageInitMissing,
  pycache_files: pycacheFiles,
  root_python_summary: rootPythonSummary,
  budgets,
  budget_status: violations.length ? 'failed' : 'passed',
  violations,
  recommendations: [
    'Keep only core entry files (__init__.py, auth.py, main.py, paths.py) in apps/api/agent_supervisor root.',
    'Put new business code under domains/<domain>, external integrations under adapters/<type>, data access under storage, and schemas under schemas.',
    'Import moved modules via their new canonical paths; legacy root wrappers are forbidden.',
    'Run npm run api:architecture before committing backend structure changes.'
  ]
};

console.log(JSON.stringify(result, null, 2));
if (violations.length) process.exit(1);
