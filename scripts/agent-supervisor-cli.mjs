import { spawnSync } from 'node:child_process';

const commandNames = new Set([
  'run',
  'batch',
  'export',
  'samples',
  'benign',
  'benign-workflows',
  'benign-workflows-write',
  'conclusions',
  'output-filter',
  'assess',
  'attack-chains',
  'requirements',
  'evaluate',
  'demo-external',
  'external-agent-demo',
  'policy-ablation',
  'surface-pack',
  'surface-packs',
  'surface-brief',
  'surface-briefs',
  'roadmap',
  'anomaly-calibration',
  'real-model-eval',
  'competition-benchmark',
  'repro-check',
  'http-e2e-benchmark',
  'openclaw-plugin',
  'openclaw-plugin-validate',
  'readiness',
  'approvals',
  'demo-drill'
]);

const booleanFlags = new Map([
  ['npm_config_write', '--write'],
  ['npm_config_run', '--run'],
  ['npm_config_compare', '--compare'],
  ['npm_config_run_compare', '--run-compare'],
  ['npm_config_execute_in_sandbox', '--execute-in-sandbox'],
  ['npm_config_inspect_runtime', '--inspect-runtime'],
  ['npm_config_managed_server', '--managed-server']
]);

const valueFlags = new Map([
  ['npm_config_output', '--output'],
  ['npm_config_format', '--format'],
  ['npm_config_status', '--status'],
  ['npm_config_scope', '--scope'],
  ['npm_config_limit', '--limit'],
  ['npm_config_input', '--input'],
  ['npm_config_json', '--json'],
  ['npm_config_guard', '--guard'],
  ['npm_config_chain', '--chain'],
  ['npm_config_surface', '--surface'],
  ['npm_config_supervisor_url', '--supervisor-url'],
  ['npm_config_api_token', '--api-token'],
  ['npm_config_max_false_alarm_rate', '--max-false-alarm-rate'],
  ['npm_config_repeats', '--repeats'],
  ['npm_config_concurrency', '--concurrency'],
  ['npm_config_calls', '--calls'],
  ['npm_config_trials', '--trials'],
  ['npm_config_operator', '--operator'],
  ['npm_config_operator_role', '--operator-role']
]);

function envEnabled(name) {
  const value = process.env[name];
  return value !== undefined && value !== '' && value !== 'false';
}

function takeOutputPositional(args) {
  if (!envEnabled('npm_config_output') || args.includes('--output')) {
    return null;
  }
  if (process.env.npm_config_output && process.env.npm_config_output !== 'true') {
    return process.env.npm_config_output;
  }
  if (args.length > 0) {
    return args.pop();
  }
  return null;
}

function recoverArgs(rawArgs) {
  if (!rawArgs.length || !commandNames.has(rawArgs[0])) {
    return rawArgs;
  }

  const args = [...rawArgs];
  const recovered = [args.shift()];
  const outputValue = takeOutputPositional(args);

  for (const [envName, flag] of booleanFlags) {
    if (envEnabled(envName) && !args.includes(flag)) {
      recovered.push(flag);
    }
  }

  for (const [envName, flag] of valueFlags) {
    if (!envEnabled(envName) || args.includes(flag)) {
      continue;
    }
    if (envName === 'npm_config_output' && outputValue) {
      recovered.push(flag, outputValue);
      continue;
    }
    const value = process.env[envName];
    if (value && value !== 'true') {
      recovered.push(flag, value);
    }
  }

  recovered.push(...args);
  return recovered;
}

const args = recoverArgs(process.argv.slice(2));
if (process.env.AGENT_SUPERVISOR_CLI_DEBUG === '1') {
  const npmConfig = Object.fromEntries(
    Object.entries(process.env)
      .filter(([key]) => key.startsWith('npm_config_') || key === 'npm_lifecycle_event')
      .sort(([a], [b]) => a.localeCompare(b))
  );
  console.error(JSON.stringify({ rawArgs: process.argv.slice(2), recoveredArgs: args, npmConfig }, null, 2));
}
const result = spawnSync('python', ['-X', 'utf8', '-m', 'apps.api.agent_supervisor.commands.cli', ...args], {
  stdio: 'inherit',
  shell: process.platform === 'win32'
});

process.exit(result.status ?? 1);
