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
  'gateway-probe',
  'mcp-probe',
  'gateway-agent-run',
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
  ['npm_config_api_token_env', '--api-token-env'],
  ['npm_config_operator_api_token', '--operator-api-token'],
  ['npm_config_operator_api_token_env', '--operator-api-token-env'],
  ['npm_config_operator_agent_id', '--operator-agent-id'],
  ['npm_config_max_false_alarm_rate', '--max-false-alarm-rate'],
  ['npm_config_repeats', '--repeats'],
  ['npm_config_concurrency', '--concurrency'],
  ['npm_config_calls', '--calls'],
  ['npm_config_trials', '--trials'],
  ['npm_config_operator', '--operator'],
  ['npm_config_operator_role', '--operator-role'],
  ['npm_config_payload_file', '--payload-file'],
  ['npm_config_url', '--url'],
  ['npm_config_session_id', '--session-id'],
  ['npm_config_timeout', '--timeout'],
  ['npm_config_tool', '--tool'],
  ['npm_config_arguments', '--arguments'],
  ['npm_config_expected_decision', '--expected-decision'],
  ['npm_config_baseline_url', '--baseline-url'],
  ['npm_config_baseline_api_token', '--baseline-api-token'],
  ['npm_config_baseline_api_token_env', '--baseline-api-token-env'],
  ['npm_config_causal_url', '--causal-url']
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
// PowerShell may resolve `python` to a different installation than the one
// used to start the API (for example an Anaconda interpreter without FastAPI).
// Evidence scripts can pin the exact interpreter through this environment
// variable; ordinary CLI usage keeps the historical PATH fallback.
const pythonCommand = process.env.AGENT_SUPERVISOR_PYTHON || 'python';
const childEnvironment = {
  ...process.env,
  AGENT_SUPERVISOR_LABS_ENABLED: process.env.AGENT_SUPERVISOR_LABS_ENABLED || 'true'
};
if (args[0] !== 'readiness') {
  // CLI commands are evidence and experiment workflows. Keep their SQLite,
  // leases, approvals and runtime events out of the operational console.
  // Readiness is different: it reads the operational runtime and validates
  // evidence captured by the running API. Giving it the lab runtime here
  // changes the source fingerprint and makes a current gateway artifact look
  // stale even when the server and checkout are identical.
  childEnvironment.AGENT_SUPERVISOR_RUNTIME_DIR =
    process.env.AGENT_SUPERVISOR_LAB_RUNTIME_DIR ||
    process.env.AGENT_SUPERVISOR_RUNTIME_DIR ||
    'apps/api/sandbox/runtime/cli-data';
}
const result = spawnSync(pythonCommand, ['-X', 'utf8', '-m', 'apps.api.agent_supervisor.commands.cli', ...args], {
  stdio: 'inherit',
  // Pass each argument as an argv entry.  Going through cmd.exe on Windows
  // strips JSON quotes from values such as --arguments '{"path":"x"}',
  // turning a valid MCP/OpenAI payload into invalid JSON before Python sees it.
  // Python is resolved directly through PATH on every supported platform.
  shell: false,
  env: childEnvironment
});

process.exit(result.status ?? 1);
