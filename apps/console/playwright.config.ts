import { defineConfig } from 'playwright/test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const consoleRoot = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = path.resolve(consoleRoot, '../..');
const runtimeDir =
  process.env.AGENT_SUPERVISOR_E2E_RUNTIME_DIR ||
  path.join(
    repoRoot,
    'apps',
    'api',
    'runtime',
    'quality',
    'live-closure-fixture',
    `agent-security-supervisor-e2e-${process.pid}`
  );
const providerPort = '18081';
const apiPort = '8016';
const consolePort = '5180';
const python = process.env.AGENT_SUPERVISOR_PYTHON || 'python';
const browserExecutablePath = process.env.PLAYWRIGHT_EXECUTABLE_PATH;
const browserChannel =
  process.env.PLAYWRIGHT_CHANNEL || (process.platform === 'win32' && !browserExecutablePath ? 'chrome' : undefined);
process.env.AGENT_SUPERVISOR_E2E_RUNTIME_DIR = runtimeDir;

const inheritedEnvironment = Object.fromEntries(
  Object.entries(process.env).filter((entry): entry is [string, string] => typeof entry[1] === 'string')
);

const apiEnvironment: Record<string, string> = {
  ...inheritedEnvironment,
  PYTHONUTF8: '1',
  AGENT_SUPERVISOR_API_HOST: '127.0.0.1',
  AGENT_SUPERVISOR_API_PORT: apiPort,
  AGENT_SUPERVISOR_RUNTIME_DIR: runtimeDir,
  AGENT_SUPERVISOR_AUTH_DISABLED: 'false',
  AGENT_SUPERVISOR_SECURITY_PROFILE: 'local',
  AGENT_SUPERVISOR_LABS_ENABLED: 'false',
  AGENT_SUPERVISOR_API_TOKEN: '',
  AGENT_SUPERVISOR_API_TOKEN_ADMIN: 'e2e-admin-token',
  AGENT_SUPERVISOR_API_TOKEN_OBSERVER: 'e2e-observer-token',
  AGENT_SUPERVISOR_API_TOKEN_EXECUTOR: '',
  AGENT_SUPERVISOR_API_TOKEN_ANALYST: 'e2e-analyst-token',
  AGENT_SUPERVISOR_AGENT_TOKENS_JSON: '{"e2e-agent":"e2e-executor-token"}',
  AGENT_SUPERVISOR_ALLOW_SHARED_EXECUTOR_TOKEN: 'false',
  AGENT_SUPERVISOR_AUDIT_HMAC_KEY: 'e2e-audit-hmac-key',
  AGENT_SUPERVISOR_CORS_ORIGINS: `http://127.0.0.1:${consolePort}`,
  AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS: 'true',
  AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS: 'true',
  MODEL_REAL_API_ENABLED: 'true',
  MODEL_PROVIDER_PRIORITY: 'openai-compatible',
  OPENAI_COMPATIBLE_API_KEY: 'e2e-provider-key',
  OPENAI_COMPATIBLE_BASE_URL: `http://127.0.0.1:${providerPort}/v1`,
  OPENAI_COMPATIBLE_MODEL: 'e2e-fixture-model',
  DEEPSEEK_API_KEY: '',
  ZHIPU_API_KEY: '',
  TARGET_MODEL_PROVIDER_PRIORITY: 'openai-compatible',
  TARGET_REAL_MODEL_PROVIDER: 'openai-compatible',
  TARGET_OPENAI_COMPATIBLE_API_KEY: 'e2e-provider-key',
  TARGET_OPENAI_COMPATIBLE_BASE_URL: `http://127.0.0.1:${providerPort}/v1`,
  TARGET_OPENAI_COMPATIBLE_MODEL: 'e2e-fixture-model',
  TARGET_DEEPSEEK_API_KEY: '',
  TARGET_ZHIPU_API_KEY: '',
  AGENT_SUPERVISOR_PROVIDER_DNS_MODE: 'system',
  MCP_GATEWAY_ENABLED: 'true',
  MCP_GATEWAY_GUARD_ENABLED: 'true',
  MCP_GATEWAY_UPSTREAM_COMMAND: `${python} -X utf8 -m apps.api.tests.fixtures.mcp_echo_server`,
  MCP_GATEWAY_SESSION_ISOLATION: 'true',
  MCP_GATEWAY_RESOURCE_LIMITS_ENABLED: 'true',
  MCP_GATEWAY_NETWORK_MODE: 'reject-unpinned',
  MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS: 'false',
  MCP_GATEWAY_REQUEST_STATE_SECRET: 'e2e-mcp-request-state-secret-32-bytes-long',
  MCP_ECHO_SERVER_REQUEST: '1',
  MCP_ECHO_PROGRESS_ON_CALL: '1',
  MCP_ECHO_NOTIFY_ON_CALL: '1',
  MCP_ECHO_LOG_LEVELS: 'debug,info,warning,error'
};

export default defineConfig({
  testDir: './e2e',
  outputDir: '../../apps/api/runtime/quality/live-closure-fixture/test-results',
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  retries: 0,
  globalTeardown: './e2e/global-teardown.ts',
  reporter: [
    ['line'],
    ['html', { outputFolder: '../../apps/api/runtime/quality/live-closure-fixture/playwright-report', open: 'never' }]
  ],
  use: {
    baseURL: `http://127.0.0.1:${consolePort}`,
    ...(browserChannel ? { channel: browserChannel } : {}),
    ...(browserExecutablePath ? { launchOptions: { executablePath: browserExecutablePath } } : {}),
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure'
  },
  webServer: [
    {
      command: `${python} -X utf8 -m apps.api.tests.fixtures.openai_gateway_provider`,
      cwd: repoRoot,
      env: { ...inheritedEnvironment, PYTHONUTF8: '1', FIXTURE_PROVIDER_PORT: providerPort },
      url: `http://127.0.0.1:${providerPort}/health`,
      reuseExistingServer: false,
      timeout: 30_000
    },
    {
      command: `${python} -X utf8 -m apps.api.dev_server`,
      cwd: repoRoot,
      env: apiEnvironment,
      url: `http://127.0.0.1:${apiPort}/api/public/status`,
      reuseExistingServer: false,
      timeout: 60_000
    },
    {
      command: 'npm run dev:e2e',
      cwd: consoleRoot,
      env: { ...inheritedEnvironment, AGENT_SUPERVISOR_API_PORT: apiPort },
      url: `http://127.0.0.1:${consolePort}`,
      reuseExistingServer: false,
      timeout: 60_000
    }
  ]
});
