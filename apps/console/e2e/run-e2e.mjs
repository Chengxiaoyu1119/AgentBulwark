import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, URL } from 'node:url';

const e2eRoot = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = path.resolve(e2eRoot, '../../..');
const playwrightCli = path.resolve(e2eRoot, '../node_modules/playwright/cli.js');
const runtimeDir =
  process.env.AGENT_SUPERVISOR_E2E_RUNTIME_DIR ||
  path.join(
    repoRoot,
    'apps',
    'api',
    'runtime',
    'quality',
    'live-closure-fixture',
    `agent-security-supervisor-e2e-${process.pid}-${Date.now()}`
  );

function runPlaywright() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [playwrightCli, 'test'], {
      cwd: path.resolve(e2eRoot, '..'),
      env: { ...process.env, AGENT_SUPERVISOR_E2E_RUNTIME_DIR: runtimeDir },
      stdio: 'inherit'
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) {
        reject(new Error(`Playwright 被信号 ${signal} 终止。`));
        return;
      }
      resolve(code ?? 1);
    });
  });
}

let exitCode = 1;
try {
  exitCode = await runPlaywright();
} finally {
  // Playwright has exited here, so its API webServer has released the Windows
  // maintenance lock. Retries cover only short process-shutdown propagation.
  await rm(runtimeDir, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
process.exitCode = exitCode;
