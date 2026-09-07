import path from 'node:path';
import { fileURLToPath } from 'node:url';

export default async function globalTeardown() {
  const candidate = process.env.AGENT_SUPERVISOR_E2E_RUNTIME_DIR;
  if (!candidate) return;
  const apiRuntimeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../api/runtime');
  const runtimeRoots = [
    path.resolve(apiRuntimeRoot, 'quality/live-closure-fixture'),
    path.resolve(apiRuntimeRoot, 'e2e')
  ];
  const resolved = path.resolve(candidate);
  const isAllowedRoot = runtimeRoots.some((runtimeRoot) => {
    const relative = path.relative(runtimeRoot, resolved);
    return relative && !relative.startsWith('..') && !path.isAbsolute(relative);
  });
  if (!isAllowedRoot || !path.basename(resolved).startsWith('agent-security-supervisor-e2e-')) {
    throw new Error(`拒绝清理非 E2E 临时目录：${resolved}`);
  }
  // Directory removal is owned by run-e2e.mjs after Playwright has stopped
  // every webServer process. Removing it here deadlocks with the API's live
  // Windows maintenance-lock handle because global teardown runs first.
}
