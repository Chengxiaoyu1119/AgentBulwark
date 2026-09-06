import path from 'node:path';
import { fileURLToPath } from 'node:url';

export default async function globalTeardown() {
  const candidate = process.env.AGENT_SUPERVISOR_E2E_RUNTIME_DIR;
  if (!candidate) return;
  const runtimeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../api/runtime/e2e');
  const resolved = path.resolve(candidate);
  const relative = path.relative(runtimeRoot, resolved);
  if (
    !relative ||
    relative.startsWith('..') ||
    path.isAbsolute(relative) ||
    !path.basename(resolved).startsWith('agent-security-supervisor-e2e-')
  ) {
    throw new Error(`拒绝清理非 E2E 临时目录：${resolved}`);
  }
  // Directory removal is owned by run-e2e.mjs after Playwright has stopped
  // every webServer process. Removing it here deadlocks with the API's live
  // Windows maintenance-lock handle because global teardown runs first.
}
