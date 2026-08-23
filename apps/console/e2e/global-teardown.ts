import { rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export default async function globalTeardown() {
  const candidate = process.env.AGENT_SUPERVISOR_E2E_RUNTIME_DIR;
  if (!candidate) return;
  const tempRoot = path.resolve(os.tmpdir());
  const resolved = path.resolve(candidate);
  const relative = path.relative(tempRoot, resolved);
  if (
    !relative ||
    relative.startsWith('..') ||
    path.isAbsolute(relative) ||
    !path.basename(resolved).startsWith('agent-security-supervisor-e2e-')
  ) {
    throw new Error(`拒绝清理非 E2E 临时目录：${resolved}`);
  }
  await rm(resolved, { recursive: true, force: true });
}
