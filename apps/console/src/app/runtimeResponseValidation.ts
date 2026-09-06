function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasBooleanFields(record: Record<string, unknown>, fields: string[]) {
  return fields.every((field) => typeof record[field] === 'boolean');
}

function isPublicConsoleStatus(value: unknown) {
  if (!isRecord(value) || value.ok !== true || value.service !== 'agent-security-supervisor') return false;
  const auth = value.console_auth;
  return (
    isRecord(auth) &&
    typeof auth.required === 'boolean' &&
    typeof auth.transport === 'string' &&
    typeof auth.profile === 'string'
  );
}

function isAuthContext(value: unknown) {
  if (!isRecord(value) || typeof value.role !== 'string') return false;
  if (value.agent_id !== null && typeof value.agent_id !== 'string') return false;
  const permissions = value.permissions;
  return (
    isRecord(permissions) &&
    hasBooleanFields(permissions, ['can_edit_policy', 'can_review_approval', 'can_execute_runtime', 'can_view']) &&
    ['can_generate', 'can_execute_managed_tools', 'can_use_mcp', 'can_execute_mcp_tools'].every(
      (field) => permissions[field] === undefined || typeof permissions[field] === 'boolean'
    )
  );
}

function isOverview(value: unknown) {
  if (!isRecord(value)) return false;
  if (!['models', 'recent_runs', 'alerts', 'audit_logs'].every((key) => Array.isArray(value[key]))) {
    return false;
  }
  const summary = value.summary;
  return (
    isRecord(summary) &&
    ['recent_run_count', 'block_rate', 'avg_latency_ms'].every(
      (key) => typeof summary[key] === 'number' && Number.isFinite(summary[key])
    )
  );
}

const validators: Record<string, (value: unknown) => boolean> = {
  '/api/public/status': isPublicConsoleStatus,
  '/api/auth/context': isAuthContext,
  '/api/overview': isOverview
};

export function validateRuntimeResponse(path: string, value: unknown) {
  const route = path.split(/[?#]/, 1)[0];
  const validator = validators[route];
  return !validator || validator(value);
}
