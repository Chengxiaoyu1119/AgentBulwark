import type { CompetitionReadiness } from '@/types';

const BOUNDARY_LABELS: Record<string, string> = {
  tool: '工具白名单',
  model: '模型白名单',
  api: '外部 API 主机',
  context: 'MCP 上下文范围'
};

export function getMissingBindings(readiness: CompetitionReadiness | null) {
  const details = readiness?.checks.find((check) => check.id === 'agent-tool-least-privilege')?.details;
  const rawBindings = details?.missing_bindings;
  if (!rawBindings || typeof rawBindings !== 'object' || Array.isArray(rawBindings)) return [];

  return Object.entries(rawBindings).flatMap(([agentId, rawBoundaries]) => {
    if (!Array.isArray(rawBoundaries)) return [];
    const boundaries = rawBoundaries
      .map(String)
      .map((boundary) => BOUNDARY_LABELS[boundary] ?? boundary)
      .filter(Boolean);
    return boundaries.length ? [{ agentId, boundaries }] : [];
  });
}
