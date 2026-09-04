import { UiSpace, UiTypography } from '../ui';
import type { JsonObject } from '../../app/mcpConsoleContract';
import { EvidenceCodeBlock, UiAlert } from '../ui';

function eventParams(event: JsonObject) {
  return event.params && typeof event.params === 'object' && !Array.isArray(event.params)
    ? (event.params as JsonObject)
    : {};
}

export function GatewayMcpStreamEvidence({ events }: { events: JsonObject[] }) {
  if (!events.length) return null;
  const progressEvents = events.filter((event) => event.method === 'notifications/progress');
  const logEvents = events.filter((event) => event.method === 'notifications/message');
  const latestProgress = progressEvents.length ? eventParams(progressEvents[progressEvents.length - 1]) : null;
  const progressText = latestProgress
    ? `${String(latestProgress.progress ?? '—')} / ${String(latestProgress.total ?? '—')}`
    : '未上报';
  const logLevels = logEvents.map((event) => String(eventParams(event).level ?? 'unknown'));

  return (
    <UiSpace orientation="vertical" size={8} className="zh-full-width">
      <UiAlert
        type="info"
        showIcon
        title={`收到 ${events.length} 条 MCP 请求级实时事件`}
        description={`最新进度：${progressText}；日志：${logEvents.length} 条${
          logLevels.length ? `（${logLevels.join('、')}）` : ''
        }。`}
      />
      <UiTypography.Text strong>请求级进度与日志证据</UiTypography.Text>
      <EvidenceCodeBlock size="small" maxHeight="large">
        {JSON.stringify(events, null, 2)}
      </EvidenceCodeBlock>
    </UiSpace>
  );
}
