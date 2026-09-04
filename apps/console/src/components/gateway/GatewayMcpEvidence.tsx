import { UiSpace, UiTypography } from '../ui';
import type { JsonObject, McpResponse } from '../../app/mcpConsoleContract';
import { EvidenceCodeBlock, LabelTag, UiAlert } from '../ui';

function stringValue(value: unknown, fallback = '—') {
  if (value === undefined || value === null || value === '') return fallback;
  return String(value);
}

function countValue(value: unknown, fallback = 0) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

function resultContainer(response: JsonObject | null): JsonObject | null {
  if (!response) return null;
  if (response.result && typeof response.result === 'object' && !Array.isArray(response.result)) {
    return response.result as JsonObject;
  }
  if (response.error && typeof response.error === 'object' && !Array.isArray(response.error)) {
    const error = response.error as JsonObject;
    return error.data && typeof error.data === 'object' && !Array.isArray(error.data)
      ? (error.data as JsonObject)
      : error;
  }
  return null;
}

export function GatewayMcpEvidence({ result }: { result: McpResponse }) {
  const evidence = resultContainer(result.response);
  const marker =
    evidence?.zhiAnSentinel && typeof evidence.zhiAnSentinel === 'object'
      ? (evidence.zhiAnSentinel as JsonObject)
      : evidence;
  const rpcError =
    result.response?.error && typeof result.response.error === 'object' ? (result.response.error as JsonObject) : null;
  const executionOutcome = stringValue(
    marker?.execution_outcome,
    rpcError?.code === -32050 ? 'audit-uncertain' : '未观测'
  );
  const outcomeDescription =
    executionOutcome === 'executed-result-contained'
      ? '上游工具已经执行；网关只隔离了返回给 Agent 的上下文。'
      : executionOutcome === 'blocked-before-execution'
        ? '调用未越过上游执行边界。'
        : executionOutcome === 'forwarded-and-completed'
          ? '调用已转发并收到上游结果。'
          : executionOutcome === 'audit-uncertain'
            ? '上游执行事实存在，但审计回执不完整，需人工核查。'
            : '';
  const scanSummary =
    marker?.scanSummary && typeof marker.scanSummary === 'object' ? (marker.scanSummary as JsonObject) : null;
  const scanSummaryText = scanSummary
    ? `网关已扫描：${stringValue(scanSummary.scanned_tool_count, '0')} 个；隔离 ${stringValue(
        scanSummary.quarantined_tool_count,
        '0'
      )} 个；警告 ${stringValue(scanSummary.warning_tool_count, '0')} 个。`
    : '';
  const visibleTools =
    result.method === 'tools/list' && result.response?.result && typeof result.response.result === 'object'
      ? (((result.response.result as JsonObject).tools as unknown[] | undefined)?.length ?? 0)
      : 0;
  const filteredTools = countValue(
    marker?.filtered_tool_count,
    Array.isArray(marker?.filteredTools) ? marker.filteredTools.length : 0
  );
  const quarantinedTools = countValue(
    marker?.quarantined_tool_count,
    Array.isArray(marker?.quarantinedTools) ? marker.quarantinedTools.length : 0
  );

  return (
    <UiSpace orientation="vertical" size={12} className="zh-full-width">
      <div className="zh-meta-grid zh-meta-grid--4">
        <div className="zh-meta-grid__item">
          <UiTypography.Text type="secondary" className="zh-meta-grid__label">
            方法
          </UiTypography.Text>
          <UiTypography.Text className="zh-meta-grid__value">{result.method}</UiTypography.Text>
        </div>
        <div className="zh-meta-grid__item">
          <UiTypography.Text type="secondary" className="zh-meta-grid__label">
            JSON-RPC
          </UiTypography.Text>
          <UiTypography.Text className="zh-meta-grid__value">
            {rpcError ? (
              <LabelTag color="red" variant="filled">
                error {stringValue(rpcError.code)}
              </LabelTag>
            ) : (
              <LabelTag color="green" variant="filled">
                result
              </LabelTag>
            )}
          </UiTypography.Text>
        </div>
        <div className="zh-meta-grid__item">
          <UiTypography.Text type="secondary" className="zh-meta-grid__label">
            决策
          </UiTypography.Text>
          <UiTypography.Text className="zh-meta-grid__value">{stringValue(marker?.decision)}</UiTypography.Text>
        </div>
        <div className="zh-meta-grid__item">
          <UiTypography.Text type="secondary" className="zh-meta-grid__label">
            审计 ID
          </UiTypography.Text>
          <UiTypography.Text className="zh-meta-grid__value">
            {stringValue(marker?.audit_id ?? marker?.auditId)}
          </UiTypography.Text>
        </div>
        <div className="zh-meta-grid__item">
          <UiTypography.Text type="secondary" className="zh-meta-grid__label">
            执行事实
          </UiTypography.Text>
          <UiTypography.Text className="zh-meta-grid__value">
            <LabelTag
              color={
                executionOutcome === 'executed-result-contained' || executionOutcome === 'audit-uncertain'
                  ? 'warning'
                  : executionOutcome === 'blocked-before-execution'
                    ? 'green'
                    : 'blue'
              }
              variant="filled"
            >
              {executionOutcome}
            </LabelTag>
          </UiTypography.Text>
        </div>
      </div>
      {outcomeDescription && (
        <UiAlert
          type={
            executionOutcome === 'executed-result-contained' || executionOutcome === 'audit-uncertain'
              ? 'warning'
              : 'info'
          }
          showIcon
          title={outcomeDescription}
        />
      )}
      {result.method === 'tools/list' && (
        <UiSpace orientation="vertical" size={4}>
          <UiTypography.Text type="secondary">
            当前响应可见工具：{visibleTools} 个；已过滤 {filteredTools} 个；模型侧隔离 {quarantinedTools} 个。
          </UiTypography.Text>
          {scanSummary && <UiTypography.Text type="secondary">{scanSummaryText}</UiTypography.Text>}
        </UiSpace>
      )}
      <UiTypography.Text strong>JSON-RPC 请求</UiTypography.Text>
      <EvidenceCodeBlock size="small">{pretty(result.request)}</EvidenceCodeBlock>
      <UiTypography.Text strong>JSON-RPC 响应与网关证据</UiTypography.Text>
      <EvidenceCodeBlock size="small" maxHeight="large">
        {pretty(result.response)}
      </EvidenceCodeBlock>
    </UiSpace>
  );
}
