import { useState } from 'react';
import { UiSpace, UiTypography } from '../ui';
import type { JsonObject, McpInputRequired } from '../../app/mcpConsoleContract';
import { safeUiDiagnostic } from '../../app/apiRequestSupport';
import { EvidenceCodeBlock, UiAlert, UiButton, UiInput } from '../ui';

function defaultResponse(request: unknown): JsonObject {
  const method =
    request && typeof request === 'object' && !Array.isArray(request)
      ? String((request as JsonObject).method ?? '')
      : '';
  if (method === 'sampling/createMessage') {
    return {
      role: 'assistant',
      content: { type: 'text', text: '已由操作员确认。' },
      model: 'operator-input'
    };
  }
  if (method === 'elicitation/create') return { action: 'accept', content: {} };
  if (method === 'roots/list') return { roots: [] };
  return {};
}

function defaultInputResponses(inputRequests: JsonObject) {
  return Object.fromEntries(Object.entries(inputRequests).map(([key, request]) => [key, defaultResponse(request)]));
}

export function GatewayMcpInputRequiredPanel({
  inputRequired,
  loading,
  onResume
}: {
  inputRequired: McpInputRequired;
  loading: boolean;
  onResume: (inputResponses: JsonObject) => void;
}) {
  const [responsesText, setResponsesText] = useState(() =>
    JSON.stringify(defaultInputResponses(inputRequired.inputRequests), null, 2)
  );
  const [error, setError] = useState('');

  function submit() {
    setError('');
    try {
      const parsed = JSON.parse(responsesText) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('inputResponses 必须是 JSON 对象。');
      }
      const expectedKeys = Object.keys(inputRequired.inputRequests).sort();
      const actualKeys = Object.keys(parsed).sort();
      if (JSON.stringify(expectedKeys) !== JSON.stringify(actualKeys)) {
        throw new Error('inputResponses 必须逐项对应当前 inputRequests。');
      }
      for (const value of Object.values(parsed)) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
          throw new Error('inputResponses 的每一项都必须是 JSON 对象。');
        }
      }
      onResume(parsed as JsonObject);
    } catch (parseError) {
      setError(safeUiDiagnostic(parseError));
    }
  }

  return (
    <UiSpace orientation="vertical" size={8} className="zh-full-width">
      <UiAlert
        type="warning"
        showIcon
        title="MCP 需要操作员输入"
        description="上游调用已暂停；确认请求内容并提交响应后，网关会用受保护的 requestState 恢复同一轮调用。"
      />
      <UiTypography.Text strong>上游 inputRequests</UiTypography.Text>
      <EvidenceCodeBlock size="small">{JSON.stringify(inputRequired.inputRequests, null, 2)}</EvidenceCodeBlock>
      <UiTypography.Text strong>本轮 inputResponses</UiTypography.Text>
      <UiInput.TextArea
        value={responsesText}
        onChange={(event) => setResponsesText(event.target.value)}
        autoSize={{ minRows: 5, maxRows: 12 }}
        spellCheck={false}
        aria-label="MCP inputResponses"
      />
      {error ? <UiAlert type="error" showIcon title={error} /> : null}
      <UiButton type="primary" loading={loading} onClick={submit}>
        提交输入并恢复
      </UiButton>
    </UiSpace>
  );
}
