import { UiFlex } from '../ui';
import { Play, RefreshCw, Send } from 'lucide-react';
import type { McpConsoleMethod } from '../../app/mcpConsoleContract';
import { UiButton } from '../ui';

export function GatewayMcpActions({
  loadingMethod,
  modern,
  canExecuteTools,
  onSend,
  onLoadContextEvidence
}: {
  loadingMethod: string;
  modern: boolean;
  canExecuteTools: boolean;
  onSend: (method: McpConsoleMethod) => void;
  onLoadContextEvidence: () => void;
}) {
  return (
    <UiFlex gap={8} wrap="wrap">
      {modern ? (
        <UiButton
          icon={<Play size={16} />}
          loading={loadingMethod === 'server/discover'}
          onClick={() => onSend('server/discover')}
        >
          server/discover
        </UiButton>
      ) : (
        <UiButton
          icon={<Play size={16} />}
          loading={loadingMethod === 'initialize'}
          onClick={() => onSend('initialize')}
        >
          initialize
        </UiButton>
      )}
      <UiButton
        icon={<RefreshCw size={16} />}
        loading={loadingMethod === 'tools/list'}
        onClick={() => onSend('tools/list')}
      >
        tools/list
      </UiButton>
      <UiButton loading={loadingMethod === 'resources/list'} onClick={() => onSend('resources/list')}>
        resources/list
      </UiButton>
      <UiButton loading={loadingMethod === 'resources/read'} onClick={() => onSend('resources/read')}>
        resources/read
      </UiButton>
      <UiButton
        loading={loadingMethod === 'resources/templates/list'}
        onClick={() => onSend('resources/templates/list')}
      >
        resource templates
      </UiButton>
      <UiButton loading={loadingMethod === 'prompts/list'} onClick={() => onSend('prompts/list')}>
        prompts/list
      </UiButton>
      <UiButton loading={loadingMethod === 'prompts/get'} onClick={() => onSend('prompts/get')}>
        prompts/get
      </UiButton>
      <UiButton loading={loadingMethod === 'context/evidence'} onClick={onLoadContextEvidence}>
        上下文 operator 证据
      </UiButton>
      <UiButton
        type="primary"
        icon={<Send size={16} />}
        loading={loadingMethod === 'tools/call'}
        onClick={() => onSend('tools/call')}
        disabled={!canExecuteTools}
      >
        tools/call
      </UiButton>
    </UiFlex>
  );
}
