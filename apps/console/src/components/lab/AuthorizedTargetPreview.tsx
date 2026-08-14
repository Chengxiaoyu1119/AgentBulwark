import { Descriptions } from 'antd';
import { EvidenceCodeBlock, LabelTag, PanelCard } from '../ui';

type AuthorizedTargetPreviewProps = {
  targetUrl: string;
  targetType: string;
  targetModel: string;
  attackInput: string;
  surfaceId: string;
  hasBearerToken: boolean;
  serverPreview?: Record<string, unknown>;
};

function payloadKind(path: string) {
  if (path.endsWith('/v1/chat/completions')) return 'openai-compatible-chat';
  if (
    path.includes('/api/runtime/evaluate') ||
    path.includes('/api/supervisor/evaluate') ||
    path.includes('/api/integrations/openclaw/events')
  )
    return 'supervisor-event';
  return 'generic-agent-run';
}

function localPreview({
  targetUrl,
  targetType,
  targetModel,
  attackInput,
  surfaceId,
  hasBearerToken
}: AuthorizedTargetPreviewProps) {
  let parsed: URL | null = null;
  try {
    parsed = targetUrl ? new URL(targetUrl) : null;
  } catch {
    parsed = null;
  }
  const path = parsed?.pathname || '';
  const kind = payloadKind(path);
  const body =
    kind === 'openai-compatible-chat'
      ? {
          model: targetModel,
          messages: [{ role: 'user', content: attackInput }],
          temperature: 0.2,
          stream: false
        }
      : {
          prompt: attackInput,
          attack_input: attackInput,
          surface_id: surfaceId,
          source: 'agent-security-supervisor-authorized-redteam'
        };
  return {
    method: 'POST',
    host: parsed?.host || '等待填写',
    path: path || '等待填写',
    target_type: targetType,
    payload_kind: kind,
    has_authorization_header: hasBearerToken,
    body
  };
}

export function AuthorizedTargetPreview(props: AuthorizedTargetPreviewProps) {
  const preview = props.serverPreview ?? localPreview(props);
  return (
    <PanelCard title="请求预览" subtitle="发送前确认目标和载荷" type="inner">
      <Descriptions column={{ xs: 1, md: 2 }} size="small">
        <Descriptions.Item label="方法">{String(preview.method ?? 'POST')}</Descriptions.Item>
        <Descriptions.Item label="主机">{String(preview.host ?? '-')}</Descriptions.Item>
        <Descriptions.Item label="路径">{String(preview.path ?? '-')}</Descriptions.Item>
        <Descriptions.Item label="类型">
          <LabelTag color="blue">{String(preview.target_type ?? props.targetType)}</LabelTag>
        </Descriptions.Item>
        <Descriptions.Item label="载荷">{String(preview.payload_kind ?? '-')}</Descriptions.Item>
        <Descriptions.Item label="鉴权头">{preview.has_authorization_header ? '已携带' : '未携带'}</Descriptions.Item>
      </Descriptions>
      <EvidenceCodeBlock maxHeight="small">{JSON.stringify(preview.body ?? {}, null, 2)}</EvidenceCodeBlock>
    </PanelCard>
  );
}
