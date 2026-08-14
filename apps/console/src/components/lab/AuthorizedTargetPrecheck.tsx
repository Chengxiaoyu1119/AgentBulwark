import { Typography } from 'antd';
import { LabelTag, PanelCard } from '../ui';

type PrecheckTone = 'success' | 'warning' | 'error';

type AuthorizedTargetPrecheckProps = {
  targetUrl: string;
  authorizationConfirmed: boolean;
};

const ALLOWED_PATH_MARKERS = [
  '/v1/chat/completions',
  '/api/chat',
  '/api/agent/run',
  '/api/runtime/evaluate',
  '/api/supervisor/evaluate',
  '/api/integrations/openclaw/events',
  '/api/attack_lab/run'
];

function isPrivateLikeHost(hostname: string) {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname)
  );
}

function tagColor(tone: PrecheckTone) {
  if (tone === 'success') return 'success';
  if (tone === 'error') return 'error';
  return 'warning';
}

function buildPrecheck(targetUrl: string, authorizationConfirmed: boolean) {
  const items: Array<{ label: string; value: string; tone: PrecheckTone }> = [];
  let parsed: URL | null = null;
  try {
    parsed = targetUrl ? new URL(targetUrl) : null;
  } catch {
    items.push({ label: 'URL 格式', value: '格式错误', tone: 'error' });
  }

  if (!targetUrl) {
    items.push({ label: 'URL 格式', value: '等待填写', tone: 'warning' });
  } else if (parsed) {
    items.push({ label: 'URL 格式', value: '可解析', tone: 'success' });
    items.push({
      label: '协议',
      value: parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.protocol : '后端会拒绝',
      tone: parsed.protocol === 'https:' || parsed.protocol === 'http:' ? 'success' : 'error'
    });
    const allowedPath = ALLOWED_PATH_MARKERS.some((marker) => parsed?.pathname.includes(marker));
    items.push({
      label: '接口路径',
      value: allowedPath ? 'LLM/Agent 授权接口路径' : '非允许路径，后端会拒绝',
      tone: allowedPath ? 'success' : 'error'
    });
    items.push({
      label: '地址范围',
      value: isPrivateLikeHost(parsed.hostname) ? '本机/内网，后端会拒绝' : '公网地址格式',
      tone: isPrivateLikeHost(parsed.hostname) ? 'error' : 'success'
    });
  }

  items.push({
    label: '授权确认',
    value: authorizationConfirmed ? '已确认授权' : '未确认，后端不会请求公网',
    tone: authorizationConfirmed ? 'success' : 'warning'
  });
  return items;
}

export function AuthorizedTargetPrecheck({ targetUrl, authorizationConfirmed }: AuthorizedTargetPrecheckProps) {
  return (
    <PanelCard title="运行前预检" type="inner">
      <div className="zh-authorized-precheck-grid">
        {buildPrecheck(targetUrl, authorizationConfirmed).map((item) => (
          <div key={item.label} className="zh-authorized-precheck-item">
            <Typography.Text type="secondary">{item.label}</Typography.Text>
            <LabelTag color={tagColor(item.tone)}>{item.value}</LabelTag>
          </div>
        ))}
      </div>
    </PanelCard>
  );
}
