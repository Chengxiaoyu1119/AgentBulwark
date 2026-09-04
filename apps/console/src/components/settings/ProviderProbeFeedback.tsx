import type { ModelProviderProbeResult } from '@/types';
import { LabelTag, UiAlert, UiButton, UiFlex, UiTypography } from '../ui';

export function ProviderProfileStatus({
  title,
  providerLabel,
  model,
  configured
}: {
  title: string;
  providerLabel: string;
  model: string;
  configured: boolean | null;
}) {
  const statusLabel = configured === null ? '状态未读取' : configured ? '凭证已配置' : '凭证未配置';
  return (
    <div className="zh-settings-profile-status">
      <div>
        <UiTypography.Text strong className="zh-text-block">
          {title}
        </UiTypography.Text>
        <UiTypography.Text type="secondary" className="zh-meta-block">
          {providerLabel} / {model || '默认模型'}
        </UiTypography.Text>
      </div>
      <LabelTag
        variant="filled"
        color={configured === null ? 'default' : configured ? 'success' : 'warning'}
        className="zh-settings-tag-flush"
      >
        {statusLabel}
      </LabelTag>
    </div>
  );
}

export function ProviderProbeAlert({ result }: { result: ModelProviderProbeResult }) {
  const healthy = result.status === 'healthy';
  const configured = result.status !== 'unconfigured';
  const title = healthy
    ? `${result.provider ?? result.provider_id} 连接探针通过`
    : configured
      ? `${result.provider ?? result.provider_id} 连接探针未通过`
      : `${result.provider ?? result.provider_id} 尚未配置凭证`;
  const details = [
    result.model ? `模型：${result.model}` : '',
    typeof result.latency_ms === 'number' ? `延迟：${result.latency_ms} ms` : '',
    result.endpoint_scope ? `路由：${result.endpoint_scope}` : '',
    result.error ? `原因：${result.error}` : ''
  ].filter(Boolean);
  return (
    <UiAlert
      type={healthy ? 'success' : 'warning'}
      showIcon
      title={title}
      description={details.join('；') || '没有可展示的探针详情。'}
      className="zh-mb-16"
    />
  );
}

export function ProviderStatusNotice({ error, loading }: { error?: string; loading?: boolean }) {
  if (error) {
    return <UiAlert type="warning" showIcon title="按用途读取模型状态失败" description={error} className="zh-mb-16" />;
  }
  return loading ? <UiAlert type="info" showIcon title="正在读取各用途的模型凭证状态。" className="zh-mb-16" /> : null;
}

export function ProviderProbeButton({
  profile,
  providerId,
  orderLabels,
  canProbe,
  loading,
  onProbe
}: {
  profile: string;
  providerId: string;
  orderLabels: string;
  canProbe: boolean;
  loading: boolean;
  onProbe?: (profile: string, providerId: string) => void | Promise<void>;
}) {
  return (
    <UiFlex justify="space-between" align="center" gap={12} wrap="wrap">
      <UiTypography.Text type="secondary" className="zh-code-sm">
        调用顺序：{orderLabels}
      </UiTypography.Text>
      {onProbe ? (
        <UiButton size="small" loading={loading} disabled={!canProbe} onClick={() => void onProbe(profile, providerId)}>
          检测连接
        </UiButton>
      ) : null}
    </UiFlex>
  );
}
