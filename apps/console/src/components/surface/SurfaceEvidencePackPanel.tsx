import { Space, Typography } from 'antd';
import { ClipboardList, ScrollText } from 'lucide-react';
import type { AttackSurface, SurfaceEvidencePack } from '@/types';
import { EvidenceList, LabelTag, MetaGrid, PanelCard, UiButton } from '../ui';

type SurfaceEvidenceScenario = SurfaceEvidencePack['scenarios'][number];

export function SurfaceEvidencePackPanel({
  surface,
  pack,
  loading,
  error
}: {
  surface: AttackSurface;
  pack: SurfaceEvidencePack | null;
  loading: boolean;
  error: string;
}) {
  const jsonHref = `/api/attack_surfaces/${encodeURIComponent(surface.id)}/evidence_pack`;
  const markdownHref = `/api/attack_surfaces/${encodeURIComponent(surface.id)}/evidence_pack.md`;
  const topPolicies = pack?.policy_distribution.slice(0, 5) ?? [];
  const topScenarios = pack?.scenarios.slice(0, 4) ?? [];
  const topGaps = pack?.gaps.slice(0, 3) ?? [];

  return (
    <PanelCard
      type="inner"
      title="攻击面证据包"
      extra={
        <Space>
          <UiButton type="link" size="small" authenticatedHref={jsonHref} icon={<ClipboardList size={14} />}>
            JSON
          </UiButton>
          <UiButton type="link" size="small" authenticatedHref={markdownHref} icon={<ScrollText size={14} />}>
            Markdown
          </UiButton>
        </Space>
      }
    >
      {error ? <Typography.Text type="danger">{error}</Typography.Text> : null}
      {!error && (
        <Space orientation="vertical" size="large" className="zh-surface-pack-stack">
          {topGaps.length > 0 && (
            <div>
              <Typography.Text strong className="zh-surface-matrix-label">
                缺口提示 <LabelTag color="error">{pack?.summary.gap_count ?? 0}</LabelTag>
              </Typography.Text>
              <EvidenceList
                items={topGaps.map((gap) => ({
                  key: `${gap.title}-${gap.evidence}`,
                  title: gap.title,
                  description: gap.evidence,
                  meta: gap.action,
                  tone: gap.severity === 'high' ? 'danger' : gap.severity === 'medium' ? 'warning' : 'info'
                }))}
              />
            </div>
          )}

          <div>
            <Typography.Text strong className="zh-surface-matrix-label">
              预期命中策略
            </Typography.Text>
            <Space size={[0, 8]} wrap>
              {topPolicies.length ? (
                topPolicies.map((item) => (
                  <LabelTag key={item.policy_id}>
                    {item.policy_id} ({item.count})
                  </LabelTag>
                ))
              ) : (
                <Typography.Text type="secondary" className="zh-text-md">
                  等待证据包加载
                </Typography.Text>
              )}
            </Space>
          </div>

          <div>
            <Typography.Text strong className="zh-surface-matrix-label">
              关联脚本验证
            </Typography.Text>
            <EvidenceList
              emptyText={loading ? '正在生成证据包...' : '暂无证据包数据。'}
              items={topScenarios.map((scenario: SurfaceEvidenceScenario) => {
                const policies = scenario.expected_decisions.map((item) => item.policy_id).join(' / ') || '未记录';
                const guarded = scenario.latest_guarded_result;
                const statusTone =
                  guarded.status === '已控制' ? 'success' : guarded.status === '攻击成功' ? 'error' : 'processing';

                return {
                  key: scenario.id,
                  title: scenario.id,
                  description: scenario.target,
                  tags: [{ label: guarded.status, color: statusTone }],
                  content: (
                    <MetaGrid
                      columns={2}
                      items={[
                        { key: 'policies', label: '预期策略', value: policies },
                        { key: 'target', label: '攻击目标', value: scenario.target }
                      ]}
                    />
                  )
                };
              })}
            />
          </div>
        </Space>
      )}
    </PanelCard>
  );
}
