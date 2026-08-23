import type { JSX } from 'react';
import { BrainCircuit, ClipboardList, FileCheck2, ShieldCheck } from 'lucide-react';
import { Typography } from 'antd';
import type { PageKey } from '@/app/navigation';
import type { Overview } from '@/types';
import { PanelCard } from '../ui';

type FeatureMapPoint = {
  label: string;
  value: string;
  page: PageKey;
};

type FeatureMapGroup = {
  title: string;
  desc: string;
  icon: JSX.Element;
  points: FeatureMapPoint[];
};

export function DashboardFeatureMap({
  overview,
  completeSurfaceCount,
  totalSamples,
  totalScripts,
  onOpenPage
}: {
  overview: Overview;
  completeSurfaceCount: number;
  totalSamples: number;
  totalScripts: number;
  onOpenPage: (page: PageKey) => void;
}) {
  const guardedControlRate = overview.summary.guarded_control_rate ?? overview.summary.block_rate;
  const configuredModelCount = overview.models.filter((model) => model.configured && model.mode === 'real-api').length;
  const groups: FeatureMapGroup[] = [
    {
      title: '攻击面研究层',
      desc: '把 Agent/API 的攻击面、对抗样本、越狱用例和工具链验证归到同一组。',
      icon: <ClipboardList size={18} />,
      points: [
        {
          label: '攻击面覆盖',
          value: `${completeSurfaceCount}/${overview.summary.surface_count} 类`,
          page: 'dashboard'
        },
        { label: '验证样本与入口', value: `${totalSamples} 样本 / ${totalScripts} 入口`, page: 'scenarios' },
        { label: '多 Agent 链路', value: '规划-生成-执行', page: 'chain' }
      ]
    },
    {
      title: '真实运行验证层',
      desc: '从页面发起验证后，后端记录 Agent 请求、Provider 响应、工具调用和监督器判定。',
      icon: <BrainCircuit size={18} />,
      points: [
        { label: '本地受控环境复现', value: `${overview.summary.scenario_count} 个入口`, page: 'lab' },
        { label: '模型接入状态', value: `${configuredModelCount}/${overview.models.length} 个可用`, page: 'settings' },
        { label: '行为审计日志', value: `${overview.audit_logs.length} 条`, page: 'audit' }
      ]
    },
    {
      title: '防御策略验收层',
      desc: '把允许、拒绝、询问、隔离、输出过滤和证据报告串成可验收闭环。',
      icon: <ShieldCheck size={18} />,
      points: [
        { label: '防护控制率', value: `${guardedControlRate}%`, page: 'policy' },
        { label: '告警阻断记录', value: `${overview.alerts.length} 条`, page: 'alerts' },
        { label: '按需证据导出', value: `${overview.recent_runs.length} 次运行`, page: 'report' }
      ]
    }
  ];

  return (
    <PanelCard
      title={
        <span className="zh-card-title-inline">
          <FileCheck2 size={18} />
          <Typography.Text strong>能力地图</Typography.Text>
        </span>
      }
      variant="borderless"
      bodyPadding={20}
    >
      <div className="zh-feature-map-grid">
        {groups.map((group) => (
          <section className="zh-feature-map-group" key={group.title}>
            <div className="zh-feature-map-group__head">
              <span className="zh-feature-map-group__icon">{group.icon}</span>
              <div>
                <Typography.Text strong>{group.title}</Typography.Text>
                <Typography.Paragraph type="secondary" className="zh-feature-map-group__desc">
                  {group.desc}
                </Typography.Paragraph>
              </div>
            </div>
            <div className="zh-feature-map-points">
              {group.points.map((point) => (
                <button
                  key={`${group.title}-${point.label}`}
                  type="button"
                  className="zh-feature-map-point"
                  onClick={() => onOpenPage(point.page)}
                >
                  <span>{point.label}</span>
                  <strong>{point.value}</strong>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
    </PanelCard>
  );
}
