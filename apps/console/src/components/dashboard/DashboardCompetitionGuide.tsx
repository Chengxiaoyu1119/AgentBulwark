import type { JSX } from 'react';
import { BrainCircuit, FileWarning, FlaskConical, Play, ShieldCheck, SlidersHorizontal, Wrench } from 'lucide-react';
import { Space, Typography } from 'antd';
import type { PageKey } from '@/app/navigation';
import type { Overview } from '@/types';
import { PanelCard } from '../ui';

type CompetitionGuideItem = {
  title: string;
  desc: string;
  metric: string;
  icon: JSX.Element;
  action: string;
  page: PageKey;
};

export function DashboardCompetitionGuide({
  overview,
  completeSurfaceCount,
  onOpenPage
}: {
  overview: Overview;
  completeSurfaceCount: number;
  onOpenPage: (page: PageKey) => void;
}) {
  const guardedControlRate = overview.summary.guarded_control_rate ?? overview.summary.block_rate;
  const configuredModelCount = overview.models.filter((model) => model.configured && model.mode === 'real-api').length;
  const items: CompetitionGuideItem[] = [
    {
      title: '风险与攻击场景',
      desc: '管理提示注入、数据泄露、工具滥用、记忆中毒和多Agent链路等风险场景。',
      metric: `${completeSurfaceCount}/${overview.summary.surface_count} 类攻击面完整`,
      icon: <FlaskConical size={18} />,
      action: '查看脚本库',
      page: 'scenarios'
    },
    {
      title: '攻防因果对照',
      desc: '用相同输入、工具调用和初始环境对比关闭防护与启用防护后的真实副作用。',
      metric: `${overview.summary.scenario_count} 个可运行脚本`,
      icon: <Play size={18} />,
      action: '运行攻防验证',
      page: 'lab'
    },
    {
      title: 'Agent与模型接入',
      desc: '接入通用HTTP Agent并配置模型来源，明确区分真实模型、固定规划器和连接状态。',
      metric: `${configuredModelCount}/${overview.models.length} 个模型已配置`,
      icon: <BrainCircuit size={18} />,
      action: '配置模型',
      page: 'settings'
    },
    {
      title: '调用审计与复核',
      desc: '关联Agent、模型规划、工具参数、监督决策、执行结果、人工审批和证据Hash。',
      metric: `${overview.audit_logs.length} 条审计记录`,
      icon: <Wrench size={18} />,
      action: '查看审计',
      page: 'audit'
    },
    {
      title: '运行时防护策略',
      desc: '配置Agent工具权限、参数边界、敏感数据规则以及允许、阻断、审批和隔离动作。',
      metric: `${guardedControlRate}% 有防护运行控制率`,
      icon: <ShieldCheck size={18} />,
      action: '调整策略',
      page: 'policy'
    },
    {
      title: '证据导出（按需）',
      desc: '运行功能不依赖报告；需要答辩或提交时，再生成攻击、审计和接口证据材料。',
      metric: `${overview.recent_runs.length} 条近期运行`,
      icon: <FileWarning size={18} />,
      action: '生成材料',
      page: 'report'
    }
  ];

  return (
    <PanelCard
      title={
        <Space>
          <SlidersHorizontal size={18} color="var(--ant-color-primary)" />
          <Typography.Text strong>AI Agent安全能力入口</Typography.Text>
        </Space>
      }
      variant="borderless"
      bodyPadding={20}
    >
      <div className="zh-competition-guide-grid">
        {items.map((item) => (
          <button
            key={item.title}
            type="button"
            className="zh-competition-guide-item"
            onClick={() => onOpenPage(item.page)}
          >
            <span className="zh-competition-guide-item__icon">{item.icon}</span>
            <span className="zh-competition-guide-item__main">
              <strong>{item.title}</strong>
              <span>{item.desc}</span>
              <em>{item.metric}</em>
            </span>
            <span className="zh-competition-guide-item__action">{item.action}</span>
          </button>
        ))}
      </div>
    </PanelCard>
  );
}
