import { Flex } from 'antd';
import { riskLabel } from '@/utils';
import { UiButton, UiInput, UiSelect } from '../ui';

interface AuditFilterBarProps {
  query: string;
  decisionFilter: string;
  riskFilter: string;
  riskScoreFilter: string;
  toolFilter: string;
  executionFilter: string;
  tools: string[];
  copiedFiltered: boolean;
  onQueryChange: (value: string) => void;
  onDecisionFilterChange: (value: string) => void;
  onRiskFilterChange: (value: string) => void;
  onRiskScoreFilterChange: (value: string) => void;
  onToolFilterChange: (value: string) => void;
  onExecutionFilterChange: (value: string) => void;
  onReset: () => void;
  onCopyFiltered: () => void;
}

export function AuditFilterBar({
  query,
  decisionFilter,
  riskFilter,
  riskScoreFilter,
  toolFilter,
  executionFilter,
  tools,
  copiedFiltered,
  onQueryChange,
  onDecisionFilterChange,
  onRiskFilterChange,
  onRiskScoreFilterChange,
  onToolFilterChange,
  onExecutionFilterChange,
  onReset,
  onCopyFiltered
}: AuditFilterBarProps) {
  return (
    <Flex gap={16} wrap="wrap" className="zh-mb-16" justify="space-between">
      <Flex gap={16} wrap="wrap" className="zh-flex-spacer">
        <UiInput
          placeholder="搜索审计编号、工具、策略、原因..."
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          className="zh-filter-control--query"
        />
        <UiSelect
          value={decisionFilter}
          onChange={onDecisionFilterChange}
          className="zh-filter-control--sm"
          options={['全部', '允许', '拒绝', '询问', '隔离'].map((value) => ({
            label: value === '全部' ? '全部决策' : value,
            value
          }))}
        />
        <UiSelect
          value={riskFilter}
          onChange={onRiskFilterChange}
          className="zh-filter-control--sm"
          options={['全部', 'critical', 'high', 'medium', 'low'].map((value) => ({
            label: value === '全部' ? '全部风险' : riskLabel[value],
            value
          }))}
        />
        <UiSelect
          value={riskScoreFilter}
          onChange={onRiskScoreFilterChange}
          className="zh-filter-control--sm"
          options={[
            ['全部', '全部风险分'],
            ['50', '≥ 50'],
            ['70', '≥ 70'],
            ['90', '≥ 90']
          ].map(([value, label]) => ({ label, value }))}
        />
        <UiSelect
          value={toolFilter}
          onChange={onToolFilterChange}
          className="zh-filter-control--md"
          options={['全部', ...tools].map((value) => ({
            label: value === '全部' ? '全部工具' : value,
            value
          }))}
        />
        <UiSelect
          value={executionFilter}
          onChange={onExecutionFilterChange}
          className="zh-filter-control--sm"
          options={['全部', '已执行', '未执行', '回执已确认', '等待回执', '执行失败'].map((value) => ({
            label: value === '全部' ? '全部执行状态' : value,
            value
          }))}
        />
      </Flex>
      <Flex gap={16} wrap="wrap">
        <UiButton onClick={onReset}>重置</UiButton>
        <UiButton onClick={onCopyFiltered}>{copiedFiltered ? '已复制' : '复制当前筛选'}</UiButton>
      </Flex>
    </Flex>
  );
}
