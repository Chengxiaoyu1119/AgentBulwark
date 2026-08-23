import { useMemo, useState } from 'react';
import { Flex, Space, Typography } from 'antd';
import { ExternalLink, RotateCcw, Search } from 'lucide-react';
import type { ReportData } from '@/types';
import { LabelTag, UiButton, UiInput, UiSelect, UiTable } from '../ui';

type ReportNormalCaseExplorerProps = {
  evaluation: ReportData['benign_evaluation'];
};

export function ReportNormalCaseExplorer({ evaluation }: ReportNormalCaseExplorerProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('全部类别');
  const [tool, setTool] = useState('全部工具');

  const categoryOptions = useMemo(
    () => [
      { label: '全部类别', value: '全部类别' },
      ...Object.keys(evaluation.summary.category_distribution).map((item) => ({ label: item, value: item }))
    ],
    [evaluation.summary.category_distribution]
  );
  const toolOptions = useMemo(
    () => [
      { label: '全部工具', value: '全部工具' },
      ...Object.keys(evaluation.summary.tool_distribution).map((item) => ({ label: item, value: item }))
    ],
    [evaluation.summary.tool_distribution]
  );
  const filteredCases = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    return evaluation.cases.filter((item) => {
      const haystack = [
        item.id,
        item.category,
        item.title,
        item.business_purpose,
        item.tool_call.tool,
        item.policy_id,
        item.reason,
        item.recommendation
      ]
        .join(' ')
        .toLowerCase();
      return (
        (!keyword || haystack.includes(keyword)) &&
        (category === '全部类别' || item.category === category) &&
        (tool === '全部工具' || item.tool_call.tool === tool)
      );
    });
  }, [category, evaluation.cases, query, tool]);

  function resetFilters() {
    setQuery('');
    setCategory('全部类别');
    setTool('全部工具');
  }

  return (
    <>
      <div className="zh-report-filter-toolbar zh-mb-16">
        <div className="zh-report-filter-copy">
          <Typography.Text strong>可检索正常任务样本</Typography.Text>
          <Typography.Text type="secondary">
            用来证明监督器不会把正常读写文件、发送邮件、调用 API 等比赛业务一刀切拦截。
          </Typography.Text>
        </div>
        <div className="zh-report-filter-controls">
          <UiInput
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索样本、工具、策略、原因"
            prefix={<Search size={14} />}
          />
          <UiSelect value={category} options={categoryOptions} onChange={setCategory} />
          <UiSelect value={tool} options={toolOptions} onChange={setTool} />
          <UiButton icon={<RotateCcw size={14} />} onClick={resetFilters}>
            重置
          </UiButton>
        </div>
      </div>

      <Flex justify="space-between" align="center" gap={12} wrap="wrap" className="zh-mb-12">
        <Typography.Text type="secondary">
          当前显示 {filteredCases.length}/{evaluation.cases.length} 个样本，误报{' '}
          {filteredCases.filter((item) => item.is_false_positive).length} 个。
        </Typography.Text>
        <Space wrap>
          <UiButton size="small" authenticatedHref="/api/datasets/benign_cases.md" icon={<ExternalLink size={14} />}>
            打开样本集
          </UiButton>
          <UiButton size="small" authenticatedHref="/api/evaluations/benign" icon={<ExternalLink size={14} />}>
            打开评测 JSON
          </UiButton>
        </Space>
      </Flex>

      <UiTable
        dataSource={filteredCases}
        rowKey="id"
        size="small"
        pagination={{ pageSize: 8, showSizeChanger: false }}
        scroll={{ x: 980 }}
        columns={[
          {
            title: '样本',
            dataIndex: 'id',
            width: 150,
            render: (text, record) => (
              <Space orientation="vertical" size={0}>
                <Typography.Text strong>{text}</Typography.Text>
                <Typography.Text type="secondary" className="zh-text-sm">
                  {record.title}
                </Typography.Text>
              </Space>
            )
          },
          { title: '类别', dataIndex: 'category', width: 120 },
          {
            title: '工具',
            key: 'tool',
            width: 120,
            render: (_, record) => <Typography.Text code>{record.tool_call.tool}</Typography.Text>
          },
          { title: '期望', dataIndex: 'expected_decision', width: 90 },
          { title: '实际', dataIndex: 'decision', width: 90 },
          {
            title: '误报',
            key: 'is_false_positive',
            width: 90,
            render: (_, record) => (
              <LabelTag variant="filled" color={record.is_false_positive ? 'error' : 'success'}>
                {record.is_false_positive ? '是' : '否'}
              </LabelTag>
            )
          },
          {
            title: '策略与原因',
            key: 'policy_reason',
            render: (_, record) => (
              <Space orientation="vertical" size={0}>
                <Typography.Text code>{record.policy_id}</Typography.Text>
                <Typography.Text type="secondary" className="zh-text-sm">
                  {record.reason}
                </Typography.Text>
              </Space>
            )
          }
        ]}
      />
    </>
  );
}
