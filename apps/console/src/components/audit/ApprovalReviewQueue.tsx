import { useMemo, useState } from 'react';
import { Space, Typography } from 'antd';
import type { ApprovalReview, ApprovalReviewList } from '@/types';
import { LabelTag, PanelCard, UiButton, UiSelect } from '../ui';
import { compareApprovalReviews } from './approvalReviewSorting';

const REVIEW_PAGE_SIZE = 8;

interface ApprovalReviewQueueProps {
  queue: ApprovalReviewList;
  reviews: ApprovalReview[];
  loading: boolean;
  error: string;
  busyId: string;
  copiedApprovalId: string;
  onRefresh: () => void;
  onDecision: (review: ApprovalReview, action: 'approve' | 'reject', executeInSandbox?: boolean) => void;
  onCopy: (review: ApprovalReview) => void;
}

function approvalStatusColor(status: ApprovalReview['status']) {
  if (status === '待复核') return 'processing';
  if (status === '已批准') return 'success';
  return 'error';
}

function executionStatus(status?: ApprovalReview['execution_status']) {
  if (!status) return undefined;

  return {
    pending_review: { label: '等待审批', color: 'processing' },
    ready_to_resume: { label: '等待Agent恢复', color: 'warning' },
    claimed: { label: 'Agent执行中', color: 'processing' },
    completed: { label: '工具已执行', color: 'success' },
    failed: { label: '恢复执行失败', color: 'error' },
    rejected: { label: '保持阻断', color: 'error' },
    sandbox_replayed: { label: '已在隔离环境重放', color: 'cyan' }
  }[status];
}

export function ApprovalReviewQueue({
  queue,
  reviews,
  loading,
  error,
  busyId,
  copiedApprovalId,
  onRefresh,
  onDecision,
  onCopy
}: ApprovalReviewQueueProps) {
  const [statusFilter, setStatusFilter] = useState('待复核');
  const [scopeFilter, setScopeFilter] = useState('operational');
  const [page, setPage] = useState(1);
  const orderedReviews = useMemo(
    () =>
      [...reviews]
        .filter((review) => statusFilter === '全部' || review.status === statusFilter)
        .filter((review) => scopeFilter === '全部' || review.scope === scopeFilter)
        .sort(compareApprovalReviews),
    [reviews, scopeFilter, statusFilter]
  );
  const pageCount = Math.max(1, Math.ceil(orderedReviews.length / REVIEW_PAGE_SIZE));
  const activePage = Math.min(page, pageCount);
  const visibleReviews = orderedReviews.slice((activePage - 1) * REVIEW_PAGE_SIZE, activePage * REVIEW_PAGE_SIZE);

  function updateStatusFilter(value: string) {
    setStatusFilter(value);
    setPage(1);
  }

  function updateScopeFilter(value: string) {
    setScopeFilter(value);
    setPage(1);
  }

  return (
    <PanelCard
      title="人工复核队列"
      extra={
        <UiButton onClick={onRefresh} loading={loading}>
          刷新队列
        </UiButton>
      }
      variant="borderless"
    >
      <div className="zh-approval-summary-grid">
        {[
          { label: '待复核', value: queue.summary.pending_count, tone: 'amber' },
          { label: '已批准', value: queue.summary.approved_count, tone: 'green' },
          { label: '已驳回', value: queue.summary.rejected_count, tone: 'red' },
          { label: 'hash 有效', value: `${queue.summary.hash_valid_count}/${queue.summary.total}`, tone: 'cyan' },
          { label: 'SLA 超时', value: queue.summary.sla_breached_count ?? 0, tone: 'red' }
        ].map((item) => (
          <div key={item.label} className={`zh-approval-summary-item zh-approval-summary-item--${item.tone}`}>
            <Typography.Text type="secondary">{item.label}</Typography.Text>
            <Typography.Text className="zh-approval-summary-value">{item.value}</Typography.Text>
          </div>
        ))}
      </div>
      {error ? (
        <Typography.Text type="danger" className="zh-text-block zh-mb-12">
          {error}
        </Typography.Text>
      ) : null}
      <Space wrap className="zh-mb-12">
        <UiSelect
          value={statusFilter}
          onChange={(value) => updateStatusFilter(String(value))}
          options={['全部', '待复核', '已批准', '已驳回'].map((value) => ({
            label: value === '全部' ? '全部审批状态' : value,
            value
          }))}
        />
        <UiSelect
          value={scopeFilter}
          onChange={(value) => updateScopeFilter(String(value))}
          options={[
            { label: '全部记录范围', value: '全部' },
            { label: '业务', value: 'operational' },
            { label: '实验', value: 'experiment' },
            { label: '演示', value: 'demo' }
          ]}
        />
        <Typography.Text type="secondary">
          当前范围 {orderedReviews.length} 条 · 每页最多 {REVIEW_PAGE_SIZE} 条
        </Typography.Text>
      </Space>
      <div className="zh-column-stack zh-approval-review-list">
        {visibleReviews.map((review) => (
          <div key={review.id} className="zh-approval-review-item">
            <div className="zh-approval-review-copy">
              <Space wrap className="zh-approval-review-tags">
                <LabelTag variant="filled" color={approvalStatusColor(review.status)}>
                  {review.status}
                </LabelTag>
                {executionStatus(review.execution_status) ? (
                  <LabelTag variant="filled" color={executionStatus(review.execution_status)?.color}>
                    {executionStatus(review.execution_status)?.label}
                  </LabelTag>
                ) : null}
                <Typography.Text strong>{review.tool}</Typography.Text>
                {review.standard_capability && review.standard_capability !== review.tool ? (
                  <Typography.Text type="secondary">→ {review.standard_capability}</Typography.Text>
                ) : null}
                <LabelTag variant="filled" color={review.scope === 'operational' ? 'blue' : 'default'}>
                  {review.scope === 'operational'
                    ? '业务'
                    : review.scope === 'experiment'
                      ? '实验'
                      : review.scope === 'demo'
                        ? '演示'
                        : '未标注'}
                </LabelTag>
                <Typography.Text type="secondary" className="zh-policy-inline">
                  Agent {review.agent_id}
                </Typography.Text>
                <Typography.Text type="secondary" className="zh-policy-inline">
                  策略 {review.policy_id}
                </Typography.Text>
                {review.escalation_level ? (
                  <LabelTag variant="filled" color={review.sla_breached ? 'error' : 'warning'}>
                    {review.escalation_level} · {review.sla_breached ? '已超时' : `${review.sla_minutes ?? 30} 分钟`}
                  </LabelTag>
                ) : null}
              </Space>
              <div className="zh-mt-4">
                <Typography.Text type="secondary">{review.reason}</Typography.Text>
              </div>
              <Space wrap size={8} className="zh-mt-4">
                <Typography.Text type="secondary" className="zh-text-meta">
                  tool hash {(review.tool_call_hash || '-').slice(0, 16)}
                </Typography.Text>
                {review.execution_claim_agent_id ? (
                  <Typography.Text type="secondary" className="zh-text-meta">
                    领取 {review.execution_claim_agent_id} ·{' '}
                    {review.execution_claimed_at?.slice(0, 19).replace('T', ' ')}
                  </Typography.Text>
                ) : null}
                {review.execution_result_hash ? (
                  <Typography.Text type="secondary" className="zh-text-meta">
                    result {(review.execution_result_hash || '-').slice(0, 16)}
                  </Typography.Text>
                ) : null}
              </Space>
            </div>
            <Space className="zh-approval-review-actions">
              {review.status === '待复核' ? (
                <UiButton
                  size="small"
                  type="primary"
                  loading={busyId === review.id}
                  disabled={Boolean(busyId)}
                  onClick={() => onDecision(review, 'approve', false)}
                >
                  批准恢复
                </UiButton>
              ) : null}
              {review.status === '待复核' ? (
                <UiButton
                  size="small"
                  loading={busyId === review.id}
                  disabled={Boolean(busyId)}
                  onClick={() => onDecision(review, 'approve', true)}
                >
                  沙箱重放
                </UiButton>
              ) : null}
              {review.status === '待复核' ? (
                <UiButton
                  size="small"
                  danger
                  loading={busyId === review.id}
                  disabled={Boolean(busyId)}
                  onClick={() => onDecision(review, 'reject')}
                >
                  驳回
                </UiButton>
              ) : null}
              <UiButton size="small" onClick={() => onCopy(review)}>
                {copiedApprovalId === review.id ? '已复制' : '复制'}
              </UiButton>
            </Space>
          </div>
        ))}
        {!orderedReviews.length && (
          <div className="zh-empty-panel">当前待办范围为空。可切换审批状态或记录范围查看历史记录。</div>
        )}
      </div>
      {orderedReviews.length > REVIEW_PAGE_SIZE ? (
        <div className="zh-list-pagination">
          <Typography.Text type="secondary">
            第 {activePage}/{pageCount} 页 · 显示 {(activePage - 1) * REVIEW_PAGE_SIZE + 1}-
            {Math.min(activePage * REVIEW_PAGE_SIZE, orderedReviews.length)} 条
          </Typography.Text>
          <Space>
            <UiButton
              size="small"
              disabled={activePage === 1}
              onClick={() => setPage((value) => Math.max(1, value - 1))}
            >
              上一页
            </UiButton>
            <UiButton
              size="small"
              disabled={activePage === pageCount}
              onClick={() => setPage((value) => Math.min(pageCount, value + 1))}
            >
              下一页
            </UiButton>
          </Space>
        </div>
      ) : null}
    </PanelCard>
  );
}
