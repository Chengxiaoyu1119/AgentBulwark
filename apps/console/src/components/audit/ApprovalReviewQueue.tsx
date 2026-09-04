import { useMemo, useState } from 'react';
import { UiSpace, UiTypography } from '../ui';
import type { ApprovalReview, ApprovalReviewList } from '@/types';
import { LabelTag, PanelCard, UiAlert, UiButton, UiConfirmButton, UiSelect, UiStack } from '../ui';
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
  onDecision: (review: ApprovalReview, action: 'approve' | 'reject') => void;
  onCopy: (review: ApprovalReview) => void;
  focusAuditId?: string;
  onClearFocus?: () => void;
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
  onCopy,
  focusAuditId = '',
  onClearFocus
}: ApprovalReviewQueueProps) {
  const [statusFilter, setStatusFilter] = useState('待复核');
  const [page, setPage] = useState(1);
  const effectiveStatusFilter = focusAuditId ? '全部' : statusFilter;
  const focusedReview = useMemo(
    () => reviews.find((review) => review.audit_id === focusAuditId),
    [focusAuditId, reviews]
  );
  const orderedReviews = useMemo(
    () =>
      [...reviews]
        .filter((review) => effectiveStatusFilter === '全部' || review.status === effectiveStatusFilter)
        .filter((review) => review.scope === 'operational')
        .sort((left, right) => {
          if (focusAuditId) {
            const focusDiff = Number(right.audit_id === focusAuditId) - Number(left.audit_id === focusAuditId);
            if (focusDiff !== 0) return focusDiff;
          }
          return compareApprovalReviews(left, right);
        }),
    [effectiveStatusFilter, focusAuditId, reviews]
  );
  const pageCount = Math.max(1, Math.ceil(orderedReviews.length / REVIEW_PAGE_SIZE));
  const activePage = Math.min(page, pageCount);
  const visibleReviews = orderedReviews.slice((activePage - 1) * REVIEW_PAGE_SIZE, activePage * REVIEW_PAGE_SIZE);

  function updateStatusFilter(value: string) {
    onClearFocus?.();
    setStatusFilter(value);
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
      {focusAuditId ? (
        <UiAlert
          type={focusedReview ? 'success' : 'info'}
          showIcon
          title={focusedReview ? `已定位复核单 ${focusedReview.id}` : '正在等待对应复核单进入队列'}
          description={`审计 ID：${focusAuditId}`}
          action={
            onClearFocus ? (
              <UiButton size="small" onClick={onClearFocus}>
                清除定位
              </UiButton>
            ) : undefined
          }
          className="zh-mb-16"
        />
      ) : null}
      <div className="zh-approval-summary-grid">
        {[
          { label: '待复核', value: queue.summary.pending_count, tone: 'amber' },
          { label: '已批准', value: queue.summary.approved_count, tone: 'green' },
          { label: '已驳回', value: queue.summary.rejected_count, tone: 'red' },
          { label: 'hash 有效', value: `${queue.summary.hash_valid_count}/${queue.summary.total}`, tone: 'cyan' },
          { label: 'SLA 超时', value: queue.summary.sla_breached_count ?? 0, tone: 'red' }
        ].map((item) => (
          <div key={item.label} className={`zh-approval-summary-item zh-approval-summary-item--${item.tone}`}>
            <UiTypography.Text type="secondary">{item.label}</UiTypography.Text>
            <UiTypography.Text className="zh-approval-summary-value">{item.value}</UiTypography.Text>
          </div>
        ))}
      </div>
      {error ? (
        <UiTypography.Text type="danger" className="zh-text-block zh-mb-12">
          {error}
        </UiTypography.Text>
      ) : null}
      <UiSpace wrap className="zh-mb-12">
        <UiSelect
          value={effectiveStatusFilter}
          onChange={(value) => updateStatusFilter(String(value))}
          options={['全部', '待复核', '已批准', '已驳回'].map((value) => ({
            label: value === '全部' ? '全部审批状态' : value,
            value
          }))}
        />
        <UiTypography.Text type="secondary">
          当前范围 {orderedReviews.length} 条 · 每页最多 {REVIEW_PAGE_SIZE} 条
        </UiTypography.Text>
      </UiSpace>
      <UiStack gap="sm" className="zh-approval-review-list">
        {visibleReviews.map((review) => {
          const focused = review.audit_id === focusAuditId;
          return (
            <div
              key={review.id}
              className={`zh-approval-review-item${focused ? ' zh-approval-review-item--focused' : ''}`}
              aria-current={focused ? 'true' : undefined}
            >
              <div className="zh-approval-review-copy">
                <UiSpace wrap className="zh-approval-review-tags">
                  <LabelTag variant="filled" color={approvalStatusColor(review.status)}>
                    {review.status}
                  </LabelTag>
                  {executionStatus(review.execution_status) ? (
                    <LabelTag variant="filled" color={executionStatus(review.execution_status)?.color}>
                      {executionStatus(review.execution_status)?.label}
                    </LabelTag>
                  ) : null}
                  <UiTypography.Text strong>{review.tool}</UiTypography.Text>
                  {review.standard_capability && review.standard_capability !== review.tool ? (
                    <UiTypography.Text type="secondary">→ {review.standard_capability}</UiTypography.Text>
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
                  <UiTypography.Text type="secondary" className="zh-policy-inline">
                    Agent {review.agent_id}
                  </UiTypography.Text>
                  <UiTypography.Text type="secondary" className="zh-policy-inline">
                    策略 {review.policy_id}
                  </UiTypography.Text>
                  {review.escalation_level ? (
                    <LabelTag variant="filled" color={review.sla_breached ? 'error' : 'warning'}>
                      {review.escalation_level} · {review.sla_breached ? '已超时' : `${review.sla_minutes ?? 30} 分钟`}
                    </LabelTag>
                  ) : null}
                </UiSpace>
                <div className="zh-mt-4">
                  <UiTypography.Text type="secondary">{review.reason}</UiTypography.Text>
                </div>
                <UiSpace wrap size={8} className="zh-mt-4">
                  <UiTypography.Text type="secondary" className="zh-text-meta">
                    tool hash {(review.tool_call_hash || '-').slice(0, 16)}
                  </UiTypography.Text>
                  {review.execution_claim_agent_id ? (
                    <UiTypography.Text type="secondary" className="zh-text-meta">
                      领取 {review.execution_claim_agent_id} ·{' '}
                      {review.execution_claimed_at?.slice(0, 19).replace('T', ' ')}
                    </UiTypography.Text>
                  ) : null}
                  {review.execution_result_hash ? (
                    <UiTypography.Text type="secondary" className="zh-text-meta">
                      result {(review.execution_result_hash || '-').slice(0, 16)}
                    </UiTypography.Text>
                  ) : null}
                </UiSpace>
              </div>
              <UiSpace className="zh-approval-review-actions">
                {review.status === '待复核' ? (
                  <UiConfirmButton
                    size="small"
                    type="primary"
                    loading={busyId === review.id}
                    disabled={Boolean(busyId)}
                    confirmTitle="批准后允许 Agent 恢复执行？"
                    confirmDescription="请确认当前复核证据、工具参数和目标范围都符合预期。"
                    onConfirm={() => onDecision(review, 'approve')}
                  >
                    批准恢复
                  </UiConfirmButton>
                ) : null}
                {review.status === '待复核' ? (
                  <UiConfirmButton
                    size="small"
                    danger
                    loading={busyId === review.id}
                    disabled={Boolean(busyId)}
                    confirmTitle="驳回这条执行请求？"
                    confirmDescription="驳回后请求保持阻断，Agent 不会继续执行该工具调用。"
                    onConfirm={() => onDecision(review, 'reject')}
                  >
                    驳回
                  </UiConfirmButton>
                ) : null}
                <UiButton size="small" onClick={() => onCopy(review)}>
                  {copiedApprovalId === review.id ? '已复制' : '复制'}
                </UiButton>
              </UiSpace>
            </div>
          );
        })}
        {!orderedReviews.length && (
          <div className="zh-empty-panel">当前待办范围为空。可切换审批状态或记录范围查看历史记录。</div>
        )}
      </UiStack>
      {orderedReviews.length > REVIEW_PAGE_SIZE ? (
        <div className="zh-list-pagination">
          <UiTypography.Text type="secondary">
            第 {activePage}/{pageCount} 页 · 显示 {(activePage - 1) * REVIEW_PAGE_SIZE + 1}-
            {Math.min(activePage * REVIEW_PAGE_SIZE, orderedReviews.length)} 条
          </UiTypography.Text>
          <UiSpace>
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
          </UiSpace>
        </div>
      ) : null}
    </PanelCard>
  );
}
