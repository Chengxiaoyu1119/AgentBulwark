import { useCallback, useEffect, useMemo, useState } from 'react';
import { decideApprovalReview, fetchApprovalReviews } from '@/app/operationalApi';
import type { ApprovalReview, ApprovalReviewList, AuditLog } from '@/types';
import { writeClipboardText } from '@/utils';
import { compareApprovalReviews } from './approvalReviewSorting';
import { auditDeepLinkEvent, getAuditIdFromHash } from './auditDeepLink';
import { buildApprovalEvidenceText, buildAuditEvidenceText, buildFilteredAuditEvidenceText } from './auditEvidenceText';

type ApprovalAction = 'approve' | 'reject';

interface UseAuditLogViewModelParams {
  logs: AuditLog[];
  refresh: () => void | Promise<void>;
}

const emptyApprovalQueue: ApprovalReviewList = {
  generated_at: '',
  status_filter: '全部',
  summary: {
    total: 0,
    pending_count: 0,
    approved_count: 0,
    rejected_count: 0,
    high_risk_count: 0,
    hash_valid_count: 0,
    latest_created_at: '',
    latest_reviewed_at: ''
  },
  reviews: []
};

function toolWasExecuted(log: AuditLog) {
  return Boolean(log.tool_output?.executed);
}

export function useAuditLogViewModel({ logs, refresh }: UseAuditLogViewModelParams) {
  const [query, setQuery] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('全部');
  const [riskFilter, setRiskFilter] = useState('全部');
  const [riskScoreFilter, setRiskScoreFilter] = useState('全部');
  const [toolFilter, setToolFilter] = useState('全部');
  const [executionFilter, setExecutionFilter] = useState('全部');
  const [selectedLogId, setSelectedLogId] = useState('');
  const [copied, setCopied] = useState(false);
  const [copiedFiltered, setCopiedFiltered] = useState(false);
  const [copiedApprovalId, setCopiedApprovalId] = useState('');
  const [approvalQueue, setApprovalQueue] = useState<ApprovalReviewList>(emptyApprovalQueue);
  const [approvalLoading, setApprovalLoading] = useState(false);
  const [approvalError, setApprovalError] = useState('');
  const [approvalBusyId, setApprovalBusyId] = useState('');
  const [activeAuditLinkId, setActiveAuditLinkId] = useState('');

  const tools = useMemo(() => Array.from(new Set(logs.map((log) => log.tool))), [logs]);

  const filteredLogs = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    const minRiskScore = riskScoreFilter === '全部' ? null : Number(riskScoreFilter);

    return logs
      .filter((log) => {
        const text =
          `${log.id} ${log.audit_hash ?? ''} ${log.previous_hash ?? ''} ${log.tool_call_hash ?? ''} ${log.tool} ${log.standard_capability ?? ''} ${log.decision} ${log.risk_level} ${log.policy_id} ${log.reason} ${log.recommendation} ${log.execution_status ?? ''} ${log.execution_target ?? ''} ${(log.risk_factors ?? []).join(' ')} ${log.risk_score ?? ''}`.toLowerCase();

        const receiptStatus = log.execution_status ?? 'awaiting_receipt';
        const receiptConfirmed = Boolean(log.execution_receipt);

        return (
          (!keyword || text.includes(keyword)) &&
          (decisionFilter === '全部' || log.decision === decisionFilter) &&
          (riskFilter === '全部' || log.risk_level === riskFilter) &&
          (riskScoreFilter === '全部' || (log.risk_score ?? 0) >= (minRiskScore ?? 0)) &&
          (toolFilter === '全部' || log.tool === toolFilter) &&
          (executionFilter === '全部' ||
            (executionFilter === '待核查'
              ? receiptStatus === 'unknown'
              : executionFilter === '已执行'
                ? toolWasExecuted(log)
                : executionFilter === '未执行'
                  ? !toolWasExecuted(log)
                  : executionFilter === '回执已确认'
                    ? receiptConfirmed
                    : executionFilter === '等待回执'
                      ? !receiptConfirmed
                      : executionFilter === '执行失败'
                        ? receiptStatus === 'failed'
                        : true))
        );
      })
      .sort((a, b) => {
        const riskScoreDiff = (b.risk_score ?? 0) - (a.risk_score ?? 0);
        if (riskScoreDiff !== 0) return riskScoreDiff;
        return String(b.timestamp ?? '').localeCompare(String(a.timestamp ?? ''));
      });
  }, [decisionFilter, executionFilter, logs, query, riskFilter, riskScoreFilter, toolFilter]);

  const selectedLog = filteredLogs.find((log) => log.id === selectedLogId) ?? filteredLogs[0];
  const selectLog = useCallback((logId: string) => {
    setSelectedLogId(logId);
  }, []);
  const controlledCount = logs.filter((log) => ['拒绝', '询问', '隔离'].includes(log.decision)).length;
  const highRiskCount = logs.filter((log) => ['high', 'critical'].includes(log.risk_level)).length;
  const executedCount = logs.filter(toolWasExecuted).length;
  const receiptCount = logs.filter((log) => Boolean(log.execution_receipt)).length;
  const unconfirmedCount = logs.filter((log) => log.execution_receipt_expected && !log.execution_receipt).length;
  const latestReviews = useMemo(() => [...approvalQueue.reviews].sort(compareApprovalReviews), [approvalQueue.reviews]);

  const loadApprovalReviews = useCallback(async () => {
    setApprovalLoading(true);
    setApprovalError('');
    try {
      setApprovalQueue(await fetchApprovalReviews('全部', 100));
    } catch {
      setApprovalError('复核队列暂时不可用，请确认后端服务已经启动。');
    } finally {
      setApprovalLoading(false);
    }
  }, []);

  const handleApprovalDecision = useCallback(
    async (review: ApprovalReview, action: ApprovalAction) => {
      setApprovalBusyId(review.id);
      setApprovalError('');
      try {
        await decideApprovalReview(
          review.id,
          action,
          action === 'approve'
            ? '生产复核：确认可由原始 Agent 按最小权限恢复一次。'
            : '复核驳回：外部收件人或敏感数据范围未满足授权条件。'
        );
        await loadApprovalReviews();
        await refresh();
      } catch {
        setApprovalError('审批动作写入失败，请检查后端接口或复核单状态。');
      } finally {
        setApprovalBusyId('');
      }
    },
    [loadApprovalReviews, refresh]
  );

  const copyApprovalEvidence = useCallback(async (review: ApprovalReview) => {
    const ok = await writeClipboardText(buildApprovalEvidenceText(review));
    if (ok) {
      setCopiedApprovalId(review.id);
      window.setTimeout(() => setCopiedApprovalId(''), 1500);
    }
  }, []);

  const resetAuditFilters = useCallback(() => {
    setQuery('');
    setDecisionFilter('全部');
    setRiskFilter('全部');
    setRiskScoreFilter('全部');
    setToolFilter('全部');
    setExecutionFilter('全部');
    setActiveAuditLinkId('');
  }, []);

  const applyAuditDeepLink = useCallback(
    (auditId: string) => {
      const normalized = auditId.trim();
      if (!normalized) return;

      setQuery(normalized);
      setDecisionFilter('全部');
      setRiskFilter('全部');
      setRiskScoreFilter('全部');
      setToolFilter('全部');
      setExecutionFilter('全部');
      selectLog(normalized);
      setActiveAuditLinkId(normalized);
    },
    [selectLog]
  );

  const copyEvidence = useCallback(async () => {
    if (!selectedLog) return;
    const ok = await writeClipboardText(buildAuditEvidenceText(selectedLog));
    setCopied(ok);
    if (ok) {
      window.setTimeout(() => setCopied(false), 1500);
    }
  }, [selectedLog]);

  const copyFilteredAuditEvidence = useCallback(async () => {
    const ok = await writeClipboardText(buildFilteredAuditEvidenceText(filteredLogs));
    setCopiedFiltered(ok);
    if (ok) {
      window.setTimeout(() => setCopiedFiltered(false), 1500);
    }
  }, [filteredLogs]);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(() => {
      if (!cancelled) {
        void loadApprovalReviews();
      }
    });
    return () => {
      cancelled = true;
    };
  }, [loadApprovalReviews, logs]);

  useEffect(() => {
    let cancelled = false;
    void Promise.resolve().then(() => {
      if (!cancelled) {
        applyAuditDeepLink(getAuditIdFromHash());
      }
    });

    const handleHashChange = () => applyAuditDeepLink(getAuditIdFromHash());
    const handleAuditDeepLink = (event: Event) => {
      const auditId = (event as CustomEvent<{ auditId?: string }>).detail?.auditId ?? getAuditIdFromHash();
      applyAuditDeepLink(auditId);
    };

    window.addEventListener('hashchange', handleHashChange);
    window.addEventListener(auditDeepLinkEvent, handleAuditDeepLink);

    return () => {
      cancelled = true;
      window.removeEventListener('hashchange', handleHashChange);
      window.removeEventListener(auditDeepLinkEvent, handleAuditDeepLink);
    };
  }, [applyAuditDeepLink]);

  return {
    query,
    setQuery,
    decisionFilter,
    setDecisionFilter,
    riskFilter,
    setRiskFilter,
    riskScoreFilter,
    setRiskScoreFilter,
    toolFilter,
    setToolFilter,
    executionFilter,
    setExecutionFilter,
    selectedLog,
    selectedLogId,
    setSelectedLogId: selectLog,
    copied,
    copiedFiltered,
    copiedApprovalId,
    activeAuditLinkId,
    approvalQueue,
    approvalLoading,
    approvalError,
    approvalBusyId,
    tools,
    filteredLogs,
    controlledCount,
    highRiskCount,
    executedCount,
    receiptCount,
    unconfirmedCount,
    latestReviews,
    loadApprovalReviews,
    handleApprovalDecision,
    copyApprovalEvidence,
    resetAuditFilters,
    copyEvidence,
    copyFilteredAuditEvidence
  };
}
export type AuditLogViewModel = ReturnType<typeof useAuditLogViewModel>;
