import { useMemo, useState } from 'react';
import { Flex, Space, Typography } from 'antd';
import type { AuditLog } from '@/types';
import { LabelTag, UiButton } from '../ui';

const AUDIT_PAGE_SIZE = 12;

interface AuditLogListProps {
  logs: AuditLog[];
  selectedLogId?: string;
  onSelectLog: (id: string) => void;
}

export function AuditLogList({ logs, selectedLogId, onSelectLog }: AuditLogListProps) {
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(logs.length / AUDIT_PAGE_SIZE));
  const selectedIndex = selectedLogId ? logs.findIndex((log) => log.id === selectedLogId) : -1;
  const selectedPage = selectedIndex >= 0 ? Math.floor(selectedIndex / AUDIT_PAGE_SIZE) + 1 : 0;
  const activePage = Math.min(selectedPage || page, pageCount);
  const visibleLogs = useMemo(
    () => logs.slice((activePage - 1) * AUDIT_PAGE_SIZE, activePage * AUDIT_PAGE_SIZE),
    [activePage, logs]
  );

  return (
    <div>
      <Typography.Text type="secondary" className="zh-text-block zh-mb-12">
        共 {logs.length} 条 · 每页最多 {AUDIT_PAGE_SIZE} 条
      </Typography.Text>
      <div className="zh-scroll-list zh-scroll-list--fixed">
        {visibleLogs.map((log) => {
          const selected = selectedLogId === log.id;

          return (
            <div
              key={log.id}
              onClick={() => onSelectLog(log.id)}
              className={`zh-selectable-list-item${selected ? ' zh-selectable-list-item--active' : ''}`}
            >
              <Flex justify="space-between" align="center" gap={16} wrap="wrap">
                <div className="zh-flex-min">
                  <Space wrap>
                    <Typography.Text strong className={selected ? 'zh-text-primary-active' : undefined}>
                      {log.tool}
                    </Typography.Text>
                    {log.standard_capability && log.standard_capability !== log.tool ? (
                      <Typography.Text type="secondary">→ {log.standard_capability}</Typography.Text>
                    ) : null}
                    <LabelTag
                      variant="filled"
                      color={log.decision === '允许' ? 'success' : log.decision === '拒绝' ? 'error' : 'warning'}
                    >
                      {log.decision}
                    </LabelTag>
                  </Space>
                  <div className="zh-mt-4">
                    <Typography.Paragraph type="secondary" ellipsis={{ rows: 2 }} className="zh-title-flush">
                      {log.reason}
                    </Typography.Paragraph>
                  </div>
                  <Space size={6} wrap>
                    <Typography.Text className="zh-text-meta zh-text-tertiary">
                      执行：
                      {log.execution_status === 'awaiting_receipt' || !log.execution_status
                        ? '等待回执'
                        : log.execution_status}
                    </Typography.Text>
                    <Typography.Text className="zh-text-meta zh-text-tertiary">
                      目标：{log.execution_target ?? '未确认'}
                    </Typography.Text>
                  </Space>
                </div>
                <div>
                  <Typography.Text className="zh-text-meta zh-text-tertiary">{log.policy_id}</Typography.Text>
                </div>
              </Flex>
            </div>
          );
        })}
        {!logs.length && <div className="zh-empty-panel">没有匹配的审计记录。</div>}
      </div>
      {logs.length > AUDIT_PAGE_SIZE ? (
        <div className="zh-list-pagination">
          <Typography.Text type="secondary">
            第 {activePage}/{pageCount} 页 · 显示 {(activePage - 1) * AUDIT_PAGE_SIZE + 1}-
            {Math.min(activePage * AUDIT_PAGE_SIZE, logs.length)} 条
          </Typography.Text>
          <Space>
            <UiButton
              size="small"
              disabled={activePage === 1}
              onClick={() => {
                setPage(Math.max(1, activePage - 1));
                onSelectLog('');
              }}
            >
              上一页
            </UiButton>
            <UiButton
              size="small"
              disabled={activePage === pageCount}
              onClick={() => {
                setPage(Math.min(pageCount, activePage + 1));
                onSelectLog('');
              }}
            >
              下一页
            </UiButton>
          </Space>
        </div>
      ) : null}
    </div>
  );
}
