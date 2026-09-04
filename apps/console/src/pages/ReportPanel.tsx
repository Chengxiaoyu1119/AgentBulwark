import { useState } from 'react';
import '../design/视觉系统/experiments.css';
import { Flex, Typography } from 'antd';
import { Copy, RefreshCw } from 'lucide-react';
import { LabelTag, PanelCard, UiButton, UiTabs } from '../components/ui';
import {
  ReportAttackEvaluationTab,
  ReportDeliveryTab,
  ReportNormalEvaluationTab,
  ReportOverviewTab
} from '../components/report';
import type { ReportData } from '../types';
import type { PageKey } from '../app/navigation';
import { writeClipboardText } from '../utils';

export function ReportPanel({
  report,
  reportSource,
  reportLoading = false,
  onOpenScenario,
  onOpenPage,
  onRefreshReport,
  onRefreshRuntime
}: {
  report: ReportData | null;
  reportSource?: 'backend' | 'fallback' | null;
  reportLoading?: boolean;
  onOpenScenario: (id: string) => void;
  onOpenPage?: (page: PageKey) => void;
  onRefreshReport?: () => Promise<void> | void;
  onRefreshRuntime?: () => Promise<unknown> | void;
}) {
  const [copied, setCopied] = useState(false);
  const [copiedFile, setCopiedFile] = useState('');
  const markdown = report?.markdown ?? '尚未生成证据，请点击“生成证据”后读取。';
  const competitionPackage = report?.competition_package;
  const packageFiles = competitionPackage?.files ?? [];
  const reportActionLabel = report ? '刷新证据' : '生成证据';

  async function copyReport() {
    const ok = await writeClipboardText(markdown);
    setCopied(ok);
    if (ok) {
      window.setTimeout(() => setCopied(false), 1600);
    }
  }

  async function copyPackageFile(filename: string, content: string) {
    const ok = await writeClipboardText(content);
    if (ok) {
      setCopiedFile(filename);
      window.setTimeout(() => setCopiedFile(''), 1600);
    }
  }

  function downloadPackageFile(filename: string, content: string, contentType: string) {
    const blob = new Blob([content], { type: `${contentType};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="zh-page-stack">
      <PanelCard variant="borderless">
        <Flex justify="space-between" align="center" className="zh-report-hero-row">
          <div className="zh-flex-min zh-report-hero-copy">
            <Typography.Title level={3} className="zh-title-flush">
              证据导出（按需）
            </Typography.Title>
            <Typography.Text type="secondary" className="zh-text-body zh-text-block zh-mt-4">
              运行时防护不依赖此页；只有在需要复核、答辩或提交材料时，才生成并导出固定证据。
            </Typography.Text>
          </div>
          <Flex gap={8} wrap="wrap">
            <UiButton
              loading={reportLoading}
              disabled={reportLoading || !onRefreshReport}
              icon={<RefreshCw size={16} />}
              onClick={() => void onRefreshReport?.()}
            >
              {reportActionLabel}
            </UiButton>
            <UiButton
              className="zh-report-copy-button"
              disabled={!report}
              icon={<Copy size={16} />}
              onClick={copyReport}
            >
              {copied ? '已复制' : '复制 Markdown'}
            </UiButton>
          </Flex>
        </Flex>
        <LabelTag
          variant="filled"
          color={reportSource === 'backend' ? 'success' : reportSource === 'fallback' ? 'warning' : 'default'}
        >
          {reportSource === 'backend'
            ? '真实后端数据'
            : reportSource === 'fallback'
              ? '内置模拟数据'
              : reportLoading
                ? '正在生成证据'
                : '尚未生成证据'}
        </LabelTag>
      </PanelCard>

      {report ? (
        <UiTabs
          className="zh-report-tabs"
          defaultActiveKey="4"
          size="large"
          items={[
            {
              key: '1',
              label: '报告概览与成熟度',
              children: (
                <ReportOverviewTab
                  report={report}
                  onRefreshReport={onRefreshReport}
                  onRefreshRuntime={onRefreshRuntime}
                  onOpenPage={onOpenPage}
                />
              )
            },
            {
              key: '2',
              label: '攻防实战评测',
              children: (
                <ReportAttackEvaluationTab
                  report={report}
                  onOpenScenario={onOpenScenario}
                  onRefreshReport={onRefreshReport}
                  onRefreshRuntime={onRefreshRuntime}
                />
              )
            },
            {
              key: '3',
              label: '正常与消融评测',
              children: <ReportNormalEvaluationTab report={report} onRefreshReport={onRefreshReport} />
            },
            {
              key: '4',
              label: '成果交付与接口',
              children: (
                <ReportDeliveryTab
                  competitionPackage={competitionPackage}
                  packageFiles={packageFiles}
                  markdown={markdown}
                  copiedFile={copiedFile}
                  copyPackageFile={copyPackageFile}
                  downloadPackageFile={downloadPackageFile}
                />
              )
            }
          ]}
        />
      ) : (
        <PanelCard variant="borderless" className="zh-centered-panel">
          <Typography.Text type="secondary">
            {reportLoading ? '正在生成证据...' : '尚未生成证据，点击“生成证据”后读取。'}
          </Typography.Text>
        </PanelCard>
      )}
    </div>
  );
}
