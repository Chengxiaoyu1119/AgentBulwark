import { useEffect, useMemo, useState } from 'react';
import { Col, Row, Space, Typography } from 'antd';
import { FileDown, FileImage, FileText, RefreshCw } from 'lucide-react';
import { fetchBriefingSheetExports, writeBriefingSheetExports, writeProjectRoadmapEvidence } from '@/api';
import type { BriefingSheetExportResult } from '@/app/reportEvaluationApi';
import { LabelTag, MetricCard as Metric, PanelCard, SectionTitle, UiAlert, UiButton } from '../ui';

const surfaceNameMap: Record<string, string> = {
  'prompt-injection': '提示注入',
  jailbreak: '模型越狱',
  'data-leakage': '内容泄露',
  'abuse-risk': '滥用风险',
  'tool-hijack': '工具调用劫持',
  'memory-poison': '记忆中毒',
  'environment-pollution': '环境感知污染'
};

type Notice = {
  type: 'success' | 'error' | 'info';
  message: string;
};

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

function fileUrl(surfaceId: string, fileFormat: 'png' | 'pdf', version?: string) {
  const base = `/api/attack_surfaces/briefing_sheets/export/files/${encodeURIComponent(surfaceId)}.${fileFormat}`;
  return version ? `${base}?v=${encodeURIComponent(version)}` : base;
}

export function ReportBriefingExportGallery() {
  const [data, setData] = useState<BriefingSheetExportResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);

  const files = useMemo(() => data?.export.files ?? [], [data]);

  async function refreshExports(showNotice = false) {
    setLoading(true);
    try {
      const result = await fetchBriefingSheetExports();
      setData(result);
      if (showNotice) {
        setNotice({ type: 'success', message: '攻击面评测导出清单已刷新。' });
      }
    } catch (error) {
      setNotice({ type: 'error', message: `读取导出清单失败：${errorMessage(error, '未知错误')}` });
    } finally {
      setLoading(false);
    }
  }

  async function runExport() {
    setRunning(true);
    setNotice(null);
    try {
      const result = await writeBriefingSheetExports('both');
      await writeProjectRoadmapEvidence();
      setData(result);
      if (!result.ok) {
        throw new Error(result.reason || '导出脚本执行失败');
      }
      setNotice({
        type: 'success',
        message: `已生成 ${result.summary.png_count} 个 PNG 和 ${result.summary.pdf_count} 个 PDF，可直接逐项预览。`
      });
    } catch (error) {
      setNotice({ type: 'error', message: `导出攻击面评测单页失败：${errorMessage(error, '未知错误')}` });
    } finally {
      setRunning(false);
      setLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadInitialExports() {
      try {
        const result = await fetchBriefingSheetExports();
        if (!cancelled) {
          setData(result);
        }
      } catch (error) {
        if (!cancelled) {
          setNotice({ type: 'error', message: `读取导出清单失败：${errorMessage(error, '未知错误')}` });
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadInitialExports();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <PanelCard
      title={
        <SectionTitle
          title="攻击面评测 PNG/PDF"
          meta={data?.ok ? `${files.length} 类已导出` : '点击按钮生成最新文件'}
        />
      }
      variant="borderless"
    >
      <Row gutter={[16, 16]} className="zh-mb-24">
        <Col xs={24} sm={12} lg={6}>
          <Metric label="PNG 文件" value={`${data?.summary.png_count ?? 0}`} tone="cyan" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="PDF 文件" value={`${data?.summary.pdf_count ?? 0}`} tone="green" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric label="攻击面覆盖" value={`${data?.summary.exported_surface_count ?? 0}/7`} tone="amber" />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Metric
            label="导出状态"
            value={data?.ok ? '正常' : loading ? '读取中' : '待生成'}
            tone={data?.ok ? 'green' : 'amber'}
          />
        </Col>
      </Row>

      <div className="zh-brief-export-toolbar">
        <div className="zh-brief-export-copy">
          <Typography.Text strong>导出文件清单</Typography.Text>
          <Typography.Text type="secondary">重新导出会清理旧文件，页面预览会自动读取最新版本。</Typography.Text>
        </div>
        <Space wrap className="zh-brief-export-actions">
          <UiButton
            variant="primary"
            icon={<FileDown size={16} />}
            loading={running}
            disabled={loading}
            onClick={() => {
              void runExport();
            }}
          >
            重新导出全部
          </UiButton>
          <UiButton
            icon={<RefreshCw size={16} />}
            loading={loading && !running}
            disabled={running}
            onClick={() => {
              void refreshExports(true);
            }}
          >
            刷新清单
          </UiButton>
          <UiButton authenticatedHref="/api/attack_surfaces/briefing_sheets/export.md">打开导出报告</UiButton>
        </Space>
      </div>

      {notice && <UiAlert className="zh-mt-16" type={notice.type} message={notice.message} showIcon />}

      {files.length ? (
        <div className="zh-brief-export-table zh-mt-16">
          {files.map((file) => {
            const surfaceName = surfaceNameMap[file.surface_id] ?? file.surface_id;
            return (
              <div className="zh-brief-export-row" key={file.surface_id}>
                <div className="zh-brief-export-row__name">
                  <Typography.Text strong>{surfaceName}</Typography.Text>
                  <Typography.Text type="secondary" className="zh-text-meta">
                    最新评测单页
                  </Typography.Text>
                </div>
                <Space size={8} wrap className="zh-brief-export-row__status">
                  <LabelTag color={file.png_path ? 'success' : 'warning'}>
                    PNG {file.png_path ? '已生成' : '未生成'}
                  </LabelTag>
                  <LabelTag color={file.pdf_path ? 'success' : 'warning'}>
                    PDF {file.pdf_path ? '已生成' : '未生成'}
                  </LabelTag>
                </Space>
                <Space wrap className="zh-brief-export-file-actions">
                  <UiButton
                    size="small"
                    icon={<FileImage size={14} />}
                    authenticatedHref={file.png_path ? fileUrl(file.surface_id, 'png', data?.generated_at) : undefined}
                    disabled={!file.png_path}
                  >
                    预览 PNG
                  </UiButton>
                  <UiButton
                    size="small"
                    icon={<FileText size={14} />}
                    authenticatedHref={file.pdf_path ? fileUrl(file.surface_id, 'pdf', data?.generated_at) : undefined}
                    disabled={!file.pdf_path}
                  >
                    打开 PDF
                  </UiButton>
                </Space>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="zh-empty-panel">
          {loading ? '正在读取导出清单...' : '还没有 PNG/PDF 文件，点击“重新导出全部”即可生成。'}
        </div>
      )}
    </PanelCard>
  );
}
