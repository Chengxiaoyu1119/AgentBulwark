import { Typography } from 'antd';
import type { CompetitionReadiness } from '@/types';
import { UiAlert } from '../ui';

interface ReadinessClaimStatusProps {
  readiness: CompetitionReadiness;
}

export function ReadinessClaimStatus({ readiness }: ReadinessClaimStatusProps) {
  const completionClaimAllowed = readiness.completion_claim_allowed ?? readiness.overall_status === 'ready';

  return (
    <UiAlert
      title={completionClaimAllowed ? '整体交付已通过' : '整体交付仍有待办'}
      type={completionClaimAllowed ? 'success' : 'warning'}
      showIcon
      className="zh-settings-blocker-alert"
      description={
        <Typography.Text>
          {completionClaimAllowed
            ? '全部就绪检查均已通过，可生成完整交付声明。'
            : `当前有 ${readiness.summary.blocker_count} 个阻塞项、${readiness.summary.warning_count} 个需补强项；生产网关状态与整体交付状态分开显示。`}
        </Typography.Text>
      }
    />
  );
}
