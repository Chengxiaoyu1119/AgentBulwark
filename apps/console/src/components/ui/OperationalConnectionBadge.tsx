import { CircleAlert, CloudOff, LoaderCircle, ShieldAlert, Wifi } from 'lucide-react';
import type { OperationalConnection } from '../../app/useAppData';
import { LabelTag } from './LabelTag';

export type OperationalConnectionBadgeProps = {
  connection: OperationalConnection;
};

const connectionPresentation = {
  checking: { color: 'blue', label: '数据检测中', icon: LoaderCircle },
  online: { color: 'green', label: '实时数据在线', icon: Wifi },
  offline: { color: 'red', label: '后端不可达', icon: CloudOff },
  'auth-expired': { color: 'red', label: '会话已失效', icon: ShieldAlert },
  forbidden: { color: 'red', label: '数据访问受限', icon: ShieldAlert },
  degraded: { color: 'orange', label: '数据读取降级', icon: CircleAlert }
} as const;

export function OperationalConnectionBadge({ connection }: OperationalConnectionBadgeProps) {
  const presentation = connectionPresentation[connection.status];
  const Icon = presentation.icon;
  const label = connection.stale ? `${presentation.label} · 快照陈旧` : presentation.label;
  return (
    <span aria-live="polite" aria-label={`运行数据状态：${label}`} title={connection.message}>
      <LabelTag color={presentation.color}>
        <Icon size={12} aria-hidden="true" /> {label}
      </LabelTag>
    </span>
  );
}
