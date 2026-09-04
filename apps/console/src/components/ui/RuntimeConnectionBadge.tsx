import { Radio } from 'lucide-react';
import { LabelTag } from './LabelTag';

export type RuntimeConnectionBadgeProps = {
  connection: {
    status: 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'unavailable';
    attempt: number;
    message: string;
  };
};

export function RuntimeConnectionBadge({ connection }: RuntimeConnectionBadgeProps) {
  const color =
    connection.status === 'connected'
      ? 'green'
      : connection.status === 'connecting'
        ? 'blue'
        : connection.status === 'reconnecting'
          ? 'orange'
          : connection.status === 'unavailable'
            ? 'red'
            : 'default';
  const label =
    connection.status === 'connected'
      ? '实时连接'
      : connection.status === 'connecting'
        ? '连接中'
        : connection.status === 'reconnecting'
          ? `重连中（${connection.attempt}）`
          : connection.status === 'unavailable'
            ? '实时不可用'
            : '实时未启动';

  return (
    <span aria-live="polite" title={connection.message}>
      <LabelTag color={color}>
        <Radio size={12} aria-hidden="true" /> {label}
      </LabelTag>
    </span>
  );
}
