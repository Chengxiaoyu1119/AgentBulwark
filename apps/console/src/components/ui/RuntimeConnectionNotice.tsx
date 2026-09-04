import { UiAlert } from './AntdControls';

export type RuntimeConnectionNoticeProps = {
  connection: {
    status: 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'unavailable';
    message: string;
  };
};

export function RuntimeConnectionNotice({ connection }: RuntimeConnectionNoticeProps) {
  if (connection.status !== 'reconnecting' && connection.status !== 'unavailable') return null;
  return (
    <UiAlert
      type={connection.status === 'unavailable' ? 'error' : 'warning'}
      showIcon
      title={connection.status === 'unavailable' ? '实时更新已停止' : '实时更新正在恢复'}
      description={connection.message}
      className="zh-runtime-connection-notice"
    />
  );
}
