import { Typography } from 'antd';
import { GatewayTracePanel } from '../components/settings/GatewayTracePanel';

export function SecurityEventsPanel() {
  return (
    <div className="zh-product-page">
      <header className="zh-product-heading">
        <div>
          <Typography.Title level={1}>安全事件</Typography.Title>
          <Typography.Text type="secondary">只显示被阻断、隔离或需要人工处理的真实请求。</Typography.Text>
        </div>
      </header>
      <GatewayTracePanel mode="events" />
    </div>
  );
}
