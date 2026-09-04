import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Typography } from 'antd';
import { RefreshCw } from 'lucide-react';
import { PanelCard, UiAlert, UiButton } from '../components/ui';

type Props = { children: ReactNode };
type State = { hasError: boolean };

/** Keep one malformed response or lazy page from blanking the whole console. */
export class AppErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(_error: Error, info: ErrorInfo) {
    // Keep diagnostics out of the UI; the component stack is enough for local
    // debugging and does not echo provider or Agent payloads to the operator.
    console.error('控制台页面渲染失败', info.componentStack);
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <main className="zh-auth-page" role="alert">
        <section className="zh-auth-shell" aria-labelledby="console-error-title">
          <PanelCard variant="borderless" className="zh-auth-card">
            <Typography.Title level={2} id="console-error-title" className="zh-title-flush">
              控制台暂时无法渲染
            </Typography.Title>
            <UiAlert
              type="error"
              showIcon
              title="当前页面出现未预期错误"
              description="实时数据不会被伪造或继续写入；重新加载后会重新验证当前操作员会话。"
              className="zh-mt-16"
            />
            <UiButton type="primary" icon={<RefreshCw size={16} />} onClick={this.handleReload} block>
              重新加载控制台
            </UiButton>
          </PanelCard>
        </section>
      </main>
    );
  }
}
