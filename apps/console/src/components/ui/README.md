# 基础 UI 组件规范

这个目录只放跨页面复用的基础组件。

## 已有组件

- `UiButton`：统一按钮，不再手写 `primary-button`、`ghost-button`、`mini-action`。
- `MetricCard`：统一指标卡，替代页面内重复的指标块。
- `StatusPill`：统一状态标签，适合允许、拒绝、询问、隔离等状态。
- `DecisionPill`：统一安全决策标签，避免在页面里反复拼 `decision ${value}`。
- `RiskTag`：统一风险等级标签，避免各业务组件重复维护风险文案和颜色。
- `PanelCard`：统一基础业务卡片标题、副标题和默认边框风格。
- `CopyButton`：统一复制按钮和复制成功状态，避免重复写剪贴板兜底逻辑。
- `EmptyState`：统一空状态展示。
- `UiDataState`：统一异步数据的 loading、error、empty、ready 四态，禁止失败读取静默降级为空数据。
- `EvidenceCodeBlock`：统一证据、JSON、Markdown、工具输出等代码块展示。
- `SectionTitle`：统一卡片标题里的主标题和辅助说明，避免重复写 `Typography.Text` 小字样式。
- `UiFieldLabel`：统一控件和紧凑指标字段的次要标签，避免业务组件重复手写 `Typography.Text type="secondary"`。

## 新增规则

- 出现 2 次以上的基础 UI，放到这里。
- 业务强相关组件不放这里，继续留在对应页面附近。
- 组件只暴露必要属性，样式通过 Token 和已有全局类控制。
- 异步数据组件必须明确传入四态之一；`error` 不得复用 `empty`，成功读取的空集合才使用 `empty`。
- 新增基础组件应先作为新功能入口使用，不要一次性替换所有旧页面。
