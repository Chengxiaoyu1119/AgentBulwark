# 前端设计系统规则

这个目录是页面样式的源头，不再让页面组件随手写颜色、字号和阴影。

## 目录职责

- `tokens.css`：统一设计变量，包含颜色、间距、圆角、阴影和旧变量别名。
- `src/styles.css`：只作为正式运营样式入口，按顺序引入 `foundation.css` 和 `operations.css`。
- `src/视觉系统.css`：只作为共享组件样式入口，按顺序引入 `shared.css` 和 `settings.css`。
- `视觉系统/foundation.css`：文档根节点、滚动条和不属于业务域的全局原语。
- `视觉系统/operations.css`：从 `src/main.tsx` 实际可达的防护、事件、设置和应用壳样式。
- `视觉系统/experiments.css`：历史报告、攻击实验、场景库和竞赛界面的显式入口；它不得被正式入口引入。
- `视觉系统/settings-experiments.css`、`agent.css`、`surface.css`：只由 `experiments.css` 引入的历史领域样式。
- 页面 CSS 只能消费 Token，不应继续新增大量硬编码颜色。
- Token 分为基础尺度、语义状态和组件几何三层；组件几何（列表高度、输入宽度、内容最大宽度等）也必须从 Token 读取，避免“看起来只是一个 px”逐渐形成第二套设计系统。
- 组件样式优先写成可复用类，不在页面里重复手写按钮、指标卡、状态标签。

## 新代码放置规则

按“谁拥有变化”决定目录，而不是按页面当下的视觉位置建目录：

- `src/components/ui/`：跨两个以上功能域复用的基础交互或布局组件；必须导出类型，并为有状态行为补测试。
- `src/components/<domain>/`：只服务一个业务域的组合组件，例如 `audit`、`gateway`、`settings`、`agent`。网关的 OpenAI/MCP/Trace 组件统一归入 `gateway`，不能因为设置页暂时承载它们就放进 `settings`。
- `src/pages/`：只负责页面编排、数据加载边界和路由，不放通用按钮、卡片或布局实现。
- `src/design/视觉系统/`：共享 Token、基础布局和领域视觉规则；页面不得新增孤立 CSS 文件。
- `src/app/`：鉴权、导航、API 请求和页面级控制器，不放视觉组件。
- `src/app/operationalApi.ts`：正式控制台使用的运营 API；生产页面不得从兼容大桶 `src/api.ts` 引入实验接口。
- `src/app/runtimeEventConnection.ts`：实时事件连接、状态判断和有上限退避的唯一所有者；页面只通过 `useRuntimeEventRefresh` 订阅刷新，不复制重连循环。
- `src/app/themePreference.ts`：主题选择的唯一所有者，优先读取操作员选择、再读取系统偏好；页面不自行读写 localStorage。

新增文件前先回答：

1. 这个行为是否在两个功能域出现？是则进入 `components/ui`。
2. 它是否依赖某个业务域的数据契约？是则进入对应的 `components/<domain>`。
3. 它是否只是组合已有组件？留在 `pages`，不要再创建基础组件。

`npm run ui:audit` 会检查顶层目录、组件目录、Token 使用、基础 Ant Design 组件封装和文件预算；共享布局层还要求使用 Token，避免新的硬编码间距扩散。治理脚本会从 `src/main.tsx` 计算生产依赖闭包，阻止运营选择器泄漏到实验文件，也阻止实验选择器进入正式样式。生产闭包只允许请求层和统一连接器拥有 `subscribeRuntimeEvents`，防止页面重新复制无限重连逻辑。
同一依赖闭包还会阻止 `attackLabApi`、`reportEvaluationApi`、历史 fallback 和兼容 API 大桶进入运营构建入口。
治理脚本同时校验正式 CSS 引用的每一个 `--zh-*` Token 都在 `tokens.css` 中有定义，避免拼写错误在浏览器中静默丢失样式。

## 样式所有权规则

1. 正式页面新增的选择器放入 `operations.css`，共享 UI 组件放入 `shared.css`。
2. 报告、红队、场景和比赛资产放入 `experiments.css` 或它显式引入的领域文件。
3. 历史页面必须自己引入 `experiments.css`，不得让正式 `main.tsx` 为它们承担 CSS 体积。
4. 不通过提高行数预算规避拆分；超过门禁时先确认选择器属于哪个变化边界。

## 运行数据边界

- `src/fallback/` 只保留空的离线状态，用于告诉用户后端连接已中断。
- 攻击面、场景、策略和模型状态必须来自实时 API；请求失败时显示错误，不使用本地样本补位。
- 治理门禁会拒绝新的 fallback 目录层级和历史样本导出，避免将 Demo 再次包进正式前端。

## Token 分层

- Primitive：原始值，例如 `--color-teal-500`。
- Semantic：按用途命名，例如 `--color-brand`。
- Legacy alias：兼容旧页面，例如 `--teal`、`--bg`。

## 后续改造规则

- 同一种颜色出现 2 次以上，收敛成 Token。
- 新增硬编码颜色一律失败；原始色值只能在 `tokens.css` 声明，组件和领域 CSS 必须消费语义 Token。
- 正式样式的间距、字号和圆角字面量预算为 0；所有固定值必须先在 `tokens.css` 定义，再由正式 CSS 消费。
- 同一种 UI 出现 2 次以上，收敛到 `src/components/ui`。
- 新页面禁止新建孤立样式文件，优先复用现有 Token 和组件。
- 新增样式后必须运行 `npm run ui:audit`，确认文件行数、入口引入和选择器所有权同时通过。
