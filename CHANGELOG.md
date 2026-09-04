# 变更日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式记录变更，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增

- MCP 生产交互：在正式防护页增加独立 MCP 工具页签，默认使用 `2026-07-28` 的 `server/discover` 并可切换 `2025-06-18` `initialize`；接通工具、Resource、Prompt、`input_required` 操作员恢复轮次和 `subscriptions/listen` 实时订阅，支持过滤、显式停止和最近 100 条通知证据，并按服务端有效角色禁用不可执行动作。
- 安全事件处置中心：在正式产品导航中整合风险事件、人工复核和执行审计，支持从“询问”调用链直接定位复核单，并实时展示批准、原始 Agent 领取和完成回执状态。
- 前端工程治理：新增共享 `UiStack` 布局和 `UiConfirmButton` 高影响操作组件，补全间距、字号、层级与动效 Token，并通过治理门禁禁止共享样式重新引入硬编码间距、渐变、`transition: all` 和任意层级值。
- 样式所有权治理：将单一的 `styles.css` 拆分为全局基础、正式运营和历史实验三层，正式构建不再携带报告、场景、攻击实验和竞赛界面 CSS，并新增行数与跨域选择器门禁。
- 运行数据去 Demo 化：删除前端内置的攻击面、场景、策略和模拟模型目录，离线时只返回空状态，并通过治理门禁防止历史样本重新进入运行包。
- 高影响操作确认：人工批准/驳回、Agent 权限删除、工具映射删除、记忆回滚和移除统一增加明确的二次确认。
- 实时事件可靠性：统一请求流与安全事件页的 SSE 生命周期，连接成功以真实响应握手为准，401/403/404 停止无效重试，瞬时故障采用最长 15 秒指数退避，并在页面显示重连原因。
- 治理门禁校正：硬编码颜色只允许在 Token 定义文件出现，修正内联样式每文件预算未实际生效的问题，并禁止正式页面复制实时事件订阅循环。
- 正式视觉 Token 化：将生产入口可达 CSS 中 127 处间距、字号和圆角字面量全部收敛到统一 Token，治理预算由 127 降至 0。
- 服务端执行证据修正：执行前意图会先写入审计表并建立执行占用，但不进入已完成运行统计或提前发布完成事件；意图落库失败时冻结占用并阻止副作用。
- 性能门禁隔离：新增 `npm run api:perf` 独立运行 MCP 监督微基准，避免覆盖率插桩污染 p95 验收结果。
- 执行状态核查：安全事件页新增不确定副作用清单，`unknown` 执行以红色事故状态展示并明确禁止自动重试；分析员与管理员可按审计、Agent、会话和工具 Hash 追踪。
- MCP 双时代传输：新增 `2026-07-28` 逐请求元数据与镜像头校验、`server/discover`、有界 `subscriptions/listen` SSE、订阅会话租约和 `2025-06-18` stdio 初始化桥；旧版主动请求不再被误写成最新版路线。
- MCP MRTR 与请求级流：旧版 stdio 的 `sampling/createMessage`、`elicitation/create`、`roots/list` 会转换为带 HMAC/TTL/单次消费绑定的 `input_required`；现代工具调用通过请求级 SSE 传递进度、八级标准日志与最终回执，恢复轮次会把通知重新绑定到当前请求流。
- OpenAI真实安全流：`/v1/chat/completions` 的 `stream=true` 改为读取Provider SSE并在尾部安全窗口后增量放行文本；分片Tool Call、reasoning和扩展字段在完整监督前保持隐藏，跨Chunk风险、Provider中断、终态不一致和客户端取消均保留明确终态证据。补充`stream_options`契约、usage终块、Provider调用事实和浏览器取消资源释放验证；控制台增加实时内容、Chunk/字符计数和停止接收操作。
- 生产证明闭环：短生命周期 production 证明新增人工审批的批准、原始 Agent 领取、完成回执和驳回证据，兼容 Windows PowerShell 5.1，并以精简终端摘要关联完整 readiness 报告；新增 `npm run proof:production:full` 作为全量证据入口。
- 部署交付验收：新增 Compose 静态门禁与真实容器冷启动验收，覆盖必填密钥失败关闭、回环端口、非 root 运行、健康检查、操作员/管理员/Agent 三类身份、服务端工具执行，以及容器替换后的审计、策略和 Agent 工作区恢复；按 Agent 隔离的运营副作用统一迁入 `/data` 持久卷。

## [0.2.0] - 2026-08-15

### 新增

- Docker 一键部署：`Dockerfile`（多阶段构建，单容器同时托管 API 与前端）、`docker-compose.yml`（数据卷持久化、健康检查、fail-closed 密钥强校验）、`.dockerignore`。
- 规则通道中文越狱关键词增强：覆盖 B-01 标注集 8 类攻击话术，留出集召回率 7.8% → 54.5%，零误报。
- 工具描述投毒扫描（`tool-description-scan`，对齐 OWASP ASI04）：识别指令覆写 / 数据外传通道 / 凭证文件访问，隔离级工具在 MCP Gateway 聚合目录时即被阻断。
- PromptGuard 2（LlamaFirewall）对比评测脚本与报告：中文攻击场景下基线召回率仅 23.4%（oracle 上界 35.1%）、延迟 712ms，确认不可用。
- README（中英）新增 OWASP Agentic Top 10 覆盖度表格：已覆盖 3/10、部分覆盖 7/10、风险触及率 100%。
- 英文版 README（`README_EN.md`）补齐防御策略矩阵与 OWASP 覆盖度，与中文版完全对齐。
- 测试隔离基础设施：`apps/api/tests/conftest.py` 将运行时数据重定向至系统临时目录，消除文件系统过滤驱动导致的回归挂起。

### 变更

- 双通道检测架构：规则通道先行（<5ms），语义通道（本地 BERT）缺失时自动降级，零报错跳过。

### 性能

- 策略配置读取引入 mtime+TTL 缓存：规则通道延迟 p95 15ms → 3.08ms（预算 5ms）。
- 策略设置 stat 节流（`_load_policy_settings` TTL + 单次 os.stat）：规则通道 p95 3.08ms → 0.209ms（优于预算 24 倍），p99 9.5ms → 1.9ms；进程内策略更新仍即时生效。
- MCP Gateway 监督开销 p95 = 1.41ms（验收线 10ms）。

### 测试

- 全量回归：后端 245 项 + 前端 39 项全部通过（第 6 周全面测试报告）。

## [0.1.0] - 2026-08-14

首个开源化版本。

### 新增

- MCP Gateway（`mcp_gateway` 模块）：MCP 协议代理，`tools/call` 强制拦截，多上游路由，决策审计落库，通知缓冲转发。
- 中文越狱检测数据集 1547 条（500 攻击标注 + 变体生成）。
- OpenClaw 插件强制阻断：`before_tool_call` 钩子对"拒绝/隔离"决策 100% 阻断，10 项专项测试。
- 通用 HTTP API 明确标注"建议式"接入边界（`/api/runtime/evaluate`）。
- 真实模型盲测脚本（DeepSeek + 智谱，30 攻击 + 30 正常 × 3 次重复）。

### 变更

- 开源化重构：归档 `apps/www`、`apps/docs`、比赛材料与历史报告至 `archive/`；删除 51 个兼容包装模块，导入全部指向领域模块。
- 重写 README 为开源导向（快速启动 / API 参考 / 架构说明）。

### 合规

- 添加 Apache 2.0 LICENSE、CONTRIBUTING.md。

## 项目初始阶段（参赛版本）

V1-01 ~ V1-06：核心监督引擎（supervisor）、工具契约规范化、敏感数据脱敏、攻防演练场景、控制台与官网。历史提交见 git log。
