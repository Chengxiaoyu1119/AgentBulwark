# 变更日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式记录变更，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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
