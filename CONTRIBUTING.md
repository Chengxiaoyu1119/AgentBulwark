# 贡献指南

感谢你对智安哨（agent-security-supervisor）的关注！欢迎以任何形式参与贡献。

## 行为准则

- 保持专业和友善，尊重所有参与者。
- 讨论聚焦技术与事实，不做人身攻击。
- 安全研究类贡献必须基于受控实验环境，不针对真实外部系统。

## 如何参与

| 类型 | 方式 |
|---|---|
| 报告缺陷 | 提交 Issue，附复现步骤与环境信息 |
| 安全风险样例 | 提交新攻击面样本或防御策略（需附攻防对照数据） |
| 功能开发 | 先开 Issue 讨论，确认方案后提交 Pull Request |
| 文档改进 | 直接提交 Pull Request |
| 翻译 | 补充或修正中英文文档 |

## 开发环境搭建

前置要求：Node.js >= 22.0，Python >= 3.10。

```bash
# 克隆仓库
git clone <repo-url>
cd agent-security-supervisor

# 安装依赖
npm --prefix apps/console install
python -m pip install -r apps/api/requirements-dev.txt
```

## 提交前检查

提交 Pull Request 前必须通过全量验证：

```bash
npm run verify
```

该命令包含：前端 Lint、前端测试、后端 Lint（ruff）、后端类型检查（mypy）、语法编译检查、架构治理检查、后端单元测试、前端构建。

单独运行某项检查：

| 检查 | 命令 |
|---|---|
| 后端测试 | `npm run api:test` |
| 后端 Lint | `npm run api:lint` |
| 后端类型检查 | `npm run api:typecheck` |
| 架构治理 | `npm run api:architecture` |
| 前端 Lint | `npm run console:lint` |
| 前端测试 | `npm run console:test` |

## 代码结构约定

后端包根目录只允许核心入口文件（`__init__.py`、`auth.py`、`main.py`、`paths.py`），业务代码按以下规则放置：

| 内容 | 位置 |
|---|---|
| 攻击研究、评测、治理、报告、运行时领域 | `apps/api/agent_supervisor/domains/<domain>/` |
| Agent 框架接入、模型适配、代理 | `apps/api/agent_supervisor/adapters/<type>/` |
| 数据与数据库访问 | `apps/api/agent_supervisor/storage/` |
| API 路由 | `apps/api/agent_supervisor/routers/` |
| Pydantic 模型 | `apps/api/agent_supervisor/schemas/` |

禁止重新引入根目录兼容包装模块；跨模块导入必须使用规范路径。修改后运行 `npm run api:architecture` 验证。

## 提交信息规范

采用 Conventional Commits，格式为 `emoji + type(scope): 简述`，简述使用中文且不超过 50 字符。

| 类型 | emoji | 用途 |
|---|---|---|
| feat | ✨ | 新功能 |
| fix | 🐛 | 缺陷修复 |
| docs | 📝 | 文档 |
| test | 🧪 | 测试 |
| refactor | ♻️ | 重构 |
| chore | 🔧 | 构建/工具 |

示例：`✨feat(governance): 新增工具契约规范化与敏感数据脱敏模块`

## Pull Request 流程

1. 从 `main` 拉取功能分支：`feat/<简述>` 或 `fix/<简述>`。
2. 完成开发并通过 `npm run verify`。
3. 提交 Pull Request，描述包含：改动内容、影响范围、验证方式。
4. 等待维护者评审，按评审意见迭代。
5. 通过后由维护者合并。

## 安全相关贡献的额外要求

- 新增攻击样本必须限定在沙箱工具边界内（见 README「安全边界」）。
- 新增防御策略需要附攻防对照评测数据（无防护复现、有防护拦截）。
- 不得提交真实系统的凭据、密钥或可识别的敏感数据。
- 审计与落库路径需保持脱敏行为不被绕过。

## 许可证

提交即表示你同意贡献内容以 [Apache License 2.0](./LICENSE) 授权。
