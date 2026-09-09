---
id: policies
title: 防护策略
---

# 防护策略

策略是 AgentBulwark 的运行时决策层。它同时读取请求身份、会话、上下文来源、工具注册、Schema、参数和目标，在工具产生副作用前给出明确状态。

## 四种决策

| 决策 | 运行含义 | 控制台状态 |
| --- | --- | --- |
| ALLOW | 通过当前检查，可继续请求或工具调用 | 已允许 |
| DENY | 阻断请求或工具调用，不访问下一执行层 | 已阻断 |
| ASK | 创建待处理审批，等待操作员决定 | 需要审批 |
| ISOLATE | 放入受限或低信任路径，不直接回灌可信上下文 | 已隔离 |

同一行动命中多条策略时按以下顺序收敛：

```text
DENY > ISOLATE > ASK > ALLOW
```

## 当前策略边界

| 策略 ID | 保护对象 | 默认决策 |
| --- | --- | --- |
| `path-boundary` | 文件路径、路径穿越和敏感目录 | DENY |
| `dangerous-command` | 删除、格式化、下载和提权等命令 | DENY |
| `sensitive-api` | 未登记的高敏 API 目标 | DENY |
| `external-api-allowlist` | Agent 外部 API 主机白名单 | ASK |
| `memory-write` | 含权限覆盖或隐藏动作的记忆写入 | ISOLATE |
| `jailbreak-filter` | 忽略系统规则的提示输入 | DENY |
| `model-output-filter` | 高风险模型输出和敏感内容复述 | DENY |
| `tool-description-scan` | MCP 工具描述中的可疑指令 | ISOLATE |
| `tool-return-trust` | 工具返回内容的低信任状态 | ISOLATE |
| `bulk-action-review` | 批量外发、批量导出和异常用途 | ASK |
| `anomaly-detection` | 工具、参数和上下文组合异常 | ASK |

策略基线位于 `apps/api/agent_supervisor/config/policies.json`，运行时覆盖和策略版本保存在后端运行目录。

## 审批绑定

ASK 行动生成审批记录。批准前后都会校验：

- Agent 身份和 Session；
- 工具名称、目标和规范化参数 Hash；
- 当前策略版本；
- 有效期与一次性 Nonce；
- Provider 路由和请求链标识。

绑定字段发生变化、审批过期或重复消费时，审批失效且不会触发上游工具执行。

## 管理接口

```text
GET   /api/policies
PATCH /api/policies/{policy_id}
GET   /api/policy_config
PATCH /api/policy_settings
GET   /api/policies/versions
GET   /api/approvals
POST  /api/approvals/{review_id}/approve
POST  /api/approvals/{review_id}/deny
```

策略修改需要后端鉴权上下文中的管理权限。任何策略文件、数据库或证据读取错误都保持拒绝，不静默放行。
