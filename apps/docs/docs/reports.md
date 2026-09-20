---
id: reports
title: 证据与回执
---

# 证据与回执

AgentBulwark 把运行结果拆成三个相互关联的对象：Trace 记录请求链，执行回执记录实际工具结果，Hash/HMAC 证据用于离线核验。它们共同回答“发生了什么、为什么处置、实际执行了什么”。

## 证据组成

| 对象 | 记录内容 | 核验重点 |
| --- | --- | --- |
| Trace | 请求、Provider、模型响应、Tool Call、决策和状态 | 请求链标识在各阶段保持一致 |
| 执行回执 | 工具、标准化参数、目标、开始/结束时间和结果状态 | 只有通过对应执行边界的行动才有真实回执 |
| Hash/HMAC | 请求/响应 Hash、参数 Hash、策略版本和链式签名 | 内容或顺序被修改时核验失败 |

## 证据状态

| 状态 | 含义 |
| --- | --- |
| `proved` | 客户端通过 MCP `_meta` 携带一次性关联凭证，网关完成来源验证 |
| `correlated` | 根据 Agent、Session、工具、参数和时间窗口完成关联，但没有密码学来源证明 |
| `unknown` | 无法可靠关联来源；高风险工具默认阻断或进入审批 |

证据状态描述的是来源证明程度，不等同于策略决策。一个请求可以被 `DENY`，同时仍然留下可核验的阻断 Trace。

## 控制台与 API

事件页从 Trace 进入详情，按以下顺序展示：输入检查、Provider 路由、模型响应、Tool Call、策略命中、审批记录、执行回执和 Hash/证据。

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| Trace 列表 | GET | `/api/gateway/traces` |
| Trace 详情 | GET | `/api/gateway/traces/{request_id}` |
| 执行回执列表 | GET | `/api/runtime/executions` |
| 执行回执详情 | GET | `/api/runtime/executions/{audit_id}` |
| 提交外部执行回执 | POST | `/api/runtime/executions/{audit_id}/complete` |
| 证据详情 | GET | `/api/evidence/{id}` |
| 证据核验 | POST | `/api/evidence/{id}/verify` |

## 可验证与不可推断

可以验证：

- Provider 是否被调用以及请求/响应 Hash 是否一致；
- Tool Call 是否命中登记、Schema、目标和策略；
- 审批是否绑定当前参数、策略版本、Agent、Session 和有效期；
- 托管网关或 MCP 是否产生执行回执，以及回执是否属于同一请求链；
- 重启后证据链是否仍能离线核验。

不能从一条 Trace 推断：

- 未接入的客户端内部是否展示过某个提示；
- `correlated` 来源是否具备 `proved` 的密码学保证；
- 没有真实调用的外部 Provider 或 MCP 是否“已经通过”。

这些边界让报告只呈现实际观测结果，不用固定样本或静态演示数据代替运行证据。
