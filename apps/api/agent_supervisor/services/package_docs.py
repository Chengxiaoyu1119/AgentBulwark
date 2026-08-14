from __future__ import annotations

from typing import Any

from apps.api.agent_supervisor.paths import ROOT_DOCS_DIR


def _adapter_schema() -> dict[str, Any]:
    return {
        "name": "OpenClaw/通用智能体工具调用事件适配结构",
        "request": {
            "conversation_id": "string",
            "agent_id": "string",
            "agent_role": "planner | executor | target-agent | tool",
            "source_app": "OpenClaw | LangChain | AutoGen | custom-agent",
            "model_input": "string",
            "model_output": "string",
            "tool_call": {
                "tool": "file.read | mail.send | api.call | code.run | memory.read | memory.write | env.read",
                "arguments": "object",
                "risk_hint": "string",
            },
            "context_sources": ["system", "user", "web", "tool", "memory"],
            "guard_enabled": "boolean",
            "execute_in_sandbox": "boolean",
        },
        "response": {
            "run_id": "string",
            "audit_id": "string",
            "persisted": "boolean",
            "decision": "允许 | 拒绝 | 询问 | 隔离",
            "risk_level": "low | medium | high | critical",
            "risk_score": "0-100 integer",
            "risk_factors": ["string"],
            "anomaly_score": "0-100 integer",
            "anomaly_signals": ["string"],
            "policy_id": "string",
            "reason": "string",
            "recommendation": "string",
            "execution_mode": "string",
            "surface_id": "string",
            "risk_evidence": "object",
        },
    }


def _submission_readme(package: dict[str, Any]) -> str:
    summary = package["summary"]
    return "\n".join(
        [
            "# 智安哨初赛提交包",
            "",
            "项目名称：智安哨：面向大模型智能体工具调用链的运行时行为防火墙与评测系统",
            "",
            "## 项目定位",
            "",
            "本项目参加信息安全作品赛软件作品的安全检测方向，构建智能体工具执行前监督、风险处置、审计取证、攻击评测和报告导出闭环。",
            "",
            "## 当前提交包统计",
            "",
            f"- 攻击面覆盖：{summary['surface_count']} 类",
            f"- 攻击脚本数量：{summary['scenario_count']} 个",
            f"- 可复现攻击面：{summary['demo_ready_surface_count']} 类",
            f"- 实验记录：{summary['run_count']} 次",
            f"- 告警证据：{summary['alert_count']} 条",
            f"- 防护控制率：{summary['control_rate']}%",
            "",
            "## 目录说明",
            "",
            "- `01_作品目标材料`：对应研究目标的风险报告、样本集、脚本库、监督原型说明和实验评测结果。",
            "- `02_运行与答辩说明`：运行方式、接口清单、验收清单、源码结构和截图建议。",
            "- `manifest.json`：提交包文件清单。",
        ]
    )


def _run_guide() -> str:
    return "\n".join(
        [
            "# 运行说明",
            "",
            "## 1. 后端服务",
            "",
            "```powershell",
            "npm run api",
            "```",
            "",
            "默认地址：`http://127.0.0.1:8012`",
            "",
            "## 2. 前端页面",
            "",
            "```powershell",
            "npm run dev",
            "```",
            "",
            "默认地址：`http://127.0.0.1:5178`",
            "",
            "## 3. 批量实验",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs assess --run-compare",
            "```",
            "",
            "这个命令会批量运行全部内置攻击脚本，并分别生成无防护和有防护实验记录。",
            "",
            "## 4. 外部智能体事件评估",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs evaluate --input apps/api/sandbox/examples/agent-event.json",
            "```",
            "",
            "也可以把真实智能体的工具调用事件 POST 到 `/api/runtime/evaluate`。外部事件会写入审计日志和告警记录。",
            "",
            "批量评估真实智能体事件：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs evaluate --input apps/api/sandbox/examples/agent-events-batch.json",
            "```",
            "",
            "## 5. 导出报告证据",
            "",
            "提交包生成功能已停用。报告材料中心仍可查看、复制和下载单个 Markdown 材料。",
            "",
            "导出单个攻击面证据包：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs surface-pack --surface prompt-injection --output apps/api/sandbox/reports",
            "```",
            "",
            "一键导出全部攻击面证据包：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs surface-packs --output apps/api/sandbox/reports",
            "```",
            "",
            "导出全部攻击面评测单页 HTML：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs surface-briefs --output apps/api/sandbox/reports",
            "```",
            "",
            "导出项目成熟度与缺口路线图：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs roadmap --output apps/api/sandbox/reports",
            "```",
            "",
            "导出异常检测阈值校准报告：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs anomaly-calibration --output apps/api/sandbox/reports",
            "```",
            "",
            "导出连续正常业务任务流程误报评测：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs benign-workflows-write --output apps/api/sandbox/reports",
            "```",
            "",
            "导出赛前一键体检报告：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs readiness --write --output apps/api/sandbox/reports",
            "```",
            "",
            "导出人工复核队列与审批闭环报告：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs approvals --write --output apps/api/sandbox/reports",
            "```",
            "",
            "运行答辩复现实验并导出报告：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs demo-drill --run --output apps/api/sandbox/reports",
            "```",
            "",
            "导出 OpenClaw 源码级插件包：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs openclaw-plugin --output apps/api/sandbox/reports",
            "```",
            "",
            "生成并验收 OpenClaw 源码级插件包：",
            "",
            "```powershell",
            "node scripts/agent-supervisor-cli.mjs openclaw-plugin-validate --output apps/api/sandbox/reports",
            "```",
            "",
            "生成结果位于 `apps/api/sandbox/reports`。",
        ]
    )


def _api_inventory() -> str:
    return "\n".join(
        [
            "# 接口清单",
            "",
            "| 接口 | 方法 | 作用 |",
            "|---|---|---|",
            "| `/api/overview` | GET | 攻击面、脚本、模型、近期实验总览 |",
            "| `/api/scenarios` | GET | 获取攻击脚本库 |",
            "| `/api/policies` | GET | 获取防御策略 |",
            "| `/api/policies/{policy_id}` | PATCH | 启用或停用策略 |",
            "| `/api/run` | POST | 运行单个攻击脚本 |",
            "| `/api/compare` | POST | 单脚本无防护/有防护对比 |",
            "| `/api/batch_compare` | POST | 批量对比全部攻击脚本 |",
            "| `/api/runtime/evaluate` | POST | 强制开启防护的通用外部智能体工具调用事件评估，并写入审计证据 |",
            "| `/api/runtime/batch_evaluate` | POST | 强制开启防护的批量外部智能体事件评估，返回控制率并写入审计证据 |",
            "| `/api/audit_logs` | GET | 行为监督审计日志 |",
            "| `/api/alerts` | GET | 告警与阻断记录 |",
            "| `/api/approvals` | GET | 人工复核队列 JSON，可按待复核、已批准、已驳回筛选 |",
            "| `/api/approvals.md` | GET | 人工复核队列 Markdown 报告 |",
            "| `/api/approvals/write` | POST | 在本地生成人工复核队列 JSON 与 Markdown 报告 |",
            "| `/api/approvals/{review_id}/decision` | POST | 对复核单执行批准或驳回，并写入 review_hash 证据 |",
            "| `/api/demo_drill` | GET | 查看最近一次答辩复现实验 JSON 报告，不产生新审计记录 |",
            "| `/api/demo_drill.md` | GET | 查看最近一次答辩复现实验 Markdown 报告 |",
            "| `/api/demo_drill/run` | POST | 运行四步答辩复现流程，串联正常放行、人工复核和记忆隔离 |",
            "| `/api/demo_drill/write` | POST | 运行并在本地生成答辩复现实验 JSON 与 Markdown |",
            "| `/api/report` | GET | 按需证据导出数据；运行时防护不依赖该接口 |",
            "| `/api/attack_surfaces/evidence_packs` | GET | 全部攻击面的证据包索引 JSON，含完整度、控制率和缺口提示 |",
            "| `/api/attack_surfaces/evidence_packs.md` | GET | 全部攻击面证据包索引 Markdown |",
            "| `/api/attack_surfaces/evidence_packs/write` | POST | 一键生成全部攻击面的 JSON、Markdown 和总索引文件 |",
            "| `/api/attack_surfaces/{surface_id}/evidence_pack` | GET | 单个攻击面的样本、脚本、策略、工具和运行证据包 JSON |",
            "| `/api/attack_surfaces/{surface_id}/evidence_pack.md` | GET | 单个攻击面证据包 Markdown |",
            "| `/api/attack_surfaces/{surface_id}/evidence_pack/write` | POST | 在本地生成单个攻击面的 JSON 与 Markdown 证据文件 |",
            "| `/api/attack_surfaces/{surface_id}/briefing_sheet.html` | GET | 单个攻击面评测单页 HTML，可直接截图或打印 |",
            "| `/api/attack_surfaces/{surface_id}/briefing_sheet/write` | POST | 在本地生成单个攻击面评测单页 HTML |",
            "| `/api/attack_surfaces/briefing_sheets/write` | POST | 一键生成全部攻击面评测单页 HTML 和索引 |",
            "| `/api/project_roadmap` | GET | 项目成熟度、方向判断、缺口 Backlog 和下一轮建议 JSON |",
            "| `/api/project_roadmap.md` | GET | 项目成熟度与缺口路线图 Markdown |",
            "| `/api/project_roadmap/write` | POST | 在本地生成项目成熟度路线图 JSON 与 Markdown |",
            "| `/api/readiness` | GET | 赛前一键体检 JSON，检查攻击面、误报、OpenClaw 和报告证据状态 |",
            "| `/api/readiness.md` | GET | 赛前一键体检 Markdown 报告 |",
            "| `/api/readiness/write` | POST | 在本地生成赛前一键体检 JSON 与 Markdown 报告 |",
            "| `/api/evaluations/anomaly_calibration` | GET | 异常检测阈值校准 JSON，含推荐阈值、召回率、误报率和复核样本 |",
            "| `/api/evaluations/anomaly_calibration.md` | GET | 异常检测阈值校准 Markdown 报告 |",
            "| `/api/evaluations/anomaly_calibration/write` | POST | 在本地生成异常检测阈值校准 JSON 与 Markdown |",
            "| `/api/evaluations/benign_workflows` | GET | 连续正常业务任务流程误报评测 JSON，含流程级误报率和审计 hash 链 |",
            "| `/api/evaluations/benign_workflows.md` | GET | 连续正常业务任务流程误报评测 Markdown |",
            "| `/api/evaluations/benign_workflows/write` | POST | 在本地生成连续正常业务任务流程误报评测 JSON 与 Markdown |",
            "| `/api/evaluations/policy_ablation` | GET | 策略消融实验结果，展示关闭关键策略后的风险暴露和兜底控制 |",
            "| `/api/evaluations/policy_ablation.md` | GET | 策略消融实验 Markdown 证据 |",
            "| `/api/deliverables` | GET | 成果交付材料包内容 |",
            "| `/api/submission_package` | POST | 已停用，保留 410 响应用于兼容旧调用 |",
            "| `/api/submission_package/clean` | POST | 已停用，保留 410 响应用于兼容旧调用 |",
            "| `/api/integrations/openclaw/schema` | GET | OpenClaw/通用智能体适配结构 |",
            "| `/api/integrations/openclaw/bundle` | GET | OpenClaw 兼容接入包，包含事件契约、样例、验证命令和验收步骤 |",
            "| `/api/integrations/openclaw/adapter.py` | GET | 外部 Agent 工具调用钩子示例代码 |",
            "| `/api/integrations/openclaw/plugin_package` | GET | OpenClaw native plugin 包摘要，含 hook、决策映射和安装命令 |",
            "| `/api/integrations/openclaw/plugin_package.md` | GET | OpenClaw 源码级插件包 Markdown 说明 |",
            "| `/api/integrations/openclaw/plugin_package/write` | POST | 在本地生成可安装的 OpenClaw native plugin 目录和 zip |",
            "| `/api/integrations/openclaw/plugin_package/validation` | GET | OpenClaw 插件包静态验收结果，含文件、Hook 和 JS 语法检查 |",
            "| `/api/integrations/openclaw/plugin_package/validation.md` | GET | OpenClaw 插件包验收 Markdown 报告 |",
            "| `/api/integrations/openclaw/plugin_package/validation/write` | POST | 在本地生成 OpenClaw 插件包验收 JSON 与 Markdown |",
            "| `/api/integrations/openclaw/events` | POST | 外部智能体工具调用事件判定 |",
            "| `/api/integrations/openclaw/minimal_agent_demo` | POST | 页面一键运行最小外部 Agent 真实工具调度验证，并生成证据文件 |",
        ]
    )


def _acceptance_checklist(package: dict[str, Any]) -> str:
    lines = [
        "# 验收清单",
        "",
        "| 方向目标 | 状态 | 证据 |",
        "|---|---|---|",
    ]
    for item in package["checklist"]:
        lines.append(f"| {item['requirement']} | {item['status']} | {item['evidence']} |")
    return "\n".join(lines)


def _source_tree() -> str:
    return "\n".join(
        [
            "# 源码结构说明",
            "",
            "| 路径 | 作用 |",
            "|---|---|",
            "| `apps/api/agent_supervisor/data.py` | 攻击面、脚本和策略基础数据 |",
            "| `apps/api/agent_supervisor/agents.py` | 多 agent 攻击复现流程和批量评测 |",
            "| `apps/api/agent_supervisor/supervisor.py` | 行为监督策略判定 |",
            "| `apps/api/agent_supervisor/benign.py` | 正常业务任务单步样本和误报率评测 |",
            "| `apps/api/agent_supervisor/benign_workflows.py` | 连续正常业务任务流程误报评测和审计 hash 链 |",
            "| `apps/api/agent_supervisor/approvals.py` | 人工复核队列、批准/驳回和 review_hash 证据生成 |",
            "| `apps/api/agent_supervisor/calibration.py` | 异常检测阈值校准、召回率和误报率报告生成 |",
            "| `apps/api/agent_supervisor/demo_drill.py` | 答辩复现实验编排和证据报告生成 |",
            "| `apps/api/agent_supervisor/tools.py` | 邮件、文件、API、代码、记忆、环境模拟业务工具 |",
            "| `apps/api/agent_supervisor/services/package_service.py` | 成果材料包和提交包生成 |",
            "| `apps/api/agent_supervisor/events.py` | 外部智能体工具调用事件评估和审计落库 |",
            "| `apps/api/agent_supervisor/openclaw_adapter.py` | OpenClaw 兼容接口、源码级 native plugin 包生成 |",
            "| `apps/api/agent_supervisor/readiness.py` | 赛前一键体检、提交包完整性检查和 P0 补证项汇总 |",
            "| `apps/api/agent_supervisor/surface_pack.py` | 单个攻击面证据包生成、Markdown 导出和索引汇总 |",
            "| `apps/api/agent_supervisor/main.py` | FastAPI 后端接口 |",
            "| `apps/api/agent_supervisor/cli.py` | 命令行运行、导出和打包入口 |",
            "| `apps/console/src/App.tsx` | 前端主页面和各功能模块 |",
            "| `apps/console/src/api.ts` | 前端 API 调用封装 |",
            "| `apps/console/src/types.ts` | 前端 TypeScript 数据类型 |",
            "| `apps/console/src/design/tokens.css` | 前端设计 Token 源头，统一颜色、间距、圆角、阴影和旧变量别名 |",
            "| `apps/console/src/components/ui/` | 复用基础 UI 组件，当前包含按钮、指标卡、状态标签和安全决策标签 |",
            "| `apps/console/src/components/evidence/` | 运行证据展示组件，承载工具调用审计摘要和 hash 时间线 |",
            "| `apps/console/src/components/surface/` | 攻击面展示组件，承载攻击入口、保护资产、检测信号等属性块 |",
            "| `apps/console/src/components/scenarios/` | 攻击脚本库页面组件，承载脚本筛选、详情和工具调用参数展示 |",
            "| `apps/console/src/components/lab/` | 攻击复现实验室组件，承载脚本运行、无防护/有防护对比和批量结果展示 |",
            "| `apps/console/src/components/agent/` | 多 Agent 攻击链页面组件，承载协作时间线、工具调用证据和结果摘要 |",
            "| `apps/console/src/components/policy/` | 防御策略中心组件，承载策略影响矩阵、覆盖工具、攻击面和关闭影响说明 |",
            "| `apps/console/src/styles.css` | 前端页面样式 |",
            "| `scripts/frontend-governance-check.mjs` | 前端规范检查脚本，统计超大文件和样式硬编码问题 |",
            "| `scripts/project-self-review.mjs` | 多 Agent 自审报告脚本，汇总结构、截图、体检和提交包状态 |",
            "| `docs/` | 项目立项、方案、报告大纲和交付说明 |",
        ]
    )


def _threat_model_for_package() -> str:
    return "\n".join(
        [
            "# 攻击面威胁模型",
            "",
            "## 需要保护的资产",
            "",
            "- 系统提示词与安全规则",
            "- 沙箱文件、参赛队伍资料、提交物摘要与赛题种子",
            "- 长期记忆库",
            "- 本地沙箱 outbox",
            "- 本地受控环境模拟业务 API",
            "- 代码执行工具",
            "- 审计日志与告警证据",
            "",
            "## 信任边界",
            "",
            "| 边界 | 低信任侧 | 监督策略 |",
            "|---|---|---|",
            "| 用户输入到模型上下文 | 用户提示、网页正文、文档内容 | 输入来源标注、越狱过滤 |",
            "| 模型输出到工具调用 | 模型生成的工具名和参数 | 工具权限矩阵、参数审计 |",
            "| 工具返回到模型上下文 | 文件、API、环境、网页返回 | 低信任隔离、禁止覆盖授权 |",
            "| 智能体记忆写入 | 用户偏好、会话摘要、外部内容 | 写入审计、隔离区、回滚 |",
            "| 沙箱工具到本机环境 | 文件路径、命令、外发请求 | 路径限制、本地沙箱 outbox、本地受控环境 API |",
            "",
            "## 关键攻击面",
            "",
            "提示注入、模型越狱、数据泄露、滥用风险、工具调用劫持、记忆中毒、环境感知污染。",
            "",
            "## 必须保持的安全约束",
            "",
            "不攻击真实外部系统；不读取用户真实文件；不发送真实邮件；不执行破坏性命令；所有危险动作只在沙箱和假数据中复现。",
        ]
    )


def _real_integration_guide() -> str:
    doc_path = ROOT_DOCS_DIR / "真实接入与攻击面扩展说明.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 真实接入与攻击面扩展说明",
            "",
            "外部智能体可以在工具执行前 POST 到 `/api/runtime/evaluate`，平台返回监督决策并写入审计日志。",
        ]
    )


def _frontend_design_record() -> str:
    doc_path = ROOT_DOCS_DIR / "前端审美优化记录.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 前端审美优化记录",
            "",
            "本轮优化减少过度卡片、收敛颜色系统、增强字体层级，并保留克制的工作台风格。",
        ]
    )


def _frontend_governance_record() -> str:
    doc_path = ROOT_DOCS_DIR / "前端工程规范与设计Token治理记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 前端工程规范与设计 Token 治理记录",
            "",
            "本轮新增设计 Token、基础 UI 组件和前端规范检查命令，用于约束目录、组件复用和样式硬编码问题。",
        ]
    )


def _multi_agent_self_review_record() -> str:
    doc_path = ROOT_DOCS_DIR / "多Agent自审优化闭环报告-20260609.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 多 Agent 自审优化闭环报告",
            "",
            "本轮通过代码结构、页面审美和成果交付三个子代理并行审查，再由主线程完成低风险修复和自动自审报告生成。",
        ]
    )


def _page_agent_demo_record() -> str:
    doc_path = ROOT_DOCS_DIR / "页面一键真实Agent验证完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 页面一键真实 Agent 验证完善记录",
            "",
            "设置页新增一键运行真实 Agent 验证的按钮，可调用 `/api/integrations/openclaw/minimal_agent_demo` 并展示工具调度结果、控制率和审计 hash。",
        ]
    )


def _openclaw_plugin_record() -> str:
    doc_path = ROOT_DOCS_DIR / "OpenClaw源码级插件包完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# OpenClaw 源码级插件包完善记录",
            "",
            "系统新增 OpenClaw native plugin 包生成能力，通过 before_tool_call 在 OpenClaw 工具执行前调用智安哨监督器。",
        ]
    )


def _policy_ablation_record() -> str:
    doc_path = ROOT_DOCS_DIR / "策略消融实验完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 策略消融实验完善记录",
            "",
            "系统新增策略消融实验，可临时关闭关键防护层，验证控制率下降、风险暴露和兜底控制情况。",
        ]
    )


def _surface_pack_record() -> str:
    doc_path = ROOT_DOCS_DIR / "攻击面证据包完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 攻击面证据包完善记录",
            "",
            "系统新增单个攻击面证据包能力，把攻击样本、越狱用例、智能体脚本、预期策略、工具覆盖、运行证据和复现入口汇总到一个可导出的 JSON/Markdown 证据视图中。",
        ]
    )


def _roadmap_record() -> str:
    doc_path = ROOT_DOCS_DIR / "项目成熟度与缺口路线图完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 项目成熟度与缺口路线图完善记录",
            "",
            "系统新增项目路线图能力，用于自动判断当前项目方向、成熟度、未完成功能和下一轮优先级。",
        ]
    )


def _anomaly_calibration_record() -> str:
    doc_path = ROOT_DOCS_DIR / "异常检测阈值校准完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 异常检测阈值校准完善记录",
            "",
            "本轮新增异常检测阈值校准能力，用攻击样本和正常业务任务样本计算推荐阈值、攻击召回率、正常业务任务误报率和低分攻击复核结果。",
            "",
            "新增接口：`/api/evaluations/anomaly_calibration`、`/api/evaluations/anomaly_calibration.md`、`/api/evaluations/anomaly_calibration/write`。",
            "",
            "新增命令：`node scripts/agent-supervisor-cli.mjs anomaly-calibration --output apps/api/sandbox/reports`。",
        ]
    )


def _benign_expansion_record() -> str:
    doc_path = ROOT_DOCS_DIR / "正常业务任务样本扩充记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 正常业务任务样本扩充记录",
            "",
            "正常业务任务样本已扩充到 36 条，覆盖 7 类赛事任务和 9 种工具，误报率 0%，期望决策匹配率 100%。",
        ]
    )


def _benign_workflow_record() -> str:
    doc_path = ROOT_DOCS_DIR / "连续正常业务任务流程误报评测记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 连续正常业务任务流程误报评测记录",
            "",
            "系统新增连续正常业务任务流程误报评测，覆盖公开资料到内部周报、赛事复盘闭环、外部分享审批和沙箱统计脚本流程。",
            "",
            "当前结果：4 条流程、14 个工具步骤、误报率 0%、期望决策匹配率 100%、审计 hash 链全部有效。",
        ]
    )


def _readiness_record() -> str:
    doc_path = ROOT_DOCS_DIR / "赛前一键体检完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 赛前一键体检完善记录",
            "",
            "## 本轮新增",
            "",
            "1. 新增后端模块：`apps/api/agent_supervisor/readiness.py`。",
            "2. 新增接口：",
            "   - `GET /api/readiness`",
            "   - `GET /api/readiness.md`",
            "   - `POST /api/readiness/write`",
            "3. 新增 CLI：",
            "   - `node scripts/agent-supervisor-cli.mjs readiness --write --output apps/api/sandbox/reports`",
            "4. 提交包新增 `16_赛前一键体检报告.md`，并在运行说明目录归档 JSON 与 Markdown 证据。",
            "",
            "## 体检范围",
            "",
            "- 攻击面与脚本覆盖",
            "- 对抗样本、越狱用例和智能体攻击脚本",
            "- 行为监督器、策略和本地受控环境业务工具",
            "- 正常业务任务单步误报评测",
            "- 连续正常业务任务流程误报评测",
            "- 异常检测阈值校准",
            "- OpenClaw 插件静态、契约端到端和 runtime inspect 证据",
            "- 200条冻结集、四组基线与性能证据",
            "- 初赛提交包、manifest 和复现截图完整性",
            "",
            "## 当前证据状态",
            "",
            "- OpenClaw 插件已完成鉴权、去自标注、阻断/放行契约检查和真实 runtime inspect。",
            "- 200条内部冻结集已绑定SHA-256，并完成四组基线与2000次性能判定。",
        ]
    )


def _approval_review_record() -> str:
    doc_path = ROOT_DOCS_DIR / "人工复核队列与审批闭环完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 人工复核队列与审批闭环完善记录",
            "",
            "## 本轮新增",
            "",
            "1. 新增后端模块：`apps/api/agent_supervisor/approvals.py`。",
            "2. 新增数据库表：`approval_reviews`，保存复核单状态、操作人、备注和完整 payload。",
            "3. 新增接口：",
            "   - `GET /api/approvals`",
            "   - `GET /api/approvals.md`",
            "   - `POST /api/approvals/write`",
            "   - `POST /api/approvals/{review_id}/decision`",
            "4. 新增 CLI：`node scripts/agent-supervisor-cli.mjs approvals --write --output apps/api/sandbox/reports`。",
            "5. 审计页新增人工复核队列，可直接批准或驳回“询问”类工具调用。",
            "",
            "## 真实项目意义",
            "",
            "- “询问”不再只是一个静态决策，而是进入待处理队列。",
            "- 复核单关联原始 `audit_hash`，审批后生成 `review_hash`。",
            "- 答辩时可以复现外部智能体触发风险、监督器暂停、人工复核、证据导出四步闭环。",
        ]
    )


def _demo_drill_record() -> str:
    doc_path = ROOT_DOCS_DIR / "答辩复现闭环完善记录-20260608.md"
    if doc_path.exists():
        return doc_path.read_text(encoding="utf-8")
    return "\n".join(
        [
            "# 答辩复现闭环完善记录",
            "",
            "## 本轮新增",
            "",
            "1. 新增后端模块：`apps/api/agent_supervisor/demo_drill.py`。",
            "2. 新增接口：",
            "   - `GET /api/demo_drill`",
            "   - `GET /api/demo_drill.md`",
            "   - `POST /api/demo_drill/run`",
            "   - `POST /api/demo_drill/write`",
            "3. 新增 CLI：`node scripts/agent-supervisor-cli.mjs demo-drill --run --output apps/api/sandbox/reports`。",
            "4. 设置页新增“答辩复现”面板，展示四步运行记录、风险分、策略、audit_hash 和 review_hash。",
            "",
            "## 复现价值",
            "",
            "- 用一条固定流程展示正常放行、外发复核、批量导出审批和记忆隔离。",
            "- 评委不用手动构造 JSON，也能看到系统从攻击输入到证据导出的完整闭环。",
            "- 提交包新增 `18_答辩复现闭环报告.md`，增强现场可解释性。",
        ]
    )


def _screenshot_checklist() -> str:
    return "\n".join(
        [
            "# 复现截图清单",
            "",
            "建议初赛材料至少保留以下截图：",
            "",
            "1. 攻击面研究台：展示 7 类攻击面和主线闭环。",
            "2. 攻击脚本库：展示对抗样本、越狱用例和脚本步骤。",
            "3. 攻击复现实验室：展示无防护/有防护对比。",
            "4. 多 Agent 攻击链：展示规划、生成、执行、监督、评测流程。",
            "5. 行为监督记录：展示工具调用、代码执行、文件访问、API 调用审计。",
            "6. 告警与阻断：展示告警证据、策略命中和处置建议。",
            "7. 防御策略中心：展示允许、拒绝、询问、隔离策略配置。",
            "8. 按需证据：展示交付材料包和验收清单。",
            "9. 全量证据索引：展示 7 类攻击面的完整度、控制率和缺口状态。",
            "10. 攻击面评测单页：展示单个攻击面的攻击链路、监督命中、工具覆盖和验收闭环。",
            "11. 项目成熟度路线图：展示方向判断、成熟度、P0 缺口和下一轮计划。",
            "12. 异常检测校准：展示推荐阈值、攻击召回率、正常误报率和低分攻击复核。",
            "13. OpenClaw 源码级插件包：展示 before_tool_call 检查结果、插件输出路径和安装命令。",
            "14. 连续正常业务任务流程误报评测：展示流程通过率、步骤误报率、边界控制和审计 hash 链。",
            "15. 赛前一键体检：展示就绪分、P0 补证项、关键检查项和提交包状态。",
            "16. 人工复核队列：展示待复核、已批准、已驳回和 review_hash 证据。",
            "17. 答辩复现：展示正常放行、外发复核、批量导出审批和记忆隔离。",
            "18. 前端工程规范与 Token 治理：展示设计 Token、统一组件接入后的桌面和移动端页面状态。",
            "19. 决策标签统一组件：展示审计页、告警页和设置页中统一渲染的允许、拒绝、询问、隔离标签。",
            "",
            "已生成的核心截图会自动复制到提交包 `02_运行与答辩说明/复现截图` 目录；截图应尽量来自真实本地运行页面，而不是手工绘图。",
        ]
    )
