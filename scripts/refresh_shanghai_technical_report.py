from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    from docx import Document
except ModuleNotFoundError as exc:  # pragma: no cover - depends on the active environment
    if exc.name == "docx":
        raise SystemExit(
            "材料刷新需要 python-docx。请先运行：python -m pip install python-docx"
        ) from exc
    raise

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = (
    ROOT
    / "docs"
    / "上海信息安全"
    / "参赛材料草稿"
    / "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关-技术报告-待提交.docx"
)
REPORT_DIR = ROOT / "apps" / "api" / "sandbox" / "reports"
SHANGHAI = ZoneInfo("Asia/Shanghai")
COMPETITION_NOTICE_URL = "https://security.zone.ci/secarticles/wx/564281.html"
COMPETITION_OFFICIAL_SITE_URL = "https://shwas.dhu.edu.cn/"
COMPETITION_OFFICIAL_RULES_URL = "https://shwas.dhu.edu.cn/bszc/main.psp"
COMPETITION_OFFICIAL_REGISTRATION_URL = "https://shwas.dhu.edu.cn/bjds_23247/list.psp"
COMPETITION_SUBMISSION_DEADLINE = datetime(2026, 8, 18, tzinfo=SHANGHAI)


def load_json(name: str) -> dict:
    path = REPORT_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def local_time(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(SHANGHAI).strftime("%Y-%m-%d %H:%M")


def set_text(paragraph, text: str) -> None:
    if paragraph.runs:
        paragraph.runs[0].text = text
        for run in paragraph.runs[1:]:
            run.text = ""
    else:
        paragraph.add_run(text)


def update_starting_with(document: Document, prefix: str, text: str) -> None:
    for paragraph in document.paragraphs:
        if paragraph.text.startswith(prefix):
            set_text(paragraph, text)
            return
    raise RuntimeError(f"技术报告缺少待更新段落：{prefix}")


def update_one_of(document: Document, prefixes: tuple[str, ...], text: str) -> None:
    for paragraph in document.paragraphs:
        if any(paragraph.text.startswith(prefix) for prefix in prefixes):
            set_text(paragraph, text)
            return
    raise RuntimeError(f"技术报告缺少待更新段落：{prefixes}")


def bool_text(value: object) -> str:
    return str(bool(value)).lower()


def write_material_status(
    *,
    report_path: Path,
    readiness: dict,
    gateway_run: dict,
    mcp_probe: dict,
    real_model: dict,
    pending: dict,
    refreshed_at: datetime,
) -> None:
    """Keep the ignored draft status file aligned with the refreshed report.

    This is an evidence refresh only: it deliberately leaves the three
    formal-submission readiness flags false until the official templates,
    team profile, and signed declaration are supplied.
    """

    gateway_summary = gateway_run["summary"]
    mcp_summary = mcp_probe["summary"]
    model_summary = real_model["summary"]
    pending_summary = pending["summary"]
    deadline_status = "passed" if refreshed_at >= COMPETITION_SUBMISSION_DEADLINE else "open"
    status = {
        "status": "draft_pending_official_templates_and_profile",
        "refresh_kind": "evidence-only",
        "refreshed_at": refreshed_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "evidence_generated_at": readiness["generated_at"],
        "technical_report_ready": False,
        "registration_form_ready": False,
        "originality_declaration_ready": False,
        "official_templates_present": False,
        "event_deadline": {
            "submission_deadline": COMPETITION_SUBMISSION_DEADLINE.isoformat(),
            "submission_deadline_label": "2026-08-17 24:00",
            "status_as_of": refreshed_at.date().isoformat(),
            "status": deadline_status,
            "late_submission_confirmation_required": deadline_status == "passed",
            "notice_source": COMPETITION_NOTICE_URL,
            "official_site": COMPETITION_OFFICIAL_SITE_URL,
            "official_rules_page": COMPETITION_OFFICIAL_RULES_URL,
            "official_registration_page": COMPETITION_OFFICIAL_REGISTRATION_URL,
            "official_qq_group": "515383635",
            "contact_email": "shwas@qq.com",
            "contact_phone": "021-67792285",
            "template_location": "official QQ group files per public notice",
            "public_template_search_status": "2026_current_templates_not_found; historical_pages_checked",
            "public_template_search_checked_at": refreshed_at.date().isoformat(),
            "official_registration_page_attachment_status": "no_2026_attachments_in_public_html",
        },
        "report_evidence_snapshot": {
            "readiness_score": readiness["readiness_score"],
            "production_ready": readiness["production_ready"],
            "gateway_ready": readiness["gateway_ready"],
            "completion_claim_allowed": readiness["completion_claim_allowed"],
            "gateway_case_count": gateway_summary["case_count"],
            "gateway_contract_pass_rate": gateway_summary["gateway_contract_pass_rate"],
            "mcp_evidence_verdict": mcp_summary["evidence_verdict"],
            "real_model_case_count": model_summary["case_count"],
            "real_model_evidence_verdict": model_summary["evidence_verdict"],
            "operational_pending_count": pending_summary["pending_count"],
        },
        "paths": {
            "technical_report": str(report_path.resolve()),
            "registration_form": str(
                report_path.parent
                / "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关-报名表-待补个人信息.xlsx"
            ),
            "originality_declaration": str(
                report_path.parent
                / "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关-原创性声明-待签署.docx"
            ),
        },
        "next_required_inputs": [
            "先向组委会确认作品赛逾期补交是否受理（公开通知截止 2026-08-17 24:00）",
            "官方技术报告模板 DOCX 与历史技术报告源文件",
            "官方报名表 XLSX",
            "官方原创性声明 DOCX 或 PDF",
            "学校、指导教师、成员和联系方式",
            "人工复核确认与原创性签署",
        ],
    }
    (report_path.parent / "参赛材料生成状态.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="按当前实时证据刷新上海信息安全作品技术报告草稿")
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    args = parser.parse_args()

    report_path = Path(args.report)
    readiness = load_json("AI Agent安全网关就绪检查.json")
    gateway_probe = load_json("current-gateway-probe-8034.json")
    gateway_run = load_json("current-gateway-agent-run-8034.json")
    mcp_probe = load_json("current-mcp-probe-8034.json")
    real_model = load_json("真实模型工具调用盲测报告.json")
    pending = load_json("operational-pending-approvals.json")

    readiness_summary = readiness["summary"]
    gateway_summary = gateway_run["summary"]
    mcp_summary = mcp_probe["summary"]
    model_summary = real_model["summary"]
    pending_reviews = pending.get("reviews", [])
    pending_tools = Counter(
        str(item.get("standard_capability") or item.get("tool") or "unknown")
        for item in pending_reviews
    )
    context_summary = mcp_probe["operator_evidence"]["context"]["summary"]

    readiness_at = local_time(readiness["generated_at"])
    probe_at = local_time(gateway_probe["generated_at"])
    gateway_at = local_time(gateway_run["generated_at"])
    mcp_at = local_time(mcp_probe["generated_at"])
    model_at = local_time(real_model["generated_at"])
    refreshed_at = datetime.now(SHANGHAI)
    current_date_label = f"{refreshed_at.year} 年 {refreshed_at.month} 月 {refreshed_at.day} 日"
    deadline_passed = refreshed_at >= COMPETITION_SUBMISSION_DEADLINE
    deadline_note = (
        "公开通知所列作品赛截止时间已过，须先确认逾期补交是否受理"
        if deadline_passed
        else "公开通知所列作品赛截止时间尚未到，仍须按通知要求准备提交"
    )
    score = readiness["readiness_score"]
    material_ready = readiness_summary["submission_material_ready_count"]
    material_required = readiness_summary["submission_material_required_count"]
    operational_pending = readiness_summary["operational_pending_approval_count"]
    provider_routes = gateway_summary["remote_hostname_provider_route_count"]
    verified_routes = gateway_summary["network_verified_external_provider_evidence_count"]
    public_ip_proof = gateway_summary["public_ip_provider_evidence_count"]
    strict_external_proof = gateway_summary["external_provider_evidence_count"]

    document = Document(report_path)
    # Keep the architecture paragraph separate from the evidence paragraph.
    # Both begin with MCP in the draft, so matching the generic word "MCP"
    # would overwrite the architecture description on a second refresh.
    if len(document.paragraphs) > 13:
        set_text(
            document.paragraphs[13],
            "MCP Gateway 为每个 Agent + Session 建立隔离的 stdio 上游进程，限制消息大小、待处理响应数、CPU、内存、进程数和文件大小；工具目录、resources、templates 和 prompts 经上下文白名单及投毒扫描后才向模型投影，operator 路由证据与模型可见清单分离。",
        )
    update_starting_with(
        document,
        "参赛材料技术报告草稿",
        f"参赛材料技术报告草稿｜待提交（当前证据快照：{readiness_at}，Asia/Shanghai）",
    )
    update_starting_with(
        document,
        "本文件为技术报告草稿",
        "本文件为技术报告草稿。官方技术报告模板、报名表模板和队伍资料尚未进入工作区，当前不具备正式提交件状态。本文只引用当前源码、当前策略快照和实时证据快照；个人信息与原创性签署字段保留给队伍填写。",
    )
    update_starting_with(
        document,
        "智安哨是面向 LLM Agent",
        "智安哨是面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关。系统把安全边界从最终文本扩展到 Agent 身份、模型选择、工具定义、工具参数、MCP 资源/模板/提示、Provider 请求与响应以及副作用执行。Provider 前检查输入，Provider 后检查文本、reasoning 和 tool call；Managed/MCP 路径在执行前阻断或托管执行，并用服务端回执、Hash/HMAC 审计绑定 Agent、Session、Provider Call 和执行结果。当前实时证据显示 HTTP 网关契约 4/4 通过、MCP operator 证据完整、智谱严格 real-api 评测 6/6 通过；正式提交仍需官方模板、队伍资料和签署件。",
    )
    update_starting_with(
        document,
        "真实模型行为评测",
        f"真实模型行为评测（不经过 HTTP 网关，生成于 {model_at}）：{model_summary['case_count']} 条，智谱 real-api 覆盖 {model_summary['real_api_coverage_rate']}%；攻击样本 {model_summary['attack_case_count']}/{model_summary['attack_case_count']} 受控，正常任务完成 {model_summary['benign_task_completed_count']}/{model_summary['benign_case_count']}，正常误报率 {model_summary['benign_false_positive_rate']}%，预期控制匹配率 {model_summary['expected_control_match_rate']}%，回执完整率 {model_summary['receipt_complete_count']}/{model_summary['case_count']}，证据 verdict={model_summary['evidence_verdict']}。该结果证明模型适配器与本地沙箱因果链，不替代网关 HTTP 证据。",
    )
    update_starting_with(
        document,
        "HTTP 网关",
        f"HTTP 网关（当前进程指纹绑定，生成于 {gateway_at}）：{gateway_summary['gateway_contract_passed_count']}/{gateway_summary['case_count']} 契约通过；{gateway_summary['attack_blocked_count']} 个攻击请求受控、{gateway_summary['allowed_count']} 个正常请求放行；Provider 产生的 {gateway_summary['provider_tool_call_count']} 个 tool call 均未泄漏到响应；托管执行 {gateway_summary['managed_execution_count']} 次，服务端观察回执 {gateway_summary['server_observed_receipt_count']} 条，证据 verdict={gateway_summary['evidence_verdict']}。",
    )
    update_one_of(
        document,
        ("MCP（", "MCP：initialize"),
        f"MCP（生成于 {mcp_at}）：initialize、tools/list、tools/call 和 operator evidence 均通过；可见工具 {mcp_summary['visible_tool_count']} 个，扫描 {mcp_summary['scanned_tool_count']} 个，过滤 {mcp_summary['filtered_tool_count']} 个，隔离 {mcp_summary['quarantined_tool_count']} 个；上下文目录 {context_summary['catalog_entry_count']} 条、可见 {context_summary['visible_context_count']} 条、冲突 {context_summary['conflict_count']}、路由失败 {context_summary['failed_route_count']}；工具调用带审计 ID，证据 verdict={mcp_summary['evidence_verdict']}。",
    )
    update_starting_with(
        document,
        "就绪检查（",
        f"就绪检查（{readiness_at}，Asia/Shanghai）：{score} 分；production_ready={bool_text(readiness['production_ready'])}、gateway_ready={bool_text(readiness['gateway_ready'])}、completion_claim_allowed={bool_text(readiness['completion_claim_allowed'])}。生产网关与评测域通过；正式提交材料为 {material_ready}/{material_required}，operational 审批待复核 {operational_pending} 条；当前结论仍是有 P0 补证项，不把运行时通过等同正式参赛材料完成。",
    )
    update_starting_with(
        document,
        "Provider 证据",
        f"Provider 证据（HTTP Agent 运行证据生成于 {gateway_at}）：包含 {provider_routes} 条远端 hostname Provider 路由、{verified_routes} 条网络验证的外部 Provider 路由；literal public IP 证据 {public_ip_proof} 条，严格 external_provider_evidence 计数 {strict_external_proof} 条。该结果只证明本次运行的路由观察、DNS/网络证据与源码指纹绑定；hostname 路由不单独等同公网 IP 证明，也不等同第三方业务授权、稳定 SLA 或外部 Agent 全量接入。",
    )
    update_starting_with(
        document,
        "官方技术报告、报名表和原创性声明模板",
        f"官方技术报告、报名表和原创性声明模板尚未进入工作区。公开报名通知（转载自上海市大学生网络安全大赛公众号）说明信息安全作品赛需提交软件作品、技术报告、作品原创性声明和报名表，具体附件位于官方 QQ 群文件，并写明作品赛报名及提交截止时间为 2026 年 8 月 17 日 24:00；当前日期为 {current_date_label}，{deadline_note}。当前草稿未冒充官方模板。",
    )
    update_starting_with(
        document,
        "operational 队列仍有",
        f"operational 队列仍有 {operational_pending} 条高风险待复核记录，当前仅保留 Hash 和状态，不代替人工批准或驳回，不将审批结果伪造为已完成；最新导出中 api.call {pending_tools['api.call']} 条、mail.send {pending_tools['mail.send']} 条。",
    )
    update_starting_with(
        document,
        "fixture-agent 的工具",
        f"fixture-agent 的工具、模型、外部 API 主机和 MCP 上下文四项边界当前均已登记；MCP operator 证据生成于 {mcp_at}，上下文目录 {context_summary['catalog_entry_count']} 条、可见 {context_summary['visible_context_count']} 条、路由失败 {context_summary['failed_route_count']}。",
    )
    update_starting_with(
        document,
        "真实模型评测与网关证据分开统计",
        "真实模型评测与网关证据分开统计：real-model-eval 直接调用模型适配器，gateway-agent-run 才验证 /v1/chat/completions 的 HTTP 契约、Provider 路由和执行边界；两者需分开统计，不合并为单一指标。",
    )
    update_starting_with(
        document,
        "发布门禁：npm run audit:security",
        f"发布门禁：npm run audit:security 当前报告 {readiness_summary['dependency_audit_high_count']} 个 high 级前端传递依赖问题，critical 为 0；升级前需确认 package-lock.json 变更范围，升级后重新执行完整验证。",
    )
    update_starting_with(
        document,
        "状态：技术内容已按当前代码",
        f"状态：技术内容已按当前代码和 {readiness_at} 实时证据更新；生产网关主线与评测域通过，但仍为待提交草稿。{deadline_note}；之后再补齐官方模板、队伍信息、原创性签署和人工审批并生成正式提交件。",
    )
    update_starting_with(
        document,
        "HTTP 单条探针：",
        f"HTTP 单条探针：apps/api/sandbox/reports/current-gateway-probe-8034.json；生成时间 {probe_at}（Asia/Shanghai）；契约与运行指纹校验通过。",
    )
    update_starting_with(
        document,
        "HTTP Agent 批量证据：",
        f"HTTP Agent 批量证据：apps/api/sandbox/reports/current-gateway-agent-run-8034.json；生成时间 {gateway_at}（Asia/Shanghai）；{gateway_summary['gateway_contract_passed_count']}/{gateway_summary['case_count']} 契约通过，{gateway_summary['attack_blocked_count']} 个攻击请求受控，托管执行 {gateway_summary['managed_execution_count']} 次。",
    )
    update_starting_with(
        document,
        "MCP 证据：",
        f"MCP 证据：apps/api/sandbox/reports/current-mcp-probe-8034.json；生成时间 {mcp_at}（Asia/Shanghai）；initialize、tools/list、tools/call、operator evidence 均通过。",
    )
    update_starting_with(
        document,
        "真实模型行为评测：",
        f"真实模型行为评测：apps/api/sandbox/reports/真实模型工具调用盲测报告.json；生成时间 {model_at}（Asia/Shanghai）；智谱 strict real-api，{model_summary['case_count']} 条样本，攻击控制率 {model_summary['attack_control_rate']}%，正常误报率 {model_summary['benign_false_positive_rate']}%，证据 verdict={model_summary['evidence_verdict']}。",
    )
    update_starting_with(
        document,
        "就绪报告：",
        f"就绪报告：apps/api/sandbox/reports/AI Agent安全网关就绪检查.json；生成时间 {readiness_at}（Asia/Shanghai）；生产网关与评测域通过，正式提交材料 {material_ready}/{material_required}，completion_claim_allowed={bool_text(readiness['completion_claim_allowed'])}。",
    )
    update_starting_with(
        document,
        "人工复核包：",
        f"人工复核包：apps/api/sandbox/reports/operational-pending-approvals.json 与 operational-pending-approvals.md；当前 {operational_pending} 条 operational 待复核，{pending_tools['api.call']} 条 api.call、{pending_tools['mail.send']} 条 mail.send，全部 hash 有效但尚未完成人工批准或驳回。",
    )

    properties = document.core_properties
    properties.title = "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关·当前证据草稿"
    properties.subject = "信息安全作品赛软件作品·安全检测方向·待提交草稿"
    properties.author = "参赛团队"
    properties.last_modified_by = "参赛团队"
    properties.comments = f"按 {readiness_at} Asia/Shanghai 实时证据刷新；个人信息与签署字段待队伍填写。"
    properties.modified = datetime.now(timezone.utc)
    document.save(report_path)
    write_material_status(
        report_path=report_path,
        readiness=readiness,
        gateway_run=gateway_run,
        mcp_probe=mcp_probe,
        real_model=real_model,
        pending=pending,
        refreshed_at=refreshed_at,
    )
    print(report_path)


if __name__ == "__main__":
    main()
