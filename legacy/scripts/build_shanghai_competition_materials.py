from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from docx import Document
from openpyxl import load_workbook

CONTEST_TITLE = "第十一届上海市大学生网络安全大赛暨“磐石行动”2026第四届全国高校网络安全攻防活动"
PROJECT_TITLE = "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关"
DEFAULT_PROFILE = {
    # Keep the generator free of historical participant identity data.  A
    # real profile must be supplied explicitly for any registration artifact.
    "school": "",
    "instructors": [],
    "members": [
        {
            "name": "",
            "major": "",
            "grade": "",
            "student_id": "",
            "phone": "",
            "email": "",
            "remark": "",
        }
    ],
    "submission_date": "",
    "declaration_date": "",
    "online_demo_url": "",
    "confirmations": {"report_reviewed": False, "registration_confirmed": False},
}
OLD_PROJECT_TITLES = (
    "智安哨：面向大模型智能体应用安全的攻击面研究与行为监督平台",
    "智安哨：大模型智能体攻击面研究与行为监督平台",
)
ABSTRACT = (
    "随着大语言模型从文本问答系统发展为可以调用文件、邮件、API、代码执行器和长期记忆的智能体系统，安全风险已经从输出内容合规扩展到模型行为是否会触发真实动作。传统输入过滤和输出审核难以覆盖工具调用、上下文污染、长期记忆污染和低信任工具返回等执行层风险。作品参加信息安全作品赛软件作品类别，所属安全检测方向，构建“攻击面研究—样本构造—本地夹具复现—行为监督—独立评测”的闭环。"
)
ABSTRACT_2 = (
    "作品覆盖提示注入、模型越狱、数据泄露、滥用风险、工具调用劫持、记忆中毒和环境感知污染7类攻击面，包含22个历史攻防脚本和当前 OpenAI 兼容 API、MCP Gateway 的真实接入路径。系统在客户端消息进入 Provider 前、Provider 输出返回 Agent 前以及工具执行前设置监督点，对工具定义、工具参数、上下文返回和执行回执进行校验，输出允许、拒绝、询问、隔离四类决策。"
)
def build_abstract_3(benchmark: dict, e2e: dict, reproducibility: dict) -> str:
    full = benchmark["full_runtime"]
    perf = benchmark["performance"]
    return (
        "工程上，系统由React控制台、FastAPI后端、本地目标夹具、沙箱工具、CLI评测器和通用AgentToolGuard组成，OpenClaw仅作为可选兼容。"
        "22个历史攻防脚本均由工具副作用断言验证；在不含risk_hint的200条内部冻结回归集中，完整运行时方案攻击召回率"
        f"{full['attack_recall_rate']}%、正常误报率{full['benign_false_positive_rate']}%。四组基线表明，仅使用工具白名单的攻击召回率为10%，"
        f"加入参数策略后为90%，加入上下文与运行时判定后为{full['attack_recall_rate']}%。20并发下P95判定延迟"
        f"{perf['concurrent_latency_ms']['p95']}毫秒、吞吐{perf['concurrent_throughput_per_second']}次/秒。完整HTTP、Token鉴权、SQLite和HMAC审计链路在"
        f"{e2e['performance']['concurrency']}并发下成功{e2e['performance']['success_count']}/{e2e['performance']['call_count']}，"
        f"P95为{e2e['performance']['latency_ms']['p95']}毫秒。作者侧独立复现入口重复运行"
        f"{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}次通过且输入、结果哈希稳定。"
        "该冻结集明确标记为内部回归证据，复现者身份仍待非作者签署，不冒充第三方盲测。"
    )


def set_text(paragraph, text: str) -> None:
    if paragraph.runs:
        paragraph.runs[0].text = text
        for run in paragraph.runs[1:]:
            run.text = ""
    else:
        paragraph.add_run(text)


def remove_paragraph(paragraph) -> None:
    paragraph._element.getparent().remove(paragraph._element)


def paragraphs_in_table(table):
    for row in table.rows:
        for cell in row.cells:
            yield from cell.paragraphs
            for nested in cell.tables:
                yield from paragraphs_in_table(nested)


def all_paragraphs(document):
    yield from document.paragraphs
    for table in document.tables:
        yield from paragraphs_in_table(table)


def replace_text(document, replacements: dict[str, str]) -> None:
    for paragraph in all_paragraphs(document):
        text = paragraph.text
        updated = text
        for old, new in replacements.items():
            updated = updated.replace(old, new)
        if updated != text:
            set_text(paragraph, updated)


def update_table(table, headers: list[str], rows: list[list[str]]) -> None:
    while len(table.rows) > 1:
        table._tbl.remove(table.rows[-1]._tr)
    for index, value in enumerate(headers):
        set_text(table.rows[0].cells[index].paragraphs[0], value)
    for values in rows:
        cells = table.add_row().cells
        for index, value in enumerate(values):
            set_text(cells[index].paragraphs[0], value)


def load_profile(path: Path | None = None) -> dict[str, Any]:
    profile = json.loads(json.dumps(DEFAULT_PROFILE, ensure_ascii=False))
    if path is not None:
        if not path.exists():
            raise SystemExit(f"参赛者资料文件不存在：{path}")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise SystemExit("参赛者资料必须是 JSON 对象")
        profile.update({key: value for key, value in loaded.items() if key != "confirmations"})
        if isinstance(loaded.get("confirmations"), dict):
            profile["confirmations"].update(loaded["confirmations"])
    return profile


def load_policy_count(repo_root: Path) -> int:
    """Read the current policy catalog instead of freezing an old count."""

    policy_path = repo_root / "apps" / "api" / "agent_supervisor" / "config" / "policies.json"
    try:
        payload = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"当前防护策略目录无法读取：{policy_path}") from exc
    if not isinstance(payload, list) or not payload:
        raise SystemExit(f"当前防护策略目录不是非空数组：{policy_path}")
    return len(payload)


def profile_missing_fields(profile: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if not str(profile.get("school", "")).strip():
        missing.append("school")
    instructors = [str(item).strip() for item in profile.get("instructors", []) if str(item).strip()]
    if not instructors:
        missing.append("instructors[0]")
    members = profile.get("members", [])
    if not isinstance(members, list) or not members:
        return [*missing, "members[0]"]
    required_member_fields = ("name", "major", "grade", "student_id", "phone", "email")
    for index, member in enumerate(members[:5]):
        for field in required_member_fields:
            if not str(member.get(field, "")).strip():
                missing.append(f"members[{index}].{field}")
    return missing


def report_ready(profile: dict[str, Any]) -> bool:
    first_member = (profile.get("members") or [{}])[0]
    confirmations = profile.get("confirmations", {})
    return bool(
        str(first_member.get("email", "")).strip()
        and str(profile.get("submission_date", "")).strip()
        and confirmations.get("report_reviewed") is True
    )


def registration_ready(profile: dict[str, Any]) -> bool:
    confirmations = profile.get("confirmations", {})
    return not profile_missing_fields(profile) and confirmations.get("registration_confirmed") is True


def update_report(
    source: Path,
    destination: Path,
    benchmark: dict,
    e2e: dict,
    reproducibility: dict,
    profile: dict[str, Any],
    policy_count: int,
) -> None:
    document = Document(source)
    first_member = (profile.get("members") or [{}])[0]
    report_email = str(first_member.get("email", "")).strip() or "待填写"
    submission_date = str(profile.get("submission_date", "")).strip() or "待填写"
    online_demo_url = str(profile.get("online_demo_url", "")).strip()
    online_demo_text = online_demo_url or "未提供公开线上入口；现场使用本地一键启动演示"
    replace_text(
        document,
        {
            CONTEST_TITLE.replace("2026第四届", "2025第三届"): CONTEST_TITLE,
            "第十九届全国大学生信息安全竞赛（作品赛）暨第三届“长城杯”网数智安全大赛（作品赛）": CONTEST_TITLE,
            OLD_PROJECT_TITLES[0]: PROJECT_TITLE,
            OLD_PROJECT_TITLES[1]: PROJECT_TITLE,
            "命题挑战赛方向一“面向大模型及其应用的安全性研究”": "信息安全作品赛“安全检测”方向",
            "命题挑战赛": "信息安全作品赛",
            "攻击召回率为76%": "攻击召回率为80%",
            "https://xa.chengxiaoyu.top:46858": online_demo_text,
        },
    )

    paragraphs = list(document.paragraphs)
    for paragraph in paragraphs:
        text = paragraph.text.strip()
        if text == "附件2：":
            set_text(paragraph, "序号：（组委会填写）")
        elif text == "☑命题赛道             □自由赛道":
            set_text(paragraph, "作品类别：软件作品    所属方向：安全检测")
        elif text == "作品名称：                                           ":
            set_text(paragraph, f"作品名称：{PROJECT_TITLE}")
        elif text.startswith("电子邮箱："):
            set_text(paragraph, f"电子邮箱：{report_email}")
        elif text.startswith("提交日期："):
            set_text(paragraph, f"提交日期：{submission_date}")
        elif text.startswith("随着大语言模型从文本问答系统"):
            set_text(paragraph, ABSTRACT)
        elif text.startswith("作品从红队视角系统研究"):
            set_text(paragraph, ABSTRACT_2)
        elif text.startswith("工程上，系统由React控制台"):
            set_text(paragraph, build_abstract_3(benchmark, e2e, reproducibility))
        elif text.startswith("该作品名称为"):
            set_text(
                paragraph,
                f"该作品名称为“{PROJECT_TITLE}”。作品所属信息安全作品赛软件作品类别的“安全检测”方向，重点研究大模型智能体在工具调用和运行时执行链路中的安全风险。",
            )
        elif text.startswith("本章明确了作品名称"):
            set_text(
                paragraph,
                "本章明确了作品名称、所属方向和研究动机。智安哨不是普通后台管理页面，而是围绕大模型智能体安全形成“攻击面研究—样本构造—本地夹具复现—行为监督—独立评测”的闭环作品。",
            )
        elif text.startswith("系统先对每个脚本运行无防护组"):
            set_text(
                paragraph,
                "系统先对每个脚本运行无防护组，再运行有防护组。22个脚本均在无防护路径观察到可验证工具副作用，复现率100%；有防护有效控制22个，控制率100%；预期策略匹配率和证据完整率均为100%。",
            )
        elif text.startswith("工具调用劫持案例中"):
            set_text(
                paragraph,
                "工具调用劫持案例中，攻击者以赛事审计为理由诱导智能体读取 confidential/competition-teams.csv。无防护时本地沙箱返回含占位 token 的敏感夹具内容；开启监督后命中文件边界策略并拒绝执行，说明监督器可以在工具执行前识别敏感路径。",
            )
        elif text.startswith("连续赛事流程攻击链案例中"):
            set_text(
                paragraph,
                "连续赛事流程攻击链案例中，攻击先接收恶意工具元数据，再诱导批量导出、外部邮件发送和记忆污染。无防护路径分别产生低信任授权字段、敏感业务对象、outbox记录和记忆写入；开启监督后触发工具返回隔离、批量动作复核、外部邮件询问和记忆写入隔离。",
            )
        elif text.startswith("该作品的核心创新在于"):
            set_text(
                paragraph,
                "该作品的核心创新在于把大模型安全从输入输出检查推进到智能体运行时行为监督，并联合分析上下文来源、Agent身份、工具能力、资源敏感度、目标去向和跨步骤时序。系统在副作用发生前输出允许、拒绝、询问或隔离，并以真实沙箱副作用、无risk_hint冻结回归集和四组基线验证各层控制的增益。",
            )
        elif text.startswith("当前系统以受控沙箱和模拟业务数据"):
            set_text(
                paragraph,
                f"当前22个攻防脚本、24条固定标签留出样本和200条冻结回归样本均属于团队内部证据；真实模型工具调用样本目前为6条。通用AgentToolGuard已完成带Token和HMAC的端到端工具执行验证；OpenClaw为可选兼容。独立复现入口已由作者重复运行{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}次，源码、数据集、策略和结果哈希均已记录；非作者签署、第三方隐藏测试集和更多真实业务日志仍待补充。报告据此区分本地实证、可重复运行证据和外部验证，不将内部回归结果表述为第三方盲测。",
            )
        elif text.startswith("报告围绕“智安哨"):
            set_text(
                paragraph,
                f"报告围绕“{PROJECT_TITLE}”展开，说明作品的选题方向、研究背景、需求分析、总体方案、关键技术、工程实现、测试结果、创新性和应用前景。系统围绕安全检测方向形成攻击复现、运行时监督、人工复核、证据留痕和独立评测闭环。",
            )
        elif text.startswith("当前系统覆盖7类攻击面"):
            set_text(
                paragraph,
                f"当前系统覆盖7类攻击面、22个历史攻击脚本和{policy_count}条监督策略；OpenAI 兼容代理与 MCP Gateway 的真实 Provider/上游证据按运行记录生成。历史脚本均完成无防护副作用复现和有防护控制；200条无risk_hint内部冻结回归集包含100条攻击和100条正常样本，完整方案攻击召回率100%、正常误报率0%，并提供四组基线和P50/P95/P99性能数据。",
            )

    instruction_start = next((i for i, paragraph in enumerate(document.paragraphs) if paragraph.text.strip() == "填写说明"), None)
    if instruction_start is not None:
        for paragraph in list(document.paragraphs)[instruction_start : instruction_start + 6]:
            remove_paragraph(paragraph)

    table0_rows = [
                ["原创性与创新性", "提出面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关，将监督点前移到 Provider 输出和工具执行边界。", f"7类攻击面、{policy_count}条策略、四类决策、通用 AgentToolGuard。"],
        ["作品完成度", "形成样本、脚本、目标夹具、监督器、沙箱、报告和控制台闭环。", f"全量后端/前端回归测试、通用Agent端到端证据、独立复现{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}次通过。"],
        ["性能与可靠性", "以无标签冻结集、四组基线和完整链路压力测试验证。", f"内部判定20并发P95 {benchmark['performance']['concurrent_latency_ms']['p95']}ms；HTTP+SQLite+HMAC链路{e2e['performance']['call_count']}次请求全部成功，P95 {e2e['performance']['latency_ms']['p95']}ms。"],
        ["应用与推广价值", "面向办公Agent敏感数据外泄防护、工具最小权限和上线前评测。", "可配置内部域、敏感路径/API、Agent工具权限；插件支持鉴权、默认关闭risk_hint。"],
        ["文档规范性", "提供技术报告、样本集、脚本、实验报告和答辩演示链路。", "JSON/Markdown证据包、fixture_source、副作用断言和复核Hash。"],
    ]
    update_table(document.tables[0], ["评审指标", "作品响应", "可核验证据"], table0_rows)
    table1_rows = [
        ["攻击研究", "覆盖提示注入、越狱、数据泄露等7类攻击面。", "攻击面矩阵、22个脚本。"],
        ["攻击材料", "历史脚本包含对抗输入、步骤和工具调用；当前 API/MCP 证据以真实运行记录为准。", "历史材料中的66条对抗样本和66条越狱用例。"],
                ["监督原型", "Provider 前后和工具执行前输出允许、拒绝、询问、隔离。", f"{policy_count}条策略、9类工具、OpenAI/MCP 审计日志。"],
        ["真实可验证性", "以本地目标夹具副作用和沙箱状态断言结果。", "attack_outcome、fixture_source、Hash链。"],
        ["误报控制", "同时验证正常单步任务和连续业务流程。", "36条样本误报0、4条流程误报0。"],
        ["开放适配", "提供通用事件接口、AgentToolGuard和多框架示例；OpenClaw为可选插件。", "带Token/HMAC的4次端到端工具调度全部生成审计证据；风险控制3次、正常执行1次。"],
        ["独立复现", "固定源码、数据集和策略快照，重复执行确定性判据。", f"作者侧{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}轮通过；报告SHA-256为{reproducibility['evidence_sha256'][:16]}…，待非作者签署。"],
        ["复核队列隔离", "将业务、批量评测和答辩演示复核单分为operational、experiment、demo。", "赛前体检分别输出三类数量；演示闭环使用demo证据，不把实验积压计入业务SLA。"],
    ]
    update_table(document.tables[1], ["完整性项目", "作品实现", "证据"], table1_rows)
    update_table(
        document.tables[5],
        ["模块", "实现位置", "主要职责"],
        [
            ["后端API", "apps/api/agent_supervisor", "监督判定、沙箱工具、评测和报告生成"],
            ["前端控制台", "apps/console/src", "攻防对照、监督复核、独立评测展示"],
            ["文档站", "apps/docs", "架构、接口、运行和演示说明"],
            ["CLI", "scripts/agent-supervisor-cli.mjs", "批量评测、样本导出、证据包和赛前体检"],
        ],
    )
    update_table(
        document.tables[6],
        ["证据类型", "内容", "用途"],
        [
            ["运行记录", "脚本、时间、防护开关、工具副作用", "证明实验实际执行"],
            ["审计日志", "工具、参数、决策、策略、风险分", "解释监督结果"],
            ["副作用断言", "执行状态、观察结果、原因、fixture_source", "证明攻击结果来自实际输出"],
            ["告警记录", "阻断或询问原因、处置建议", "支撑现场展示"],
            ["完整性校验", "previous_hash、audit_hash、review_hash和可选HMAC签名", "校验内容连续性；配置签名密钥后检测重算篡改"],
            [
                "内部冻结回归集",
                "100条攻击、100条正常，不含risk_hint，绑定数据集和策略SHA-256",
                f"数据集SHA-256：{benchmark['dataset_sha256']}；策略快照SHA-256：{benchmark['policy_sha256']}；不冒充第三方盲测",
            ],
            [
                "独立复现一致性",
                "固定输入重复运行冻结评测和通用Agent链路，并记录源码清单与报告哈希",
                f"{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}轮通过；输入稳定、结果稳定；待非作者签署",
            ],
        ],
    )
    update_table(
        document.tables[7],
        ["指标", "含义", "本次结果"],
        [
            ["无防护复现率", "关闭监督时攻击是否触发预期副作用", "100%（22/22）"],
            ["有防护控制率", "开启监督后风险动作是否被控制", "100%（22/22）"],
            ["预期策略匹配率", "实际策略是否与人工标签一致", "100%（22/22）"],
            ["证据完整率", "是否具备样本、脚本、断言、告警和Hash", "100%（22/22）"],
            ["正常任务误报率", "正常任务被错误控制的比例", "0%（36条）"],
            ["独立留出集漏报率", "攻击样本未被控制的比例", "0%（12条攻击）"],
            ["独立留出集误报率", "正常样本被错误控制的比例", "0%（12条正常）"],
            ["冻结回归集", "无risk_hint的内部固定回归样本", "100条攻击+100条正常；完整方案召回100%、误报0%"],
            ["四组基线", "逐层验证工具契约、参数和上下文的增益", "允许全部0%、工具白名单10%、参数策略90%、完整方案100%召回"],
            ["运行时性能", "2000次判定、20并发", f"P50/P95/P99={benchmark['performance']['concurrent_latency_ms']['p50']}/{benchmark['performance']['concurrent_latency_ms']['p95']}/{benchmark['performance']['concurrent_latency_ms']['p99']}ms"],
            ["完整链路性能", "HTTP、Token、SQLite、审计Hash与HMAC", f"{e2e['performance']['call_count']}次请求全部成功；吞吐{e2e['performance']['throughput_per_second']}次/秒；P95={e2e['performance']['latency_ms']['p95']}ms"],
            ["独立复现一致性", "同一源码、数据集和策略下重复执行确定性判据", f"{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}轮通过；输入和结果哈希稳定"],
        ],
    )
    update_table(
        document.tables[8],
        ["创新点", "说明"],
        [
            ["执行层安全检查点", "把安全检查从对话层前移到工具执行前，直接约束目标资源和副作用。"],
            ["工具契约规范化", "对工具白名单、Unicode、编码路径、收件人和API路径统一规范化，默认拒绝未知工具。"],
            ["副作用实证评测", "攻击成功由文件、邮件、API、记忆、模型输出等沙箱副作用断言，不由防护开关自证。"],
            ["独立留出集", "使用人工固定标签攻击/正常样本测量召回率、误报率和策略匹配率。"],
            ["四类处置与人工闭环", "允许、拒绝、询问、隔离配合审计Hash和reviewHash，兼顾自动化与人工判断。"],
            ["开放适配与赛事场景", "覆盖通用HTTP、OpenAI Agents、LangChain、LangGraph和赛事队伍/提交物/榜单/会话等业务对象；OpenClaw为可选兼容。"],
            ["可配置零信任边界", "按部署环境配置内部邮箱域、敏感路径、高敏API和每个Agent的工具最小权限。"],
            ["去自标注评测", "通用Agent端到端演示和200条冻结集均不发送risk_hint，由监督器独立观察工具、参数、上下文和时序。"],
        ],
    )

    properties = document.core_properties
    properties.title = PROJECT_TITLE
    properties.subject = "信息安全作品赛软件作品·安全检测方向"
    properties.author = "参赛团队"
    properties.last_modified_by = "参赛团队"
    properties.keywords = "大模型安全,智能体,工具调用,运行时监督,安全检测"
    destination.parent.mkdir(parents=True, exist_ok=True)
    document.save(destination)


def update_declaration(source: Path, destination: Path, profile: dict[str, Any]) -> None:
    document = Document(source)
    replace_text(
        document,
        {
            "第十届上海市大学生网络安全大赛暨“磐石行动”2025第三届全国高校网络安全攻防活动（作品赛）": CONTEST_TITLE + "（信息安全作品赛）",
            "《                         》": f"《{PROJECT_TITLE}》",
        },
    )
    declaration_date = str(profile.get("declaration_date", "")).strip() or "2026年    月    日"
    for paragraph in document.paragraphs:
        if paragraph.text.strip().startswith("年"):
            set_text(paragraph, declaration_date)
    properties = document.core_properties
    properties.title = f"{PROJECT_TITLE}·作品原创性声明"
    properties.author = "参赛团队"
    properties.last_modified_by = "参赛团队"
    destination.parent.mkdir(parents=True, exist_ok=True)
    document.save(destination)


def update_registration(
    source: Path,
    destination: Path,
    benchmark: dict,
    e2e: dict,
    reproducibility: dict,
    profile: dict[str, Any],
) -> None:
    workbook = load_workbook(source)
    sheet = workbook["Sheet1"]
    sheet["B2"] = str(profile.get("school", "")).strip() or "待填写"
    instructors = [str(item).strip() for item in profile.get("instructors", []) if str(item).strip()]
    sheet["G2"] = "、".join(instructors) or "待填写"
    sheet["B3"] = PROJECT_TITLE
    sheet["B4"] = "1.软件作品（安全检测方向）"
    for row in range(7, 12):
        for column in ("A", "B", "C", "D", "E", "G", "H"):
            sheet[f"{column}{row}"] = None
    members = profile.get("members", [])
    for offset, member in enumerate(members[:5]):
        row = 7 + offset
        sheet[f"A{row}"] = str(member.get("name", "")).strip() or "待填写"
        sheet[f"B{row}"] = str(member.get("major", "")).strip() or "待填写"
        sheet[f"C{row}"] = str(member.get("grade", "")).strip() or "待填写"
        sheet[f"D{row}"] = str(member.get("student_id", "")).strip() or "待填写"
        sheet[f"E{row}"] = str(member.get("phone", "")).strip() or "待填写"
        sheet[f"G{row}"] = str(member.get("email", "")).strip() or "待填写"
        sheet[f"H{row}"] = str(member.get("remark", "")).strip()
    sheet["A13"] = (
        "智安哨是一套面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关，属于人工智能应用安全与安全检测方向。作品在模型请求进入 Provider 前、模型输出返回 Agent 前、工具执行和 MCP 上下文回灌前建立统一信任边界，联合分析上下文来源、Agent 身份、工具能力、资源敏感度、目标去向和跨步骤时序，输出允许、拒绝、询问、隔离决策。22 个本地攻击脚本和 200 条内部冻结回归样本仅作为防线验证证据；真实 Provider、MCP 上游和正式材料状态单独标注，不把离线评测当作生产接入证明。四组基线和并发延迟数据只用于说明策略增量与工程成本，"
        f"{benchmark['performance']['concurrent_latency_ms']['p95']}毫秒。通用AgentToolGuard已完成带Token/HMAC的4次端到端工具调度；HTTP、SQLite与审计完整链路"
        f"{e2e['performance']['call_count']}次请求全部成功，P95为{e2e['performance']['latency_ms']['p95']}毫秒。独立复现入口作者侧"
        f"{reproducibility['summary']['passed_count']}/{reproducibility['summary']['trial_count']}轮通过并记录源码、数据集、策略和报告SHA-256；非作者签署待回收。OpenClaw仅作为可选兼容。"
    )
    workbook.properties.creator = "参赛团队"
    workbook.properties.lastModifiedBy = "参赛团队"
    destination.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(destination)


def docx_text(path: Path) -> str:
    document = Document(path)
    chunks = [paragraph.text for paragraph in document.paragraphs]
    chunks.extend(cell.text for table in document.tables for row in table.rows for cell in row.cells)
    return "\n".join(chunks)


def docx_xml_text(path: Path) -> str:
    with ZipFile(path) as archive:
        return "\n".join(
            archive.read(info).decode("utf-8", errors="ignore")
            for info in archive.infolist()
            if info.filename.endswith(".xml")
        )


def validate_report_template(report_path: Path, official_template: Path) -> None:
    required_headings = {
        "摘要",
        "第一章 作品概述",
        "第二章 作品设计与实现",
        "第三章 作品测试与分析",
        "第四章 创新性说明",
        "第五章 总结",
        "参考文献",
    }
    template_headings = {paragraph.text.strip() for paragraph in Document(official_template).paragraphs if paragraph.style.name.startswith("Heading")}
    report_headings = {paragraph.text.strip() for paragraph in Document(report_path).paragraphs if paragraph.style.name.startswith("Heading")}
    missing_headings = sorted(required_headings - template_headings)
    if missing_headings:
        raise SystemExit(f"官方上海技术报告模板结构异常，缺少章节：{missing_headings}")
    if not required_headings.intersection(report_headings):
        raise SystemExit("生成技术报告未保留官方模板章节结构")
    xml_text = docx_xml_text(report_path)
    forbidden = (
        "第十九届全国大学生信息安全竞赛",
        "长城杯",
        "广州应用科技学院",
        "命题赛道",
        "线上演示入口（提交时补充）",
    )
    leaked = [term for term in forbidden if term in xml_text]
    if leaked:
        raise SystemExit(f"技术报告 XML 仍包含旧赛事、身份或未填入口信息：{leaked}")


def material_input_paths(repo_root: Path, profile_path: Path | None) -> tuple[dict[str, Path], list[str]]:
    """Resolve source files before creating any output artifact.

    The official Shanghai templates live in an ignored, operator-provided
    directory.  Reporting every missing input together keeps a clean checkout
    diagnosable and avoids a half-generated package or an accidental fallback
    to historical participant data.
    """

    source_report_dir = repo_root / "docs" / "长城信息安全"
    source_report_candidates = sorted(source_report_dir.glob("*作品报告.docx")) if source_report_dir.exists() else []
    paths = {
        "参赛信息填写模板": profile_path or Path(""),
        "历史技术报告源文件": (
            source_report_candidates[0]
            if source_report_candidates
            else repo_root / "docs/长城信息安全/*作品报告.docx"
        ),
        "官方技术报告模板": repo_root / "docs/上海信息安全/作品赛报名表及附件/附件1a：作品技术报告（软件作品模板）.docx",
        "官方原创性声明模板": repo_root / "docs/上海信息安全/作品赛报名表及附件/附件2：作品赛作品原创性声明.docx",
        "官方报名表模板": repo_root / "docs/上海信息安全/作品赛报名表及附件/信息安全作品赛报名表.xlsx",
    }
    missing = [label for label, path in paths.items() if not path.is_file()]
    return paths, missing


def main() -> None:
    parser = argparse.ArgumentParser(description="生成上海市大学生网络安全大赛信息安全作品赛材料草稿")
    parser.add_argument("--output", default="docs/上海信息安全/参赛材料草稿")
    parser.add_argument("--profile", default="docs/上海信息安全/参赛材料草稿/参赛信息填写模板.json")
    parser.add_argument("--signed-declaration", help="已签署的原创性声明 DOCX/PDF 路径；提供后复制为正式声明文件")
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    profile_path = repo_root / args.profile if args.profile else None
    source_paths, missing_inputs = material_input_paths(repo_root, profile_path)
    if missing_inputs:
        details = [f"- {label}: {source_paths[label]}" for label in missing_inputs]
        raise SystemExit("参赛材料生成前置输入缺失：\n" + "\n".join(details))
    profile = load_profile(profile_path)
    missing_profile_fields = profile_missing_fields(profile)
    benchmark_report = json.loads((repo_root / "apps/api/sandbox/reports/200条冻结集与基线性能评测.json").read_text(encoding="utf-8"))
    benchmark = {
        "full_runtime": next(item["summary"] for item in benchmark_report["baselines"] if item["name"] == "full-runtime"),
        "performance": benchmark_report["performance"],
        "dataset_sha256": benchmark_report["dataset"]["sha256"],
        "policy_sha256": benchmark_report["policy_snapshot"]["sha256"],
    }
    e2e = json.loads((repo_root / "apps/api/sandbox/reports/HTTP-SQLite-审计完整链路性能评测.json").read_text(encoding="utf-8"))
    reproducibility = json.loads((repo_root / "apps/api/sandbox/reports/独立复现一致性验收报告.json").read_text(encoding="utf-8"))
    policy_count = load_policy_count(repo_root)
    output = repo_root / args.output
    source_report = source_paths["历史技术报告源文件"]
    official_template = source_paths["官方技术报告模板"]
    source_declaration = source_paths["官方原创性声明模板"]
    source_registration = source_paths["官方报名表模板"]
    report_name = f"{PROJECT_TITLE}-技术报告.docx" if report_ready(profile) else f"{PROJECT_TITLE}-技术报告-待提交.docx"
    declaration_draft_path = output / f"{PROJECT_TITLE}-原创性声明-待签署.docx"
    registration_name = f"{PROJECT_TITLE}-报名表.xlsx" if registration_ready(profile) else f"{PROJECT_TITLE}-报名表-待补个人信息.xlsx"
    report_path = output / report_name
    registration_path = output / registration_name
    update_report(source_report, report_path, benchmark, e2e, reproducibility, profile, policy_count)
    update_declaration(source_declaration, declaration_draft_path, profile)
    update_registration(source_registration, registration_path, benchmark, e2e, reproducibility, profile)
    declaration_path = declaration_draft_path
    signed_source = Path(args.signed_declaration) if args.signed_declaration else None
    if signed_source:
        signed_source = signed_source if signed_source.is_absolute() else repo_root / signed_source
        if not signed_source.exists() or signed_source.suffix.lower() not in {".docx", ".pdf"}:
            raise SystemExit("已签署原创性声明必须是存在的 DOCX 或 PDF 文件")
        declaration_path = output / f"{PROJECT_TITLE}-原创性声明{signed_source.suffix.lower()}"
        shutil.copy2(signed_source, declaration_path)
    report_text = docx_text(report_path)
    declaration_text = docx_text(declaration_draft_path)
    forbidden = ("第十九届全国大学生信息安全竞赛", "长城杯", "广州应用科技学院", "何彬")
    leaked = [term for term in forbidden if term in report_text]
    if leaked:
        raise SystemExit(f"技术报告仍包含匿名审查禁止信息：{leaked}")
    if PROJECT_TITLE not in report_text or CONTEST_TITLE not in report_text:
        raise SystemExit("技术报告缺少当前作品名称或赛事名称")
    if PROJECT_TITLE not in declaration_text or CONTEST_TITLE not in declaration_text:
        raise SystemExit("原创性声明缺少当前作品名称或赛事名称")
    validate_report_template(report_path, official_template)
    status = {
        "profile_path": str((repo_root / args.profile).resolve()) if args.profile else "",
        "profile_missing_fields": missing_profile_fields,
        "report_reviewed": bool(profile.get("confirmations", {}).get("report_reviewed")),
        "registration_confirmed": bool(profile.get("confirmations", {}).get("registration_confirmed")),
        "technical_report_ready": report_ready(profile),
        "registration_form_ready": registration_ready(profile),
        "originality_declaration_ready": bool(signed_source),
        "signed_declaration_source": str(signed_source.resolve()) if signed_source else "",
        "paths": {
            "technical_report": str(report_path.resolve()),
            "registration_form": str(registration_path.resolve()),
            "originality_declaration": str(declaration_path.resolve()),
        },
    }
    status_path = output / "参赛材料生成状态.json"
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"技术报告：{report_path}")
    print(f"原创性声明：{declaration_path}")
    print(f"报名表：{registration_path}")
    print(f"材料状态：{status_path}")


if __name__ == "__main__":
    main()
