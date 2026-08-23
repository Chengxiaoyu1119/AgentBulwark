from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_MARKERS = ("智安哨", "大模型智能体", "行为监督")
CURRENT_TITLE = "智安哨：面向 LLM Agent、OpenAI 兼容 API 与 MCP 的运行时安全网关"
HISTORICAL_TITLE = "智安哨：面向大模型智能体应用安全的攻击面研究与行为监督平台"
RULE_SOURCE = "https://security.zone.ci/secarticles/wx/564281.html（转载自上海市大学生网络安全大赛公众号）"
DEADLINE = "2026年8月17日24:00"


def read_pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader
    except ImportError:
        return ""
    try:
        return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
    except Exception:  # noqa: BLE001 - audit remains explicit when a PDF cannot be parsed
        return ""


def audit(root: Path) -> dict[str, Any]:
    history_root = root / "docs" / "长城信息安全"
    prior_artifacts = [
        str(path.relative_to(root)).replace("\\", "/")
        for path in sorted(history_root.glob("*智安哨*"))
        if path.is_file()
    ]
    award_documents = sorted((root / "docs" / "上海信息安全").glob("*获奖名单*.pdf"))
    award_matches = []
    parsed_award_documents = []
    for path in award_documents:
        text = read_pdf_text(path)
        parsed_award_documents.append(
            {
                "path": str(path.relative_to(root)).replace("\\", "/"),
                "parsed": bool(text),
                "contains_project_marker": any(marker in text for marker in PROJECT_MARKERS),
            }
        )
        if any(marker in text for marker in PROJECT_MARKERS):
            award_matches.append(str(path.relative_to(root)).replace("\\", "/"))

    if award_matches:
        status = "local-award-match-found"
        conclusion = "本地获奖名单出现同源作品标记，提交前必须核对是否为同一作品及是否符合重复参赛规则。"
    elif prior_artifacts:
        status = "needs-team-attestation"
        conclusion = "本地存在同源历史提交材料，但获奖名单未出现项目标记；名单缺失不能证明未获奖，需由队伍确认历史参赛与获奖情况。"
    else:
        status = "no-local-history-found"
        conclusion = "当前本地材料未发现同源历史提交，但仍需队伍确认没有外部参赛获奖记录。"

    return {
        "schema_version": "agent-supervisor.shanghai-eligibility-audit.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "source": RULE_SOURCE,
            "deadline": DEADLINE,
            "text": "已经参加过其它赛事并获奖的作品不得重复参赛。",
        },
        "status": status,
        "prior_submission_detected": bool(prior_artifacts),
        "prior_submission_artifacts": prior_artifacts,
        "award_documents": parsed_award_documents,
        "local_award_match_found": bool(award_matches),
        "local_award_match_documents": award_matches,
        "lineage_assessment": {
            "current_title": CURRENT_TITLE,
            "historical_title": HISTORICAL_TITLE,
            "shared_brand": "智安哨" in CURRENT_TITLE and "智安哨" in HISTORICAL_TITLE,
            "shared_research_topic": "大模型智能体" in CURRENT_TITLE and "大模型智能体" in HISTORICAL_TITLE,
            "assessment": "同品牌、同研究主线，属于明显演进关系；改名本身不足以证明是全新作品。",
        },
        "team_attestation_required": True,
        "conclusion": conclusion,
        "next_action": "确认《智安哨》是否曾在其它赛事获奖；若获奖，保留现状作为研究平台并更换未获奖的新作品主线。",
    }


def build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 上海信息安全作品赛参赛资格审查",
        "",
        f"- 审查状态：`{report['status']}`",
        f"- 规则来源：`{report['rule']['source']}`",
        f"- 提交截止：{report['rule']['deadline']}",
        f"- 资格结论：{report['conclusion']}",
        "",
        "## 证据",
        "",
        f"- 发现同源历史提交材料：{'是' if report['prior_submission_detected'] else '否'}",
        f"- 本地获奖名单命中同源标记：{'是' if report['local_award_match_found'] else '否'}",
        f"- 同源判断：{report['lineage_assessment']['assessment']}",
        "",
        "### 同源历史材料",
        "",
    ]
    if report["prior_submission_artifacts"]:
        lines.extend(f"- `{path}`" for path in report["prior_submission_artifacts"])
    else:
        lines.append("- 未发现")
    lines.extend(["", "### 本地获奖名单", ""])
    for item in report["award_documents"]:
        lines.append(f"- `{item['path']}`：已解析={'是' if item['parsed'] else '否'}，命中={'是' if item['contains_project_marker'] else '否'}")
    lines.extend(
        [
            "",
            "## 第一性原理判断",
            "",
            "“获奖名单未出现项目名”只能证明当前本地文件没有匹配项，不能证明队伍从未获奖。最终资格事实属于队伍历史信息，必须由队伍确认。",
            "",
            f"下一步：{report['next_action']}",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="审查上海信息安全作品赛重复获奖参赛资格")
    parser.add_argument("--output", default="apps/api/sandbox/reports")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root / args.output
    output.mkdir(parents=True, exist_ok=True)
    report = audit(root)
    json_path = output / "上海信息安全参赛资格审查.json"
    markdown_path = output / "上海信息安全参赛资格审查.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_markdown(report), encoding="utf-8")
    print(json.dumps({"json_path": str(json_path.resolve()), "markdown_path": str(markdown_path.resolve()), "status": report["status"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
