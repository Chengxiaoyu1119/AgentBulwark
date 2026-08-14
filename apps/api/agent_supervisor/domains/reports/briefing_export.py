from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...paths import REPO_ROOT, SANDBOX_REPORTS_DIR
from ...storage.data import get_scenarios
from ...storage.database import latest_scenario_run_pairs
from .surface_pack import write_all_surface_briefing_sheets

REPORT_ROOT = SANDBOX_REPORTS_DIR
EXPORT_DIR_NAME = "攻击面评测单页导出"
EXPORT_REPORT_JSON = "攻击面评测单页PNG-PDF导出报告.json"
EXPORT_REPORT_MARKDOWN = "攻击面评测单页PNG-PDF导出报告.md"
LEGACY_EXPORT_DIR_NAMES = ["答辩单页导出"]
LEGACY_EXPORT_REPORTS = ["答辩单页PNG-PDF导出报告.json", "答辩单页PNG-PDF导出报告.md"]
SURFACE_LABELS = {
    "prompt-injection": "提示注入",
    "jailbreak": "模型越狱",
    "data-leakage": "内容泄露",
    "abuse-risk": "滥用风险",
    "tool-hijack": "工具调用劫持",
    "memory-poison": "记忆中毒",
    "environment-pollution": "环境感知污染",
}


def write_briefing_sheet_exports(format_: str = "both") -> dict[str, Any]:
    if format_ not in {"png", "pdf", "both"}:
        raise ValueError("format must be one of: png, pdf, both")

    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    _cleanup_legacy_briefing_outputs()
    briefing_result = write_all_surface_briefing_sheets(
        runs=latest_scenario_run_pairs([scenario["id"] for scenario in get_scenarios()])
    )
    output_dir = REPORT_ROOT / EXPORT_DIR_NAME
    _reset_output_dir(output_dir)
    script_path = REPO_ROOT / "scripts" / "export-briefing-sheets.mjs"
    node_path = shutil.which("node")

    if not node_path:
        data = _failed_result("未找到 Node.js，无法调用本地导出脚本。", briefing_result, output_dir)
        _write_export_report(data)
        return data

    command = [
        node_path,
        str(script_path),
        "--input-dir",
        str(REPORT_ROOT),
        "--output-dir",
        str(output_dir),
        "--format",
        format_,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        data = _failed_result("导出超时：180 秒内没有完成 PNG/PDF 生成。", briefing_result, output_dir)
        _write_export_report(data)
        return data

    export_result = _parse_export_stdout(completed.stdout)
    ok = completed.returncode == 0 and bool(export_result.get("ok"))
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": ok,
        "format": format_,
        "reason": "" if ok else export_result.get("reason") or completed.stderr.strip() or "导出脚本执行失败。",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "briefing_sheets": briefing_result,
        "export": export_result,
        "summary": {
            "surface_count": briefing_result.get("surface_count", 0),
            "html_file_count": briefing_result.get("file_count", 0),
            "exported_surface_count": int(export_result.get("file_count") or 0),
            "png_count": sum(1 for item in export_result.get("files", []) if item.get("png_path")),
            "pdf_count": sum(1 for item in export_result.get("files", []) if item.get("pdf_path")),
            "output_dir": str(output_dir.resolve()),
        },
    }
    _write_export_report(data)
    return data


def load_briefing_sheet_export_report() -> dict[str, Any] | None:
    path = REPORT_ROOT / EXPORT_REPORT_JSON
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def build_briefing_sheet_export_markdown(data: dict[str, Any] | None = None) -> str:
    data = data or load_briefing_sheet_export_report() or _failed_result("尚未运行攻击面评测单页 PNG/PDF 导出。", {}, REPORT_ROOT / EXPORT_DIR_NAME)
    summary = data.get("summary", {})
    lines = [
        "# 攻击面评测导出记录",
        "",
        f"- 生成时间：{data.get('generated_at', '-')}",
        f"- 导出状态：{'通过' if data.get('ok') else '未通过'}",
        f"- 输出目录：`{summary.get('output_dir', '-')}`",
        f"- 攻击面数量：{summary.get('surface_count', 0)}",
        f"- PNG 文件：{summary.get('png_count', 0)}",
        f"- PDF 文件：{summary.get('pdf_count', 0)}",
    ]
    if data.get("reason"):
        lines.extend(["", f"- 失败原因：{data['reason']}"])
    lines.extend(["", "## 文件清单", "", "| 攻击面 | PNG | PDF |", "|---|---|---|"])
    files = data.get("export", {}).get("files", [])
    if files:
        for item in files:
            lines.append(
                "| {surface} | {png} | {pdf} |".format(
                    surface=_surface_label(item.get("surface_id")),
                    png="已生成" if item.get("png_path") else "未生成",
                    pdf="已生成" if item.get("pdf_path") else "未生成",
                )
            )
    else:
        lines.append("| - | - | - |")
    return "\n".join(lines) + "\n"


def _surface_label(surface_id: Any) -> str:
    text = str(surface_id or "").strip()
    return SURFACE_LABELS.get(text, text or "-")


def _failed_result(reason: str, briefing_result: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": False,
        "format": "both",
        "reason": reason,
        "command": [],
        "returncode": 1,
        "stdout": "",
        "stderr": "",
        "briefing_sheets": briefing_result,
        "export": {"ok": False, "reason": reason, "files": [], "file_count": 0, "output_dir": str(output_dir.resolve())},
        "summary": {
            "surface_count": briefing_result.get("surface_count", 0),
            "html_file_count": briefing_result.get("file_count", 0),
            "exported_surface_count": 0,
            "png_count": 0,
            "pdf_count": 0,
            "output_dir": str(output_dir.resolve()),
        },
    }


def _parse_export_stdout(stdout: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"ok": False, "reason": "导出脚本没有返回合法 JSON。", "raw_stdout": stdout, "files": [], "file_count": 0}
    return data if isinstance(data, dict) else {"ok": False, "reason": "导出脚本返回结构不是对象。", "files": [], "file_count": 0}


def _write_export_report(data: dict[str, Any]) -> None:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    (REPORT_ROOT / EXPORT_REPORT_JSON).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    (REPORT_ROOT / EXPORT_REPORT_MARKDOWN).write_text(build_briefing_sheet_export_markdown(data), encoding="utf-8")


def _cleanup_legacy_briefing_outputs() -> None:
    for name in LEGACY_EXPORT_DIR_NAMES:
        _remove_report_path(REPORT_ROOT / name)
    for name in LEGACY_EXPORT_REPORTS:
        _remove_report_path(REPORT_ROOT / name)
    for pattern in ("攻击面答辩单页-*.html", "攻击面答辩单页索引.html"):
        for path in REPORT_ROOT.glob(pattern):
            _remove_report_path(path)


def _reset_output_dir(output_dir: Path) -> None:
    _remove_report_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def _remove_report_path(path: Path) -> None:
    try:
        resolved = path.resolve()
        resolved.relative_to(REPORT_ROOT.resolve())
    except (OSError, ValueError):
        return
    if resolved.is_dir():
        shutil.rmtree(resolved)
    elif resolved.exists():
        resolved.unlink()
