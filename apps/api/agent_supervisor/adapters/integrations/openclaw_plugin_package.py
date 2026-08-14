from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apps.api.agent_supervisor.adapters.integrations.openclaw_plugin_templates import (
    _openclaw_plugin_manifest,
    _openclaw_plugin_package_json,
    _openclaw_plugin_readme,
    _openclaw_plugin_runtime,
    _openclaw_plugin_source,
)
from apps.api.agent_supervisor.paths import SANDBOX_REPORTS_DIR

OPENCLAW_PLUGIN_PACKAGE_LOCK = threading.Lock()
OPENCLAW_PLUGIN_ID = "agent-supervisor-openclaw-guard"


def build_openclaw_plugin_package_files(
    supervisor_url: str = "http://127.0.0.1:8012/api/integrations/openclaw/events",
) -> dict[str, str]:
    return {
        "package.json": _openclaw_plugin_package_json(),
        "openclaw.plugin.json": _openclaw_plugin_manifest(supervisor_url),
        "src/index.ts": _openclaw_plugin_source(supervisor_url),
        "dist/index.js": _openclaw_plugin_runtime(supervisor_url),
        "README.md": _openclaw_plugin_readme(supervisor_url),
    }


def build_openclaw_plugin_package_summary(
    supervisor_url: str = "http://127.0.0.1:8012/api/integrations/openclaw/events",
) -> dict[str, Any]:
    files = build_openclaw_plugin_package_files(supervisor_url)
    runtime = files["dist/index.js"]
    return {
        "name": "agent-supervisor-openclaw-guard",
        "version": "2026.06.08",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package_type": "OpenClaw native plugin",
        "supervisor_url": supervisor_url,
        "core_hooks": ["before_tool_call", "after_tool_call"],
        "decision_mapping": {
            "允许": "放行工具调用，继续执行。",
            "拒绝": "返回 block 决策，强制阻断工具调用，人工无法放行。",
            "询问": "返回 requireApproval 决策，等待人工确认，超时拒绝。",
            "隔离": "返回 block 决策，强制阻断工具调用，人工无法放行。",
        },
        "install_commands": [
            "openclaw plugins install -l apps/api/sandbox/reports/agent-supervisor-openclaw-guard",
            "openclaw plugins enable agent-supervisor-openclaw-guard",
            "openclaw plugins inspect agent-supervisor-openclaw-guard --runtime --json",
        ],
        "runtime_checks": {
            "has_package_openclaw_extensions": '"openclaw"' in files["package.json"] and '"extensions"' in files["package.json"],
            "has_manifest_id": '"id": "agent-supervisor-openclaw-guard"' in files["openclaw.plugin.json"],
            "has_before_tool_call": "api.on" in runtime and '"before_tool_call"' in runtime,
            "has_after_tool_call": "api.on" in runtime and '"after_tool_call"' in runtime,
            "has_fail_closed": "failClosedDecision" in runtime and "timeoutBehavior" in runtime,
            "has_api_token": "apiToken" in runtime and "Authorization" in runtime,
            "risk_hint_default_off": 'emitRiskHint: { type: "boolean", default: false }' in runtime,
            "file_count": len(files),
        },
        "files": [
            {
                "path": path,
                "size": len(content.encode("utf-8")),
            }
            for path, content in files.items()
        ],
    }


def build_openclaw_plugin_package_markdown(
    supervisor_url: str = "http://127.0.0.1:8012/api/integrations/openclaw/events",
) -> str:
    summary = build_openclaw_plugin_package_summary(supervisor_url)
    files = build_openclaw_plugin_package_files(supervisor_url)
    lines = [
        "# OpenClaw 源码级插件包",
        "",
        "该材料把智安哨从“兼容事件接口”推进到 OpenClaw native plugin 形态。插件通过 OpenClaw typed plugin hooks 在工具执行前调用智安哨监督器。",
        "",
        "## 依据的 OpenClaw 接入面",
        "",
        "- `before_tool_call`：工具执行前策略闸门，可阻断或要求人工审批。",
        "- `after_tool_call`：工具执行后观察结果，用于审计补充。",
        "- native plugin 包：包含 `package.json`、`openclaw.plugin.json` 和运行入口。",
        "",
        "## 安装命令",
        "",
        "```powershell",
        *summary["install_commands"],
        "```",
        "",
        "## 决策映射",
        "",
        "| 智安哨决策 | OpenClaw Hook 行为 |",
        "|---|---|",
    ]
    for decision, behavior in summary["decision_mapping"].items():
        lines.append(f"| {decision} | {behavior} |")
    lines.extend(
        [
            "",
            "## 静态验收",
            "",
            "| 检查项 | 结果 |",
            "|---|---|",
        ]
    )
    for key, value in summary["runtime_checks"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(
        [
            "",
            "## 文件清单",
            "",
            "| 文件 | 大小 |",
            "|---|---:|",
        ]
    )
    for item in summary["files"]:
        lines.append(f"| `{item['path']}` | {item['size']} bytes |")
    lines.extend(
        [
            "",
            "## 运行入口预览",
            "",
            "```js",
            files["dist/index.js"],
            "```",
        ]
    )
    return "\n".join(lines)



def write_openclaw_plugin_package(
    output_root: str | Path | None = None,
    supervisor_url: str = "http://127.0.0.1:8012/api/integrations/openclaw/events",
) -> dict[str, Any]:
    with OPENCLAW_PLUGIN_PACKAGE_LOCK:
        root = Path(output_root) if output_root else SANDBOX_REPORTS_DIR
        package_dir = root / "agent-supervisor-openclaw-guard"
        package_dir.mkdir(parents=True, exist_ok=True)
        files = build_openclaw_plugin_package_files(supervisor_url)
        written: list[Path] = []
        for relative, content in files.items():
            path = package_dir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            written.append(path)

        markdown_path = root / "OpenClaw源码级插件包.md"
        markdown_path.write_text(build_openclaw_plugin_package_markdown(supervisor_url), encoding="utf-8")
        written.append(markdown_path)

        zip_path = root / "agent-supervisor-openclaw-guard.zip"
        if zip_path.exists():
            zip_path.unlink()
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for relative in files:
                path = package_dir / relative
                archive.write(path, arcname=f"agent-supervisor-openclaw-guard/{relative}")
            archive.write(markdown_path, arcname="OpenClaw源码级插件包.md")

    summary = build_openclaw_plugin_package_summary(supervisor_url)
    return {
        "generated_at": summary["generated_at"],
        "package_dir": str(package_dir.resolve()),
        "zip_path": str(zip_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "file_count": len(written),
        "summary": summary,
    }


def validate_openclaw_plugin_package(
    output_root: str | Path | None = None,
    supervisor_url: str = "http://127.0.0.1:8012/api/integrations/openclaw/events",
    *,
    inspect_runtime: bool = False,
) -> dict[str, Any]:
    package = write_openclaw_plugin_package(output_root=output_root, supervisor_url=supervisor_url)
    package_dir = Path(package["package_dir"])
    runtime_path = package_dir / "dist" / "index.js"
    required_files = ["package.json", "openclaw.plugin.json", "src/index.ts", "dist/index.js", "README.md"]
    file_checks = {relative: (package_dir / relative).exists() for relative in required_files}
    static_checks = dict(package["summary"]["runtime_checks"])
    node_check = _run_command_check(
        ["node", "--check", str(runtime_path)],
        command_label=f"node --check {runtime_path}",
        missing_message="未检测到 Node.js，无法执行 JavaScript 语法检查。",
    )
    openclaw_cli = shutil.which("openclaw")
    install_command_label = f"openclaw plugins install -l {package_dir}"
    enable_command_label = f"openclaw plugins enable {OPENCLAW_PLUGIN_ID}"
    inspect_command_label = f"openclaw plugins inspect {OPENCLAW_PLUGIN_ID} --runtime --json"
    static_only_reason = "默认只做无副作用静态验收；如需真实 OpenClaw runtime inspect，请启用 inspect_runtime。"
    install_check = _skipped_command_check(install_command_label, static_only_reason, available=bool(openclaw_cli))
    enable_check = _skipped_command_check(enable_command_label, static_only_reason, available=bool(openclaw_cli))
    runtime_check = _skipped_command_check(inspect_command_label, static_only_reason, available=bool(openclaw_cli))
    if inspect_runtime:
        if openclaw_cli:
            install_check = _run_command_check(
                [openclaw_cli, "plugins", "install", "-l", str(package_dir)],
                command_label=install_command_label,
                missing_message="未检测到 OpenClaw CLI，无法安装插件。",
                timeout=180,
            )
            install_check["available"] = True
            enable_check = _run_command_check(
                [openclaw_cli, "plugins", "enable", OPENCLAW_PLUGIN_ID],
                command_label=enable_command_label,
                missing_message="未检测到 OpenClaw CLI，无法启用插件。",
                timeout=180,
            )
            enable_check["available"] = True
            runtime_check = _run_command_check(
                [openclaw_cli, "plugins", "inspect", OPENCLAW_PLUGIN_ID, "--runtime", "--json"],
                command_label=inspect_command_label,
                missing_message="未检测到 OpenClaw CLI，无法执行真实 runtime inspect。",
                timeout=180,
            )
            runtime_check["available"] = True
        else:
            no_cli_reason = "当前环境未安装 OpenClaw CLI；请在安装 OpenClaw 后执行 install、enable 与 inspect 命令。"
            install_check = _skipped_command_check(install_command_label, no_cli_reason)
            enable_check = _skipped_command_check(enable_command_label, no_cli_reason)
            runtime_check = _skipped_command_check(inspect_command_label, no_cli_reason)

    static_passed = all(value is True for key, value in static_checks.items() if key != "file_count")
    files_passed = all(file_checks.values())
    node_passed = node_check["passed"] is True
    contract_check = _run_plugin_contract_check(files=build_openclaw_plugin_package_files(supervisor_url))
    contract_passed = contract_check["passed"] is True
    runtime_passed = _runtime_inspect_passed(runtime_check)
    remaining_gap = []
    if not runtime_passed:
        remaining_gap.append("真实 OpenClaw runtime inspect 尚未通过；需要在已安装 OpenClaw 的环境中安装、启用并检查插件。")
    if not files_passed:
        remaining_gap.append("插件包缺少必要文件。")
    if not node_passed:
        remaining_gap.append("插件运行入口 JavaScript 语法检查未通过或未执行。")
    if not contract_passed:
        remaining_gap.append("插件鉴权、盲测去标签和前置阻断契约端到端检查未通过。")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package_dir": package["package_dir"],
        "zip_path": package["zip_path"],
        "markdown_path": package["markdown_path"],
        "static_passed": static_passed,
        "files_passed": files_passed,
        "node_syntax_passed": node_passed,
        "contract_e2e_passed": contract_passed,
        "runtime_inspect_passed": runtime_passed,
        "openclaw_cli_path": openclaw_cli or "",
        "overall_status": "runtime-validated"
        if static_passed and files_passed and node_passed and contract_passed and runtime_passed
        else "contract-e2e-validated"
        if static_passed and files_passed and node_passed and contract_passed
        else "static-validated"
        if static_passed and files_passed and node_passed
        else "needs-fix",
        "file_checks": file_checks,
        "static_checks": static_checks,
        "node_check": node_check,
        "contract_e2e_check": contract_check,
        "openclaw_install_check": install_check,
        "openclaw_enable_check": enable_check,
        "openclaw_runtime_check": runtime_check,
        "install_commands": package["summary"]["install_commands"],
        "remaining_gap": remaining_gap,
        "package": package,
    }


def write_openclaw_plugin_validation_report(
    output_root: str | Path | None = None,
    supervisor_url: str = "http://127.0.0.1:8012/api/integrations/openclaw/events",
    *,
    inspect_runtime: bool = False,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else SANDBOX_REPORTS_DIR
    root.mkdir(parents=True, exist_ok=True)
    validation = validate_openclaw_plugin_package(
        output_root=root,
        supervisor_url=supervisor_url,
        inspect_runtime=inspect_runtime,
    )
    json_path = root / "OpenClaw源码级插件包验收报告.json"
    markdown_path = root / "OpenClaw源码级插件包验收报告.md"
    json_path.write_text(json.dumps(validation, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_openclaw_plugin_validation_markdown(validation), encoding="utf-8")
    return {
        "generated_at": validation["generated_at"],
        "json_path": str(json_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "validation": validation,
    }


def build_openclaw_plugin_validation_markdown(validation: dict[str, Any] | None = None) -> str:
    validation = validation or validate_openclaw_plugin_package()
    lines = [
        "# OpenClaw 源码级插件包验收报告",
        "",
        f"生成时间：{validation['generated_at']}",
        f"总体状态：`{validation['overall_status']}`",
        "",
        "## 验收结论",
        "",
        f"- 文件完整性：{'通过' if validation['files_passed'] else '未通过'}",
        f"- 静态 Hook 检查：{'通过' if validation['static_passed'] else '未通过'}",
        f"- JavaScript 语法检查：{'通过' if validation['node_syntax_passed'] else '未通过'}",
        f"- 插件鉴权/盲测/阻断契约：{'通过' if validation.get('contract_e2e_passed') else '未通过'}",
        f"- OpenClaw runtime inspect：{'通过' if validation['runtime_inspect_passed'] else '未完成'}",
        "",
        "## 文件检查",
        "",
        "| 文件 | 结果 |",
        "|---|---|",
    ]
    for relative, passed in validation["file_checks"].items():
        lines.append(f"| `{relative}` | {'通过' if passed else '缺失'} |")
    lines.extend(
        [
            "",
            "## 静态检查",
            "",
            "| 检查项 | 结果 |",
            "|---|---|",
        ]
    )
    for key, value in validation["static_checks"].items():
        lines.append(f"| `{key}` | `{value}` |")
    node_check = validation["node_check"]
    contract_check = validation.get("contract_e2e_check") or {}
    openclaw_checks = [
        ("OpenClaw 安装插件", validation.get("openclaw_install_check")),
        ("OpenClaw 启用插件", validation.get("openclaw_enable_check")),
        ("OpenClaw runtime inspect", validation.get("openclaw_runtime_check")),
    ]
    lines.extend(
        [
            "",
            "## 命令检查",
            "",
            f"- JS 语法命令：`{node_check['command']}`",
            f"- JS 语法结果：{'通过' if node_check['passed'] else '未通过'}",
            f"- 契约端到端命令：`{contract_check.get('command', '-')}`",
            f"- 契约端到端结果：{'通过' if contract_check.get('passed') else contract_check.get('stderr') or '未通过'}",
        "",
        ]
    )
    for label, check in openclaw_checks:
        if not check:
            continue
        lines.extend(
            [
                f"- {label} 命令：`{check['command']}`",
                f"- {label} 状态：{'已执行' if check['attempted'] else '未执行'}",
                f"- {label} 结果：{'通过' if check['passed'] else check.get('skipped_reason') or check.get('stderr') or '未通过'}",
            ]
        )
    lines.extend(
        [
            "",
            "## 安装与真实验收命令",
            "",
            "```powershell",
            *validation["install_commands"],
            "```",
            "",
            "## 剩余缺口",
            "",
        ]
    )
    if validation["remaining_gap"]:
        lines.extend(f"- {gap}" for gap in validation["remaining_gap"])
    else:
        lines.append("- 无。")
    return "\n".join(lines)


def _run_plugin_contract_check(*, files: dict[str, str]) -> dict[str, Any]:
    harness = r'''
import http from "node:http";
import plugin from "./plugin.js";

const hooks = {};
plugin.register({
  on(name, handler) {
    hooks[name] = handler;
  },
});

const received = [];
const server = http.createServer(async (request, response) => {
  let raw = "";
  for await (const chunk of request) raw += chunk;
  const body = JSON.parse(raw || "{}");
  received.push({ authorization: request.headers.authorization || "", body });
  const path = String(body?.tool_call?.arguments?.path || "");
  const blocked = path.includes("confidential");
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify({
    decision: blocked ? "拒绝" : "允许",
    policy_id: blocked ? "path-boundary" : "default-allow",
    reason: blocked ? "sensitive path" : "allowed",
  }));
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
const pluginConfig = {
  supervisorUrl: `http://127.0.0.1:${address.port}`,
  apiToken: "contract-token",
  emitRiskHint: false,
};
const blocked = await hooks.before_tool_call({
  toolName: "file_read",
  params: { path: "confidential/records.csv" },
  context: { pluginConfig, sessionKey: "contract-attack" },
});
const allowed = await hooks.before_tool_call({
  toolName: "file_read",
  params: { path: "public/readme.md" },
  context: { pluginConfig, sessionKey: "contract-benign" },
});
await hooks.after_tool_call({
  toolName: "file_read",
  params: { path: "public/readme.md" },
  result: "ok",
  context: { pluginConfig, sessionKey: "contract-benign" },
});
await new Promise((resolve) => server.close(resolve));

const result = {
  hooks_registered: Boolean(hooks.before_tool_call && hooks.after_tool_call),
  authenticated: received.length === 3 && received.every((item) => item.authorization === "Bearer contract-token"),
  risk_hint_absent: received.every((item) => !("risk_hint" in (item.body.tool_call || {}))),
  attack_blocked: blocked?.block === true,
  benign_allowed: allowed === undefined,
  request_count: received.length,
};
result.passed = Object.entries(result).every(([key, value]) => key === "request_count" || value === true);
console.log(JSON.stringify(result));
'''.strip()
    with tempfile.TemporaryDirectory(prefix="agent-supervisor-openclaw-contract-") as temp_dir:
        root = Path(temp_dir)
        openclaw_root = root / "node_modules" / "openclaw"
        sdk_root = openclaw_root / "plugin-sdk"
        sdk_root.mkdir(parents=True, exist_ok=True)
        (root / "package.json").write_text('{"type":"module"}', encoding="utf-8")
        (openclaw_root / "package.json").write_text(
            json.dumps(
                {
                    "name": "openclaw",
                    "type": "module",
                    "exports": {"./plugin-sdk/plugin-entry": "./plugin-sdk/plugin-entry.js"},
                }
            ),
            encoding="utf-8",
        )
        (sdk_root / "plugin-entry.js").write_text("export function definePluginEntry(value) { return value; }", encoding="utf-8")
        (root / "plugin.js").write_text(files["dist/index.js"], encoding="utf-8")
        harness_path = root / "contract-test.mjs"
        harness_path.write_text(harness, encoding="utf-8")
        check = _run_command_check(
            ["node", str(harness_path)],
            command_label="node OpenClaw plugin contract-test.mjs",
            missing_message="未检测到 Node.js，插件契约端到端检查未执行。",
            timeout=30,
        )
    details: dict[str, Any] = {}
    if check.get("passed"):
        try:
            details = json.loads(str(check.get("stdout", "")).strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            details = {"passed": False, "error": "契约检查没有返回有效 JSON。"}
    check["details"] = details
    check["passed"] = bool(check.get("passed") and details.get("passed"))
    return check


def _skipped_command_check(command_label: str, skipped_reason: str, *, available: bool = False) -> dict[str, Any]:
    return {
        "attempted": False,
        "available": available,
        "passed": None,
        "command": command_label,
        "stdout": "",
        "stderr": "",
        "skipped_reason": skipped_reason,
    }


def _run_command_check(
    command: list[str],
    *,
    command_label: str,
    missing_message: str,
    timeout: int = 90,
) -> dict[str, Any]:
    executable = shutil.which(command[0]) if command else None
    if not executable:
        return {
            "attempted": False,
            "available": False,
            "passed": None,
            "command": command_label,
            "stdout": "",
            "stderr": missing_message,
            "skipped_reason": missing_message,
        }
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - validation should report failures, not crash packaging
        return {
            "attempted": True,
            "available": True,
            "passed": False,
            "command": command_label,
            "stdout": "",
            "stderr": str(exc),
            "skipped_reason": "",
        }
    return {
        "attempted": True,
        "available": True,
        "passed": completed.returncode == 0,
        "command": command_label,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "skipped_reason": "",
    }


def _runtime_inspect_passed(runtime_check: dict[str, Any]) -> bool:
    if runtime_check.get("passed") is not True:
        return False
    try:
        payload = json.loads(str(runtime_check.get("stdout") or "{}"))
    except json.JSONDecodeError:
        return False
    plugin = payload.get("plugin") if isinstance(payload, dict) else {}
    raw_typed_hooks = payload.get("typedHooks") if isinstance(payload, dict) else []
    typed_hooks = raw_typed_hooks if isinstance(raw_typed_hooks, list) else []
    hook_names = {str(item.get("name")) for item in typed_hooks if isinstance(item, dict)}
    return (
        isinstance(plugin, dict)
        and plugin.get("id") == OPENCLAW_PLUGIN_ID
        and plugin.get("status") == "loaded"
        and plugin.get("enabled") is True
        and "before_tool_call" in hook_names
    )
