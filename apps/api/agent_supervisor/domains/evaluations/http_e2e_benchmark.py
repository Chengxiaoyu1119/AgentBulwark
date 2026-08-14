from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, sleep
from typing import Any

from apps.api.agent_supervisor.paths import REPO_ROOT, SANDBOX_REPORTS_DIR

API_TOKEN = "benchmark-local-token"
HMAC_KEY = "benchmark-local-hmac-key"


def write_http_e2e_benchmark_report(
    output_root: str | Path | None = None,
    *,
    call_count: int = 200,
    concurrency: int = 20,
) -> dict[str, Any]:
    root = Path(output_root) if output_root else SANDBOX_REPORTS_DIR
    root.mkdir(parents=True, exist_ok=True)
    calls = max(1, call_count)
    workers = max(1, concurrency)

    with tempfile.TemporaryDirectory(prefix="agent-supervisor-e2e-") as temp_dir:
        runtime_dir = Path(temp_dir)
        port = _available_port()
        process = _start_server(runtime_dir, port)
        try:
            _wait_until_ready(process, port)
            unauthorized_status = _request_json(port, _event(0), token="")["status"]
            authenticated_status = _health_status(port)
            tasks = [_event(index) for index in range(calls)]
            started = perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                records = list(pool.map(lambda event: _timed_request(port, event), tasks))
            elapsed = perf_counter() - started
        finally:
            _stop_server(process)

        database_path = runtime_dir / "agent_supervisor.sqlite3"
        persistence = _inspect_database(database_path)
        database_artifact = root / "HTTP-SQLite-审计完整链路性能评测.sqlite3"
        shutil.copy2(database_path, database_artifact)

    successes = [item for item in records if item["status"] == 200]
    latencies = [float(item["latency_ms"]) for item in records]
    data = {
        "schema_version": "agent-supervisor.http-e2e-benchmark.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": ["HTTP", "Bearer Token 鉴权", "监督决策", "SQLite 写入", "审计 hash", "HMAC 签名"],
        "method": {
            "endpoint": "/api/runtime/evaluate",
            "server": "真实本地 uvicorn 子进程",
            "database": "隔离临时 SQLite；完成后复制为证据文件",
            "risk_hint_used": False,
            "external_agent_network_time_included": False,
            "acceptance": {"success_rate": 100, "throughput_per_second_min": 50, "p95_latency_ms_max": 1500},
        },
        "security": {
            "auth_disabled": False,
            "unauthorized_status": unauthorized_status,
            "authenticated_status": authenticated_status,
            "hmac_enabled": True,
        },
        "performance": {
            "call_count": calls,
            "success_count": len(successes),
            "failure_count": calls - len(successes),
            "concurrency": workers,
            "elapsed_seconds": round(elapsed, 4),
            "throughput_per_second": round(calls / elapsed, 2) if elapsed else 0,
            "latency_ms": _latency_summary(latencies),
        },
        "persistence": persistence,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
        },
        "errors": [item for item in records if item["status"] != 200][:10],
        "database_artifact": str(database_artifact.resolve()),
    }
    json_path = root / "HTTP-SQLite-审计完整链路性能评测.json"
    markdown_path = root / "HTTP-SQLite-审计完整链路性能评测.md"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(build_http_e2e_benchmark_markdown(data), encoding="utf-8")
    return {
        "json_path": str(json_path.resolve()),
        "markdown_path": str(markdown_path.resolve()),
        "database_path": str(database_artifact.resolve()),
        "benchmark": data,
    }


def build_http_e2e_benchmark_markdown(data: dict[str, Any]) -> str:
    performance = data["performance"]
    persistence = data["persistence"]
    security = data["security"]
    latency = performance["latency_ms"]
    return "\n".join(
        [
            "# HTTP、SQLite 与审计完整链路性能评测",
            "",
            "> 本报告测量真实本地 HTTP 服务链路，包含 Token 鉴权、监督决策、SQLite 写入、审计 hash 与 HMAC 签名；不包含外部模型网络耗时。",
            "",
            "## 结果",
            "",
            f"- 请求：{performance['call_count']}，成功：{performance['success_count']}，失败：{performance['failure_count']}",
            f"- 并发：{performance['concurrency']}，吞吐：{performance['throughput_per_second']} 次/秒",
            f"- 延迟 P50/P95/P99：{latency['p50']} / {latency['p95']} / {latency['p99']} ms",
            f"- SQLite 运行记录：{persistence['run_count']}，审计记录：{persistence['audit_log_count']}",
            f"- 审计 hash：{persistence['audit_hash_count']}，HMAC 签名：{persistence['audit_signature_count']}",
            "",
            "## 鉴权断言",
            "",
            f"- 无 Token 请求状态码：{security['unauthorized_status']}",
            f"- 有 Token 健康检查状态码：{security['authenticated_status']}",
            "",
            "## 证据边界",
            "",
            "- 使用隔离临时数据库，不污染演示数据库和人工复核队列。",
            "- 请求体不包含 risk_hint，避免把标签直接泄露给检测器。",
            "- 数据库副本随 JSON 和 Markdown 报告一并保留，便于复核审计记录。",
        ]
    )


def _event(index: int) -> dict[str, Any]:
    variants = (
        ("file.read", {"path": f"public/reference-{index % 20}.md"}, "读取公开项目资料。"),
        ("file.read", {"path": "confidential/competition-teams.csv"}, "读取受保护参赛材料。"),
        ("api.call", {"endpoint": f"/projects/public/{index % 20}", "method": "GET"}, "查询公开项目状态。"),
        ("mail.send", {"to": f"outside-{index}@example.net", "subject": "摘要", "body": "项目摘要"}, "发送外部摘要。"),
    )
    tool, arguments, prompt = variants[index % len(variants)]
    return {
        "conversation_id": f"http-e2e-{index:04d}",
        "agent_id": "http-e2e-agent",
        "agent_role": "executor",
        "source_app": "HttpE2EBenchmark",
        "model_input": prompt,
        "model_output": f"准备调用 {tool}。",
        "tool_call": {"tool": tool, "arguments": arguments},
        "context_sources": ["user", "agent-plan"],
        "guard_enabled": True,
        "execute_in_sandbox": False,
    }


def _timed_request(port: int, event: dict[str, Any]) -> dict[str, Any]:
    started = perf_counter()
    response = _request_json(port, event, token=API_TOKEN)
    latency = (perf_counter() - started) * 1000
    body = response.get("body", {})
    audit_log = body.get("audit_log", {}) if isinstance(body, dict) else {}
    return {
        "status": response["status"],
        "latency_ms": round(latency, 3),
        "decision": body.get("decision") if isinstance(body, dict) else None,
        "audit_hash": audit_log.get("audit_hash") if isinstance(audit_log, dict) else None,
        "error": response.get("error", ""),
    }


def _request_json(port: int, event: dict[str, Any], *, token: str) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/runtime/evaluate",
        data=json.dumps(event, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {"status": response.status, "body": json.loads(response.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": {}, "error": exc.read().decode("utf-8", errors="replace")[:300]}
    except (OSError, TimeoutError) as exc:
        return {"status": 0, "body": {}, "error": str(exc)[:300]}


def _health_status(port: int) -> int:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/health",
        headers={"Authorization": f"Bearer {API_TOKEN}"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status


def _start_server(runtime_dir: Path, port: int) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env.update(
        {
            "AGENT_SUPERVISOR_RUNTIME_DIR": str(runtime_dir),
            "AGENT_SUPERVISOR_AUTH_DISABLED": "false",
            "AGENT_SUPERVISOR_AGENT_TOKENS_JSON": json.dumps({"http-e2e-agent": API_TOKEN}),
            "AGENT_SUPERVISOR_AUDIT_HMAC_KEY": HMAC_KEY,
            "AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID": "benchmark-v1",
            "AGENT_SUPERVISOR_API_HOST": "127.0.0.1",
            "PYTHONUTF8": "1",
        }
    )
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "apps.api.agent_supervisor.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _wait_until_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = perf_counter() + 20
    while perf_counter() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"完整链路评测服务启动失败，退出码 {process.returncode}")
        try:
            if _health_status(port) == 200:
                return
        except (OSError, urllib.error.URLError):
            sleep(0.1)
    raise TimeoutError("完整链路评测服务在 20 秒内未就绪")


def _stop_server(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _inspect_database(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "run_count": 0,
            "audit_log_count": 0,
            "audit_hash_count": 0,
            "audit_signature_count": 0,
            "database_bytes": 0,
        }
    with sqlite3.connect(path) as conn:
        run_count = int(conn.execute("SELECT COUNT(*) FROM experiment_runs").fetchone()[0])
        rows = conn.execute("SELECT payload FROM audit_logs").fetchall()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    logs = [json.loads(row[0]) for row in rows]
    return {
        "run_count": run_count,
        "audit_log_count": len(logs),
        "audit_hash_count": sum(1 for item in logs if item.get("audit_hash")),
        "audit_signature_count": sum(1 for item in logs if item.get("audit_signature")),
        "database_bytes": path.stat().st_size,
    }


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": _percentile(values, 0.50),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "max": round(max(values), 3) if values else 0,
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return round(ordered[index], 3)
