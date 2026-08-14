"""stdio 上游 MCP 客户端：子进程 + 换行分隔 JSON-RPC 2.0。

MCP stdio 传输约定：每条 JSON-RPC 消息独占一行（UTF-8）。
后台线程负责读取上游输出并按 id 关联请求响应，通知类消息进入待处理队列。
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from typing import Any


class StdioUpstreamError(RuntimeError):
    """上游 MCP Server 通信失败。"""


class StdioMcpUpstream:
    """与真实 MCP Server 子进程通信的最小 stdio JSON-RPC 客户端。"""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        extra_env: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not command:
            raise StdioUpstreamError("上游 MCP Server 启动命令为空。")
        self._command = list(command)
        self._cwd = cwd
        self._extra_env = dict(extra_env or {})
        self._timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._inbox: queue.Queue[dict[str, Any]] = queue.Queue()
        self._reader: threading.Thread | None = None
        self._next_id = 0

    # -- 生命周期 -----------------------------------------------------------

    @property
    def started(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        if self.started:
            return
        env = {**os.environ, **self._extra_env}
        try:
            self._proc = subprocess.Popen(
                self._command,
                cwd=self._cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:  # 命令不存在 / 无执行权限
            raise StdioUpstreamError(f"无法启动上游 MCP Server：{exc}") from exc
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        self._reader = None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _ensure_started(self) -> None:
        if not self.started:
            self.start()

    # -- 读写 ---------------------------------------------------------------

    def _reader_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                self._inbox.put(message)
        self._inbox.put({"__upstream_closed__": True})

    def _write_line(self, payload: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise StdioUpstreamError("上游 MCP Server 未运行。")
        proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        proc.stdin.flush()

    def _allocate_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _wait_response(self, request_id: int, timeout: float) -> dict[str, Any]:
        deadline_timeout = timeout or self._timeout
        while True:
            try:
                message = self._inbox.get(timeout=deadline_timeout)
            except queue.Empty as exc:
                raise StdioUpstreamError(f"上游 MCP Server 响应超时（id={request_id}）。") from exc
            if message.get("__upstream_closed__"):
                raise StdioUpstreamError("上游 MCP Server 已退出。")
            if message.get("id") == request_id and ("result" in message or "error" in message):
                return message
            # 服务端通知或无关消息：丢弃（v1 不处理上游主动请求）。

    # -- 对外接口 -----------------------------------------------------------

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        client_id: Any = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """发送请求并返回响应；响应 id 还原为调用方的 client_id。"""
        with self._lock:
            self._ensure_started()
            request_id = self._allocate_id()
            payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
            if params is not None:
                payload["params"] = params
            self._write_line(payload)
            response = self._wait_response(request_id, timeout or self._timeout)
        if client_id is not None:
            response["id"] = client_id
        return response

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._ensure_started()
            payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                payload["params"] = params
            self._write_line(payload)


def new_upstream_from_config() -> StdioMcpUpstream | None:
    """按环境变量构造上游客户端；未配置时返回 None。"""
    from apps.api.agent_supervisor.mcp_gateway.config import gateway_timeout_seconds, upstream_command, upstream_cwd

    command = upstream_command()
    if not command:
        return None
    return StdioMcpUpstream(command, cwd=upstream_cwd(), timeout=gateway_timeout_seconds())
