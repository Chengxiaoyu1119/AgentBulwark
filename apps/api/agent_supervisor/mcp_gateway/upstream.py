"""stdio 上游 MCP 客户端：子进程 + 换行分隔 JSON-RPC 2.0。

MCP stdio 传输约定：每条 JSON-RPC 消息独占一行（UTF-8）。
后台线程负责读取上游输出并按 id 关联请求响应，通知类消息进入待处理队列。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from collections import OrderedDict, deque
from time import monotonic
from typing import Any, Callable, cast

from apps.api.agent_supervisor.mcp_gateway.http_transport import log_level_allows

NOTIFICATION_BUFFER_SIZE = 200
DEFAULT_MAX_MESSAGE_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_PENDING_RESPONSES = 256
DEFAULT_MAX_MEMORY_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_CPU_SECONDS = 30
DEFAULT_MAX_PIDS = 128
DEFAULT_MAX_OPEN_FILES = 256
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_UPSTREAM_ENV_KEYS = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "NODE_PATH",
        "NPM_CONFIG_PREFIX",
        "PATH",
        "PATHEXT",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
        "XDG_CONFIG_HOME",
    }
)
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class StdioUpstreamError(RuntimeError):
    """上游 MCP Server 通信失败。"""


class StdioUpstreamServerRequest(StdioUpstreamError):
    """上游在等待客户端输入时发出的旧版 server→client 请求。"""

    def __init__(self, message: dict[str, Any], *, parent_request_id: int) -> None:
        self.message = message
        self.parent_request_id = parent_request_id
        super().__init__("上游 MCP Server 请求了现代 MRTR 输入。")


class StdioMcpUpstream:
    """与真实 MCP Server 子进程通信的最小 stdio JSON-RPC 客户端。"""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        extra_env: dict[str, str] | None = None,
        timeout: float = 10.0,
        max_message_bytes: int | None = None,
        max_pending_responses: int | None = None,
        resource_limits_enabled: bool | None = None,
    ) -> None:
        if not command:
            raise StdioUpstreamError("上游 MCP Server 启动命令为空。")
        self._command = list(command)
        self._cwd = cwd
        self._extra_env = dict(extra_env or {})
        self._timeout = timeout
        self._max_message_bytes = max_message_bytes or _env_int(
            "MCP_GATEWAY_MAX_MESSAGE_BYTES", DEFAULT_MAX_MESSAGE_BYTES, minimum=16 * 1024, maximum=16 * 1024 * 1024
        )
        self._max_pending_responses = max_pending_responses or _env_int(
            "MCP_GATEWAY_MAX_PENDING_RESPONSES", DEFAULT_MAX_PENDING_RESPONSES, minimum=16, maximum=4096
        )
        self._resource_limits_enabled = (
            _env_bool("MCP_GATEWAY_RESOURCE_LIMITS_ENABLED", True)
            if resource_limits_enabled is None
            else resource_limits_enabled
        )
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        # Requests may be issued concurrently by separate Agent sessions. A
        # plain FIFO queue can lose an out-of-order response when waiter A
        # removes waiter B's message, so responses are demultiplexed by id.
        self._responses: dict[int, dict[str, Any]] = {}
        self._response_condition = threading.Condition()
        self._upstream_closed = False
        self._notifications: deque[dict[str, Any]] = deque(maxlen=NOTIFICATION_BUFFER_SIZE)
        self._server_request_events: dict[int, deque[dict[str, Any]]] = {}
        self._inflight_capture: "OrderedDict[int, bool]" = OrderedDict()
        self._notification_sinks: dict[int, tuple[Callable[[dict[str, Any]], None], Any, str | None]] = {}
        self._reader: threading.Thread | None = None
        self._next_id = 0
        self._reader_error = ""
        self._job_handle: Any = None

    # -- 生命周期 -----------------------------------------------------------

    @property
    def started(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def clone(self) -> "StdioMcpUpstream":
        """Create an unstarted upstream with the same bounded configuration.

        A single stdio MCP process is a stateful trust boundary: its initialized
        session, environment and in-memory resources belong to whoever opened
        the process.  The production gateway uses this method to create one
        child per authenticated Agent session.  The clone deliberately copies
        configuration only; pipes, response buffers and process handles never
        cross the boundary.
        """

        return StdioMcpUpstream(
            self._command,
            cwd=self._cwd,
            extra_env=self._extra_env,
            timeout=self._timeout,
            max_message_bytes=self._max_message_bytes,
            max_pending_responses=self._max_pending_responses,
            resource_limits_enabled=self._resource_limits_enabled,
        )

    def start(self) -> None:
        if self.started:
            return
        with self._response_condition:
            self._upstream_closed = False
            self._responses.clear()
            self._reader_error = ""
        env = _build_upstream_env(self._extra_env)
        try:
            popen_kwargs: dict[str, Any] = {
                "cwd": self._cwd,
                "env": env,
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
                "text": True,
                "encoding": "utf-8",
                "bufsize": 1,
            }
            # A gateway must own the complete child lifecycle.  POSIX uses a
            # process group plus resource.setrlimit; Windows uses a Job Object
            # so memory, CPU and process-count limits are enforced by the OS
            # rather than merely reported as configuration.
            if os.name == "nt":
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                popen_kwargs["start_new_session"] = True
                if self._resource_limits_enabled:
                    preexec_fn = _build_resource_limiter()
                    if preexec_fn is not None:
                        popen_kwargs["preexec_fn"] = preexec_fn
            self._proc = subprocess.Popen(self._command, **popen_kwargs)
            if os.name == "nt" and self._resource_limits_enabled:
                try:
                    self._job_handle = _attach_windows_job_object(self._proc)
                except Exception as exc:  # noqa: BLE001 - fail closed on missing OS isolation
                    _terminate_process_tree(self._proc)
                    try:
                        self._proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self._proc.kill()
                    self._proc = None
                    raise StdioUpstreamError(f"Windows MCP 上游缺少 Job Object 隔离：{exc}") from exc
        except OSError as exc:  # 命令不存在 / 无执行权限
            raise StdioUpstreamError(f"无法启动上游 MCP Server：{exc}") from exc
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    def close(self) -> None:
        proc = self._proc
        job_handle = self._job_handle
        self._proc = None
        self._job_handle = None
        self._reader = None
        if job_handle is not None:
            _terminate_windows_job_object(job_handle)
        if proc is not None and proc.poll() is None:
            _terminate_process_tree(proc)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc is not None:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        with self._response_condition:
            self._upstream_closed = True
            self._response_condition.notify_all()

    def _ensure_started(self) -> None:
        if not self.started:
            self.start()

    # -- 读写 ---------------------------------------------------------------

    def _request_notification_sink(self, message: dict[str, Any]) -> Callable[[dict[str, Any]], None] | None:
        """Resolve only an unambiguous, request-authorized notification sink.

        Legacy stdio log notifications carry no parent request id. They are
        therefore safe to bridge only while exactly one upstream request is in
        flight and that request opted in with a valid per-request ``logLevel``.
        """

        method = str(message.get("method") or "")
        raw_params = message.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        if method == "notifications/progress":
            progress_token = params.get("progressToken")
            matches = [
                callback
                for callback, expected_token, _ in self._notification_sinks.values()
                if _same_jsonrpc_scalar(progress_token, expected_token)
            ]
            # A duplicated client token does not identify one request stream.
            # Drop the notification instead of leaking it into whichever
            # matching stream happened to be registered first.
            return matches[0] if len(matches) == 1 else None
        if method != "notifications/message" or len(self._inflight_capture) != 1:
            return None
        request_id = next(iter(self._inflight_capture))
        sink_entry = self._notification_sinks.get(request_id)
        if sink_entry is None:
            return None
        callback, _, minimum_level = sink_entry
        return callback if log_level_allows(minimum_level, params.get("level")) else None

    def _reader_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            with self._response_condition:
                self._reader_error = "上游 MCP 输出管道不可用。"
                self._upstream_closed = True
                self._response_condition.notify_all()
            return
        # ``TextIOWrapper.readline(size)`` may return a partial line when the
        # upstream frame is larger than ``size``.  Treating that partial chunk
        # as a complete JSON-RPC message silently discards the rest of the
        # frame and turns an oversized-response violation into a timeout.  Keep
        # one bounded accumulator until the newline arrives so every frame is
        # measured in encoded bytes and rejected deterministically.
        pending_line = ""
        pending_bytes = 0
        while True:
            # The size argument bounds each read allocation.  The accumulator
            # below enforces the total frame bound even when the OS splits one
            # line across several reads.
            piece = self._read_stdout_piece(proc)
            if piece is None:
                return
            if not piece:
                break
            if not isinstance(piece, str):
                self._fail_reader("上游 MCP 输出管道返回了非文本数据。", proc)
                return
            pending_line += piece
            pending_bytes += len(piece.encode("utf-8", errors="replace"))
            if pending_bytes > self._max_message_bytes:
                self._fail_reader(f"上游 MCP 消息超过 {self._max_message_bytes} 字节上限。", proc)
                return
            # A newline is part of the bounded wire frame (the writer checks
            # the encoded payload including its trailing newline).  If the
            # accumulator has already reached the limit without a newline,
            # any valid terminator would exceed the limit; fail without
            # waiting on a peer that may keep the pipe open forever.
            if not piece.endswith("\n"):
                if pending_bytes >= self._max_message_bytes:
                    self._fail_reader(f"上游 MCP 消息超过 {self._max_message_bytes} 字节上限。", proc)
                    return
                continue
            line = pending_line.strip()
            pending_line = ""
            pending_bytes = 0
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message and "id" not in message:
                # 上行通知（如 notifications/tools/list_changed）进入缓冲区
                self._notifications.append(message)
                with self._response_condition:
                    sink = self._request_notification_sink(message)
                if sink is not None:
                    try:
                        sink(message)
                    except Exception:
                        # A progress observer is best-effort; the actual MCP
                        # response and audit chain remain authoritative.
                        pass
                continue
            if "method" in message and "id" in message:
                ambiguous = False
                with self._response_condition:
                    inflight = list(self._inflight_capture.items())
                    captured = [request_id for request_id, capture in inflight if capture]
                    if not captured:
                        should_reply = True
                        parent_id = None
                    elif len(inflight) == 1 and len(captured) == 1:
                        should_reply = False
                        parent_id = captured[0]
                        self._server_request_events.setdefault(parent_id, deque()).append(message)
                    else:
                        # MCP server→client requests do not carry the parent
                        # client request id.  With more than one in-flight
                        # request there is no safe owner; never guess and leak
                        # one Agent's input into another request.
                        should_reply = False
                        parent_id = None
                        ambiguous = True
                    self._response_condition.notify_all()
                if ambiguous:
                    self._fail_reader(
                        "上游 MCP server→client 请求无法安全归属到唯一未决请求；已终止上游。",
                        proc,
                    )
                    return
                # Legacy calls retain the established automatic error reply.
                # Modern bridge calls set ``capture_server_requests`` and let
                # the request waiter project the event into input_required.
                if should_reply:
                    self._reply_server_request(message)
                continue
            if "id" not in message or not ("result" in message or "error" in message):
                continue
            try:
                response_id = int(message["id"])
            except (TypeError, ValueError):
                continue
            overflow = False
            with self._response_condition:
                if response_id not in self._responses and len(self._responses) >= self._max_pending_responses:
                    self._reader_error = f"上游 MCP 响应缓存超过 {self._max_pending_responses} 条上限。"
                    self._upstream_closed = True
                    overflow = True
                else:
                    self._responses[response_id] = message
                self._response_condition.notify_all()
            if overflow:
                _terminate_process_tree(proc)
                return
        with self._response_condition:
            self._upstream_closed = True
            self._response_condition.notify_all()

    def _read_stdout_piece(self, proc: subprocess.Popen[str]) -> str | None:
        """Read one bounded UTF-8 chunk and converge pipe errors immediately."""
        stdout = proc.stdout
        if stdout is None:
            self._fail_reader("上游 MCP 输出管道不可用。", proc)
            return None
        try:
            return stdout.readline(self._max_message_bytes + 1)
        except UnicodeError as exc:
            self._fail_reader(f"上游 MCP 输出不是有效 UTF-8（{type(exc).__name__}）。", proc)
        except (OSError, ValueError) as exc:
            self._fail_reader(f"读取上游 MCP 输出管道失败（{type(exc).__name__}）。", proc)
        except Exception as exc:  # noqa: BLE001 - reader must wake waiters on any pipe failure
            self._fail_reader(f"读取上游 MCP 输出失败（{type(exc).__name__}）。", proc)
        return None

    def _fail_reader(self, reason: str, proc: subprocess.Popen[str]) -> None:
        with self._response_condition:
            self._reader_error = reason
            self._upstream_closed = True
            self._response_condition.notify_all()
        if proc.poll() is None:
            _terminate_process_tree(proc)

    def _reply_server_request(self, message: dict[str, Any]) -> None:
        try:
            with self._lock:
                self._write_line(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32601,
                            "message": "智垒 MCP Gateway 不支持上游主动请求。",
                        },
                    }
                )
        except (StdioUpstreamError, OSError):
            pass  # 进程已退出时无需应答

    def notifications(self) -> list[dict[str, Any]]:
        """读取并清空已缓冲的上行通知。"""
        drained = list(self._notifications)
        self._notifications.clear()
        return drained

    def _write_line(self, payload: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise StdioUpstreamError("上游 MCP Server 未运行。")
        try:
            encoded = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            if len(encoded) > self._max_message_bytes:
                raise StdioUpstreamError(f"发送到上游的 MCP 消息超过 {self._max_message_bytes} 字节上限。")
            proc.stdin.write(encoded.decode("utf-8"))
            proc.stdin.flush()
        except StdioUpstreamError:
            raise
        except (UnicodeError, OSError, ValueError) as exc:
            self._fail_reader(f"写入上游 MCP 管道失败（{type(exc).__name__}）。", proc)
            raise StdioUpstreamError("写入上游 MCP 管道失败。") from exc

    def _allocate_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _wait_response(
        self,
        request_id: int,
        timeout: float,
        *,
        server_request_handler: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
        cancel_event: Any = None,
    ) -> dict[str, Any]:
        deadline = monotonic() + (timeout or self._timeout)
        while True:
            if cancel_event is not None and cancel_event.is_set():
                self._send_cancelled(request_id)
                raise StdioUpstreamError("MCP 请求已取消。")
            server_request: dict[str, Any] | None = None
            with self._response_condition:
                message = self._responses.pop(request_id, None)
                if message is not None:
                    return message
                queued = self._server_request_events.get(request_id)
                if queued:
                    server_request = queued.popleft()
                    if not queued:
                        self._server_request_events.pop(request_id, None)
                if self._reader_error:
                    raise StdioUpstreamError(self._reader_error)
                if self._upstream_closed:
                    raise StdioUpstreamError("上游 MCP Server 已退出。")
                if server_request is None:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise StdioUpstreamError(f"上游 MCP Server 响应超时（id={request_id}）。")
                    self._response_condition.wait(timeout=min(remaining, 0.1))
                    continue
            # Invoke a potentially blocking MRTR callback after releasing the
            # reader condition. This keeps progress and final response frames
            # flowing while the HTTP client is deciding what to return.
            if server_request_handler is None:
                raise StdioUpstreamServerRequest(server_request, parent_request_id=request_id)
            response = server_request_handler(server_request)
            if response is None:
                # The handler returns ``None`` both for unsupported server
                # requests and when a request-scoped HTTP stream is cancelled.
                # In the latter case the loop does not reach its top-of-loop
                # cancellation check again, so emit the MCP cancellation
                # notification here before surfacing the deterministic error.
                if cancel_event is not None and cancel_event.is_set():
                    self._send_cancelled(request_id)
                    raise StdioUpstreamError("MCP 请求已取消。")
                raise StdioUpstreamServerRequest(server_request, parent_request_id=request_id)
            self.respond_to_server_request(server_request, response)

    # -- 对外接口 -----------------------------------------------------------

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        client_id: Any = None,
        timeout: float | None = None,
        capture_server_requests: bool = False,
        server_request_handler: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
        notification_sink: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: Any = None,
    ) -> dict[str, Any]:
        """发送请求并返回响应；响应 id 还原为调用方的 client_id。

        注意：等待响应在锁外进行，避免 reader 线程需要拿锁应答上游
        主动请求时与主线程互等（死锁）。
        """
        # ``_ensure_started`` and ``_write_line`` can fail before an id is
        # allocated (for example when the configured executable is missing).
        # Initialise the local up front so the cleanup path never masks the
        # original, actionable upstream error with ``UnboundLocalError``.
        request_id: int | None = None
        try:
            with self._lock:
                self._ensure_started()
                request_id = self._allocate_id()
                payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
                if params is not None:
                    payload["params"] = params
                with self._response_condition:
                    self._inflight_capture[request_id] = bool(capture_server_requests)
                    if notification_sink is not None:
                        raw_metadata = params.get("_meta") if isinstance(params, dict) else None
                        metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
                        raw_log_level = metadata.get("io.modelcontextprotocol/logLevel")
                        log_level = raw_log_level if isinstance(raw_log_level, str) else None
                        self._notification_sinks[request_id] = (
                            notification_sink,
                            metadata.get("progressToken"),
                            log_level,
                        )
                self._write_line(payload)
            response = self._wait_response(
                request_id,
                timeout or self._timeout,
                server_request_handler=server_request_handler if capture_server_requests else None,
                cancel_event=cancel_event,
            )
        finally:
            if request_id is not None:
                with self._response_condition:
                    self._inflight_capture.pop(request_id, None)
                    self._server_request_events.pop(request_id, None)
                    self._notification_sinks.pop(request_id, None)
        if client_id is not None:
            response["id"] = client_id
        return response

    def _send_cancelled(self, request_id: int) -> None:
        """Best-effort MCP cancellation for a disconnected HTTP stream."""

        try:
            with self._lock:
                if self.started:
                    self._write_line(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": {"requestId": request_id, "reason": "client-disconnected"},
                        }
                    )
        except (StdioUpstreamError, OSError):
            # The reader/child may already have exited; the waiting caller is
            # still given a deterministic cancellation error.
            pass

    def respond_to_server_request(self, message: dict[str, Any], response: dict[str, Any]) -> None:
        """Reply to a captured legacy server request without exposing it upstream."""
        request_id = message.get("id")
        if request_id is None:
            raise StdioUpstreamError("上游 server request 缺少 id。")
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        if "error" in response:
            payload["error"] = response["error"]
        else:
            payload["result"] = response.get("result", response)
        with self._lock:
            self._write_line(payload)

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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _build_resource_limiter() -> Any:
    """Return a POSIX pre-exec hook with conservative MCP child limits.

    The hook is intentionally optional: Windows has no ``resource`` module,
    and an unsupported limit must never prevent a normal MCP server from
    starting.  Unsupported individual limits are skipped independently.
    """
    try:
        import resource
    except ImportError:
        return None
    resource_module = cast(Any, resource)

    cpu_seconds = _env_int("MCP_GATEWAY_MAX_CPU_SECONDS", DEFAULT_MAX_CPU_SECONDS, minimum=1, maximum=300)
    memory_bytes = _env_int("MCP_GATEWAY_MAX_MEMORY_BYTES", DEFAULT_MAX_MEMORY_BYTES, minimum=64 * 1024 * 1024, maximum=4 * 1024 * 1024 * 1024)
    pids = _env_int("MCP_GATEWAY_MAX_PIDS", DEFAULT_MAX_PIDS, minimum=16, maximum=4096)
    open_files = _env_int("MCP_GATEWAY_MAX_OPEN_FILES", DEFAULT_MAX_OPEN_FILES, minimum=32, maximum=4096)
    file_bytes = _env_int("MCP_GATEWAY_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES, minimum=1 * 1024 * 1024, maximum=256 * 1024 * 1024)

    def limit() -> None:
        limits = (
            ("RLIMIT_CPU", cpu_seconds),
            ("RLIMIT_AS", memory_bytes),
            ("RLIMIT_NPROC", pids),
            ("RLIMIT_NOFILE", open_files),
            ("RLIMIT_FSIZE", file_bytes),
        )
        for name, maximum in limits:
            resource_name = getattr(resource_module, name, None)
            if resource_name is None:
                continue
            try:
                current_soft, current_hard = resource_module.getrlimit(resource_name)
                hard = maximum if current_hard in {resource_module.RLIM_INFINITY, -1} else min(current_hard, maximum)
                soft = min(maximum, hard)
                resource_module.setrlimit(resource_name, (soft, hard))
            except (OSError, ValueError):
                continue

    return limit


def windows_job_objects_available() -> bool:
    """Return whether this Windows host exposes the Job Object API.

    This is deliberately a capability check, not a claim that a particular
    child is already attached.  ``StdioMcpUpstream.start`` still attaches and
    validates the handle for every process before the server can receive a
    JSON-RPC frame.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes

        ctypes_api = cast(Any, ctypes)
        kernel32 = ctypes_api.WinDLL("kernel32", use_last_error=True)
        return all(
            getattr(kernel32, name, None) is not None
            for name in ("CreateJobObjectW", "SetInformationJobObject", "AssignProcessToJobObject")
        )
    except (AttributeError, OSError):
        return False


def _attach_windows_job_object(proc: subprocess.Popen[str]) -> Any:
    """Create and attach a bounded Windows Job Object to ``proc``."""
    if os.name != "nt":
        return None

    import ctypes
    from ctypes import wintypes
    ctypes_api = cast(Any, ctypes)

    class _LargeInteger(ctypes.Structure):
        _fields_ = [("QuadPart", ctypes.c_longlong)]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", _LargeInteger),
            ("PerJobUserTimeLimit", _LargeInteger),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes_api.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes_api.get_last_error(), "CreateJobObjectW failed")

    # JOB_OBJECT_LIMIT_JOB_TIME, ACTIVE_PROCESS, PROCESS_MEMORY, JOB_MEMORY and
    # KILL_ON_JOB_CLOSE.  Limits are intentionally conservative and mirror the
    # POSIX defaults used by the same gateway.
    limits = _ExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = 0x00000004 | 0x00000008 | 0x00000100 | 0x00000200 | 0x00002000
    limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = _env_int(
        "MCP_GATEWAY_MAX_CPU_SECONDS", DEFAULT_MAX_CPU_SECONDS, minimum=1, maximum=300
    ) * 10_000_000
    limits.BasicLimitInformation.ActiveProcessLimit = _env_int(
        "MCP_GATEWAY_MAX_PIDS", DEFAULT_MAX_PIDS, minimum=16, maximum=4096
    )
    limits.ProcessMemoryLimit = _env_int(
        "MCP_GATEWAY_MAX_MEMORY_BYTES",
        DEFAULT_MAX_MEMORY_BYTES,
        minimum=64 * 1024 * 1024,
        maximum=4 * 1024 * 1024 * 1024,
    )
    limits.JobMemoryLimit = limits.ProcessMemoryLimit
    if not kernel32.SetInformationJobObject(
        job,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        error = ctypes_api.get_last_error()
        kernel32.CloseHandle(job)
        raise OSError(error, "SetInformationJobObject failed")

    process_handle = wintypes.HANDLE(getattr(proc, "_handle", 0))
    if not process_handle.value or not kernel32.AssignProcessToJobObject(job, process_handle):
        error = ctypes_api.get_last_error()
        kernel32.CloseHandle(job)
        raise OSError(error, "AssignProcessToJobObject failed")
    return job


def _terminate_windows_job_object(job_handle: Any) -> None:
    if os.name != "nt" or job_handle is None:
        return
    try:
        import ctypes
        from ctypes import wintypes

        ctypes_api = cast(Any, ctypes)
        kernel32 = ctypes_api.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.TerminateJobObject(job_handle, 1)
        kernel32.CloseHandle(job_handle)
    except (AttributeError, OSError):
        return


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=2,
            )
        else:
            import signal

            killpg = getattr(os, "killpg", None)
            if callable(killpg):
                killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
    except (OSError, subprocess.SubprocessError):
        try:
            proc.terminate()
        except OSError:
            pass


def _build_upstream_env(extra_env: dict[str, str]) -> dict[str, str]:
    """Build a least-privilege environment for an MCP child process.

    An MCP server is a plugin boundary.  Passing the API process's complete
    environment would disclose provider keys, Agent tokens and the audit HMAC
    to a compromised or merely curious server before any tool call is made.
    Keep only runtime essentials by default; operators may explicitly add
    non-default variables with ``MCP_GATEWAY_UPSTREAM_ENV_ALLOWLIST`` or the
    constructor's test/configuration ``extra_env``.
    """
    configured = {
        item.strip()
        for item in os.getenv("MCP_GATEWAY_UPSTREAM_ENV_ALLOWLIST", "").split(",")
        if item.strip() and ENV_NAME_PATTERN.fullmatch(item.strip())
    }
    sensitive_configured = sorted(item for item in configured if _looks_sensitive_env_name(item))
    if sensitive_configured:
        raise StdioUpstreamError(
            "MCP_GATEWAY_UPSTREAM_ENV_ALLOWLIST 包含凭据类变量，禁止把网关秘密暴露给上游："
            + ", ".join(sensitive_configured[:8])
        )
    allowed = DEFAULT_UPSTREAM_ENV_KEYS | configured
    child_env = {key: os.environ[key] for key in allowed if key in os.environ}
    # MCP-specific feature flags are safe operational configuration and are
    # commonly supplied through the parent process (including test fixtures).
    # Keep token/key-like names out even when they use the MCP_ prefix.
    for key, value in os.environ.items():
        if key.startswith("MCP_") and not re.search(r"(?i)(token|key|secret|password|credential|auth|hmac)", key):
            child_env.setdefault(key, value)
    for key, value in extra_env.items():
        if not ENV_NAME_PATTERN.fullmatch(str(key)):
            raise StdioUpstreamError(f"上游 MCP 环境变量名无效：{key}")
        if _looks_sensitive_env_name(str(key)):
            raise StdioUpstreamError(f"上游 MCP 环境变量 `{key}` 可能包含凭据，禁止注入子进程。")
        child_env[str(key)] = str(value)
    # JSON-RPC stdio is UTF-8 regardless of the host code page.  Windows
    # Python children otherwise inherit cp936/cp1252 for a pipe and can emit
    # undecodable non-ASCII tool descriptions, which silently kills the
    # reader thread and makes tools/list appear empty.  Force the protocol
    # encoding for Python-compatible upstreams while keeping the environment
    # otherwise least-privileged.
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"
    child_env["PYTHONUNBUFFERED"] = "1"
    return child_env


def _looks_sensitive_env_name(name: str) -> bool:
    return bool(re.search(r"(?i)(token|api[_-]?key|secret|password|credential|auth|hmac|private[_-]?key)", name))


def _same_jsonrpc_scalar(left: Any, right: Any) -> bool:
    """Compare progress tokens without bool/int aliasing or container coercion."""
    scalar_types = (str, int, float)
    if isinstance(left, bool) or isinstance(right, bool):
        return False
    if not isinstance(left, scalar_types) or not isinstance(right, scalar_types):
        return False
    return type(left) is type(right) and left == right
