"""多上游路由：按工具目录把 tools/call 路由到声明该工具的上游。

路由规则：
- 每条路由是一个命名上游（name + StdioMcpUpstream）；`default` 为兜底路由。
- 工具目录来自各上游的 tools/list（懒加载缓存）；tools/call 按目录命中路由。
- 目录未命中（目录为空或工具未声明）时落到 default 路由——监督器仍会
  先拦截，未知工具由上游按自身协议报错。
- tools/list 聚合所有上游；同名工具先注册者生效，冲突在返回值中标注。
"""

from __future__ import annotations

import threading
from typing import Any

from apps.api.agent_supervisor.domains.governance.skill_scanner import (
    VERDICT_QUARANTINE,
    scan_tool_definition,
    skill_scan_enabled,
)
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream, StdioUpstreamError

DEFAULT_ROUTE = "default"


class UpstreamRouter:
    """命名上游集合 + 基于工具目录的调用路由。"""

    def __init__(self, upstreams: dict[str, StdioMcpUpstream]) -> None:
        if DEFAULT_ROUTE not in upstreams:
            raise ValueError("UpstreamRouter 必须包含 default 路由。")
        self._upstreams = dict(upstreams)
        self._lock = threading.Lock()
        self._catalog: dict[str, str] = {}
        self._skill_verdicts: dict[str, dict[str, Any]] = {}
        self._catalog_loaded = False

    @property
    def default(self) -> StdioMcpUpstream:
        return self._upstreams[DEFAULT_ROUTE]

    def upstream(self, route: str) -> StdioMcpUpstream:
        return self._upstreams.get(route, self.default)

    def route_names(self) -> list[str]:
        return list(self._upstreams)

    def close(self) -> None:
        for upstream in self._upstreams.values():
            upstream.close()

    # -- 工具目录 -----------------------------------------------------------

    def _ordered_upstreams(self) -> list[tuple[str, StdioMcpUpstream]]:
        """default 路由优先：同名工具归属 default。"""
        items = list(self._upstreams.items())
        items.sort(key=lambda item: 0 if item[0] == DEFAULT_ROUTE else 1)
        return items

    def refresh_catalog(self) -> dict[str, str]:
        """查询所有上游 tools/list，重建 工具名 → 路由名 目录，并同步 Skill 扫描结论。"""
        catalog: dict[str, str] = {}
        verdicts: dict[str, dict[str, Any]] = {}
        for route, upstream in self._ordered_upstreams():
            try:
                # request 内部会 _ensure_started：未启动的路由首次列目录时启动
                response = upstream.request("tools/list", {})
            except StdioUpstreamError:
                continue
            tools = (response.get("result") or {}).get("tools") or []
            for tool in tools:
                if isinstance(tool, dict) and tool.get("name"):
                    name = str(tool["name"])
                    if name in catalog:
                        continue
                    catalog[name] = route
                    if skill_scan_enabled():
                        scan = scan_tool_definition(tool)
                        verdicts[name] = {"verdict": scan.verdict, "signals": scan.signals}
        with self._lock:
            self._catalog = catalog
            self._skill_verdicts = verdicts
            self._catalog_loaded = True
        return dict(catalog)

    def catalog(self) -> dict[str, str]:
        with self._lock:
            return dict(self._catalog)

    def ensure_catalog(self) -> dict[str, str]:
        """目录尚未加载时刷新一次（含 Skill 扫描结论）；已加载直接返回缓存。

        tools/call 可能先于 tools/list 到达（Agent 缓存工具目录的场景），
        需要保证隔离级工具在调用时也有扫描结论兜底。
        """
        with self._lock:
            if self._catalog_loaded:
                return dict(self._catalog)
        return self.refresh_catalog()

    def skill_verdict(self, tool_name: str) -> dict[str, Any] | None:
        """返回最近一次目录刷新缓存的 Skill 扫描结论；未扫描过返回 None。"""
        with self._lock:
            return self._skill_verdicts.get(tool_name)

    def tool_is_quarantined(self, tool_name: str) -> bool:
        verdict = self.skill_verdict(tool_name)
        return bool(verdict and verdict.get("verdict") == VERDICT_QUARANTINE)

    # -- 路由 ---------------------------------------------------------------

    def route_for_tool(self, tool_name: str) -> tuple[str, StdioMcpUpstream]:
        """返回 (路由名, 上游)；未知工具落 default。"""
        with self._lock:
            route = self._catalog.get(tool_name, DEFAULT_ROUTE)
        return route, self._upstreams[route]

    def list_tools(self) -> dict[str, Any]:
        """聚合所有上游的工具清单，标注来源路由与同名冲突。"""
        catalog = self.refresh_catalog()
        conflicts: dict[str, list[str]] = {}
        tools: list[dict[str, Any]] = []
        seen: set[str] = set()
        for route, upstream in self._ordered_upstreams():
            try:
                response = upstream.request("tools/list", {})
            except StdioUpstreamError:
                continue
            for tool in (response.get("result") or {}).get("tools") or []:
                if not isinstance(tool, dict) or not tool.get("name"):
                    continue
                name = str(tool["name"])
                if catalog.get(name) != route:
                    conflicts.setdefault(name, [catalog[name], route])
                    continue
                if name in seen:
                    continue
                seen.add(name)
                annotated = {**tool, "zhiAnRoute": route}
                verdict = self.skill_verdict(name)
                if verdict is not None:
                    annotated["zhiAnSentinel"] = {"skillScan": verdict}
                tools.append(annotated)
        return {"tools": tools, "conflicts": conflicts or None}


def router_from_config(default: StdioMcpUpstream, routes: dict[str, StdioMcpUpstream]) -> UpstreamRouter:
    """构造路由：routes 中的 default 会被显式传入的 default 覆盖。"""
    merged = dict(routes)
    merged[DEFAULT_ROUTE] = default
    return UpstreamRouter(merged)
