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
        """查询所有上游 tools/list，重建 工具名 → 路由名 目录。"""
        catalog: dict[str, str] = {}
        for route, upstream in self._ordered_upstreams():
            try:
                # request 内部会 _ensure_started：未启动的路由首次列目录时启动
                response = upstream.request("tools/list", {})
            except StdioUpstreamError:
                continue
            tools = (response.get("result") or {}).get("tools") or []
            for tool in tools:
                if isinstance(tool, dict) and tool.get("name"):
                    catalog.setdefault(str(tool["name"]), route)
        with self._lock:
            self._catalog = catalog
        return dict(catalog)

    def catalog(self) -> dict[str, str]:
        with self._lock:
            return dict(self._catalog)

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
                tools.append({**tool, "zhiAnRoute": route})
        return {"tools": tools, "conflicts": conflicts or None}


def router_from_config(default: StdioMcpUpstream, routes: dict[str, StdioMcpUpstream]) -> UpstreamRouter:
    """构造路由：routes 中的 default 会被显式传入的 default 覆盖。"""
    merged = dict(routes)
    merged[DEFAULT_ROUTE] = default
    return UpstreamRouter(merged)
