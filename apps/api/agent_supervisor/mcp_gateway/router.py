"""多上游路由：按工具目录和上下文目录把 MCP 请求路由到真实上游。

路由规则：
- 每条路由是一个命名上游（name + StdioMcpUpstream）；`default` 为兜底路由。
- 工具目录来自各上游的 tools/list（懒加载缓存）；tools/call 按目录命中路由。
- 未知工具不会落到 default 路由；调用方只能使用当前 ``tools/list`` 已登记的工具。
- resources/prompts 的列表响应按上游聚合，并建立 URI/name 到路由的目录；
  在多上游且尚未发现目标时，读取类请求直接拒绝，避免把请求误送到 default。
- tools/list 聚合所有上游；同名工具先注册者生效，冲突在返回值中标注。
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import Any

from apps.api.agent_supervisor.domains.governance.skill_scanner import (
    VERDICT_QUARANTINE,
    VERDICT_WARN,
    project_tool_definition,
    safe_model_tool_name,
    scan_tool_definition,
    skill_scan_enabled,
)
from apps.api.agent_supervisor.domains.governance.tool_contract import (
    context_allowlist_reason,
    get_agent_context_allowlist,
    get_agent_tool_allowlist,
    normalize_tool_call,
)
from apps.api.agent_supervisor.mcp_gateway.upstream import StdioMcpUpstream, StdioUpstreamError
from apps.api.agent_supervisor.storage.data import get_policy_settings

DEFAULT_ROUTE = "default"
CONTEXT_LIST_METHODS = frozenset(
    {
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    }
)
CONTEXT_ROUTE_METHODS = frozenset(
    {
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/get",
        "completion/complete",
    }
)
_URI_TEMPLATE_TOKEN_RE = re.compile(r"\{[^{}\r\n]{1,128}\}")


def _safe_upstream_error(value: Any) -> dict[str, str]:
    raw = str(value or "")
    return {
        "error": "MCP 上游请求失败；详细原因仅保留在审计记录中。",
        "error_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    }


def _uri_matches_template(uri: str, template: str) -> bool:
    """Match an expanded URI against a bounded MCP URI template.

    The gateway only needs routing, not full RFC 6570 expansion.  Treat each
    template expression as one variable span and preserve the literal pieces
    around it.  This keeps matching deterministic and avoids compiling an
    untrusted template into a backtracking regular expression.
    """

    if not uri or not template or len(uri) > 4096 or len(template) > 2048:
        return False
    matches = list(_URI_TEMPLATE_TOKEN_RE.finditer(template))
    if not matches:
        return uri == template
    prefix = template[: matches[0].start()]
    if not uri.startswith(prefix):
        return False
    position = len(prefix)
    for current, following in zip(matches, [*matches[1:], None], strict=True):
        literal = template[current.end() : following.start()] if following is not None else template[current.end() :]
        if not literal:
            continue
        next_position = uri.find(literal, position)
        if next_position < 0:
            return False
        position = next_position + len(literal)
    return position <= len(uri)


class UpstreamRouter:
    """命名上游集合 + 基于工具目录的调用路由。"""

    def __init__(self, upstreams: dict[str, StdioMcpUpstream]) -> None:
        if DEFAULT_ROUTE not in upstreams:
            raise ValueError("UpstreamRouter 必须包含 default 路由。")
        self._upstreams = dict(upstreams)
        self._lock = threading.Lock()
        self._catalog: dict[str, str] = {}
        self._tool_definitions: dict[str, dict[str, Any]] = {}
        self._skill_verdicts: dict[str, dict[str, Any]] = {}
        self._catalog_conflicts: dict[str, list[str]] = {}
        self._resource_catalog: dict[str, str] = {}
        self._resource_template_catalog: dict[str, str] = {}
        self._prompt_catalog: dict[str, str] = {}
        self._context_inventory: dict[str, dict[tuple[str, str], dict[str, Any]]] = {
            "resources": {},
            "resourceTemplates": {},
            "prompts": {},
        }
        self._context_failures: dict[str, list[dict[str, str]]] = {
            "resources": [],
            "resourceTemplates": [],
            "prompts": [],
        }
        self._catalog_loaded = False
        self._catalog_skill_scan_enabled: bool | None = None

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

    def clone(self) -> "UpstreamRouter":
        """Return a fresh route set with independent stdio child processes.

        Catalogs are intentionally not copied.  Tool descriptions, resource
        routes and prompt routes are model-visible state and must be discovered
        inside the new Agent session rather than inherited from another one.
        """

        return UpstreamRouter({route: upstream.clone() for route, upstream in self._upstreams.items()})

    # -- 工具目录 -----------------------------------------------------------

    def _ordered_upstreams(self) -> list[tuple[str, StdioMcpUpstream]]:
        """default 路由优先：同名工具归属 default。"""
        items = list(self._upstreams.items())
        items.sort(key=lambda item: 0 if item[0] == DEFAULT_ROUTE else 1)
        return items

    def refresh_catalog(self) -> dict[str, str]:
        """查询所有上游 tools/list，重建 工具名 → 路由名 目录，并同步 Skill 扫描结论。"""
        scan_enabled = skill_scan_enabled()
        catalog: dict[str, str] = {}
        tool_definitions: dict[str, dict[str, Any]] = {}
        verdicts: dict[str, dict[str, Any]] = {}
        conflicts: dict[str, list[str]] = {}
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
                        conflicts.setdefault(name, [catalog[name], route])
                        continue
                    catalog[name] = route
                    tool_definitions[name] = dict(tool)
                    if scan_enabled:
                        scan = scan_tool_definition(tool)
                        verdicts[name] = {"verdict": scan.verdict, "signals": scan.signals}
        with self._lock:
            self._catalog = catalog
            self._tool_definitions = tool_definitions
            self._skill_verdicts = verdicts
            self._catalog_conflicts = conflicts
            self._catalog_loaded = True
            self._catalog_skill_scan_enabled = scan_enabled
        return dict(catalog)

    def catalog(self) -> dict[str, str]:
        with self._lock:
            return dict(self._catalog)

    def ensure_catalog(self) -> dict[str, str]:
        """目录尚未加载时刷新一次（含 Skill 扫描结论）；已加载直接返回缓存。

        tools/call 可能先于 tools/list 到达（Agent 缓存工具目录的场景），
        需要保证隔离级工具在调用时也有扫描结论兜底。
        """
        current_skill_scan_enabled = skill_scan_enabled()
        with self._lock:
            if self._catalog_loaded and self._catalog_skill_scan_enabled == current_skill_scan_enabled:
                return dict(self._catalog)
        return self.refresh_catalog()

    def invalidate_catalog(self) -> None:
        """Drop cached tool definitions after an upstream list-change event.

        Tool descriptions and input schemas are part of the model-visible trust
        boundary.  Keeping an old clean catalog after a server announces a
        change would let a newly poisoned definition bypass the next call's
        description scan.
        """
        with self._lock:
            self._catalog_loaded = False
            self._catalog = {}
            self._tool_definitions = {}
            self._skill_verdicts = {}
            self._catalog_conflicts = {}
            self._resource_catalog = {}
            self._resource_template_catalog = {}
            self._prompt_catalog = {}
            self._context_inventory = {"resources": {}, "resourceTemplates": {}, "prompts": {}}
            self._context_failures = {"resources": [], "resourceTemplates": [], "prompts": []}
            self._catalog_skill_scan_enabled = None

    def skill_verdict(self, tool_name: str) -> dict[str, Any] | None:
        """返回最近一次目录刷新缓存的 Skill 扫描结论；未扫描过返回 None。"""
        with self._lock:
            return self._skill_verdicts.get(tool_name)

    def tool_definition(self, tool_name: str) -> dict[str, Any] | None:
        """Return the cached model-visible definition for one tool.

        The definition is used only for server-side argument validation; callers
        still receive the upstream's original protocol response.
        """
        with self._lock:
            definition = self._tool_definitions.get(tool_name)
            return dict(definition) if isinstance(definition, dict) else None

    def tool_is_registered(self, tool_name: str) -> bool:
        """Return whether the tool was advertised by an upstream catalog.

        A caller must not be able to invoke an arbitrary standard capability
        merely because the default upstream happens to understand that name.
        The MCP ``tools/list`` catalog is the authority for the current
        gateway instance; an unadvertised call is rejected before routing.
        """
        with self._lock:
            return str(tool_name or "") in self._catalog

    def tool_is_quarantined(self, tool_name: str) -> bool:
        verdict = self.skill_verdict(tool_name)
        return bool(verdict and verdict.get("verdict") == VERDICT_QUARANTINE)

    def tool_allowed_for_agent(self, tool_name: str, agent_id: str) -> bool:
        """Enforce the same capability boundary used by ``tools/list``.

        Discovery filtering is only a usability boundary.  A caller can still
        hand-craft ``tools/call`` without first asking for the catalog, so the
        call path must repeat the allowlist decision before any upstream I/O.
        """

        allowed_tools = get_agent_tool_allowlist(get_policy_settings(), agent_id)
        if allowed_tools is None:
            return True
        return self._tool_visible_for_agent(tool_name, agent_id, allowed_tools)

    # -- 路由 ---------------------------------------------------------------

    def route_for_tool(self, tool_name: str) -> tuple[str, StdioMcpUpstream]:
        """返回 (路由名, 上游)；未知工具仍返回 default 供审计标注。"""
        with self._lock:
            route = self._catalog.get(tool_name, DEFAULT_ROUTE)
        return route, self._upstreams[route]

    def notify_all(self, method: str, params: dict[str, Any] | None = None) -> None:
        """把协议生命周期通知广播到每个上游。"""
        for upstream in self._upstreams.values():
            upstream.notify(method, params)

    def list_context(
        self,
        method: str,
        params: dict[str, Any],
        *,
        client_id: Any = None,
        agent_id: str = "",
    ) -> dict[str, Any]:
        """聚合 resources/prompts 列表，并记录每项的真实路由。

        MCP 的单个 Gateway 对 Agent 呈现一个逻辑服务器；多上游列表不能只
        查询 default，否则 Agent 看到的能力与实际能力不一致。列表项上的
        路由目录仅保存在网关内部；模型侧只接收标准 MCP 列表项，操作员可
        通过认证的工具证据接口查看实际上游归属。
        """
        if method not in CONTEXT_LIST_METHODS:
            raise ValueError(f"不支持聚合 MCP 方法：{method}")
        result_key = {
            "resources/list": "resources",
            "resources/templates/list": "resourceTemplates",
            "prompts/list": "prompts",
        }[method]
        merged: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        filtered_count = 0
        first_error_response: dict[str, Any] | None = None
        upstream_params = {key: value for key, value in params.items() if key != "zhiAnRoute"}
        with self._lock:
            self._context_inventory[result_key] = {}
            self._context_failures[result_key] = []
            if result_key == "resources":
                self._resource_catalog = {}
            elif result_key == "resourceTemplates":
                self._resource_template_catalog = {}
            else:
                self._prompt_catalog = {}
        for route, upstream in self._ordered_upstreams():
            try:
                response = upstream.request(method, upstream_params, client_id=client_id)
            except StdioUpstreamError as exc:
                failures.append({"route": route, **_safe_upstream_error(exc)})
                continue
            if isinstance(response.get("error"), dict):
                if first_error_response is None:
                    first_error_response = dict(response)
                failures.append(
                    {
                        "route": route,
                        **_safe_upstream_error(response["error"].get("message") or "upstream error"),
                    }
                )
                continue
            upstream_result = response.get("result")
            entries = upstream_result.get(result_key) if isinstance(upstream_result, dict) else None
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                # Keep the upstream route in the private catalog only.  A
                # caller can read by URI/name after discovery; it does not
                # need an internal route label in model context.
                annotated = {key: value for key, value in entry.items() if key != "zhiAnRoute"}
                with self._lock:
                    identifier_field = {
                        "resources": "uri",
                        "resourceTemplates": "uriTemplate",
                        "prompts": "name",
                    }[result_key]
                    identifier = str(entry.get(identifier_field) or "").strip()
                    if identifier:
                        try:
                            serialized_entry = json.dumps(
                                entry,
                                ensure_ascii=False,
                                default=str,
                                separators=(",", ":"),
                            )
                        except (TypeError, ValueError, RecursionError):
                            serialized_entry = f"{result_key}:{identifier}"
                        self._context_inventory[result_key][(identifier, route)] = {
                            "kind": result_key,
                            "identifier": identifier[:512],
                            "route": route,
                            "entry_hash": hashlib.sha256(serialized_entry.encode("utf-8")).hexdigest(),
                        }
                    if result_key == "resources":
                        uri = str(entry.get("uri") or "").strip()
                        if uri:
                            self._resource_catalog.setdefault(uri, route)
                    elif result_key == "resourceTemplates":
                        uri_template = str(entry.get("uriTemplate") or "").strip()
                        if uri_template:
                            self._resource_template_catalog.setdefault(uri_template, route)
                    else:
                        name = str(entry.get("name") or "").strip()
                        if name:
                            self._prompt_catalog.setdefault(name, route)
                if not self.context_item_allowed(result_key, entry, agent_id):
                    filtered_count += 1
                    continue
                merged.append(annotated)
        with self._lock:
            self._context_failures[result_key] = [dict(item) for item in failures]
        if not merged and failures and len(failures) == len(self._upstreams):
            if len(self._upstreams) == 1 and first_error_response is not None:
                return first_error_response
            return {
                "jsonrpc": "2.0",
                "id": client_id,
                "error": {"code": -32603, "message": "MCP 上游均未返回有效列表。", "data": {"routes": failures}},
            }
        result: dict[str, Any] = {result_key: merged}
        marker: dict[str, Any] = {
            "contextScope": {
                "agent": agent_id or "anonymous-local",
                "filteredCount": filtered_count,
                "trust": "untrusted-data",
            }
        }
        if failures:
            marker.update({"partial": True, "failed_route_count": len(failures)})
        if marker:
            result["zhiAnSentinel"] = marker
        return {"jsonrpc": "2.0", "id": client_id, "result": result}

    def context_inventory(self, *, agent_id: str = "") -> dict[str, Any]:
        """Return operator-only evidence for MCP resources/templates/prompts.

        The model-facing list methods intentionally return only the filtered
        standard MCP entries.  This inventory refreshes the private catalogs,
        then exposes bounded identifiers, route ownership and hashes only to
        the authenticated management endpoint so an operator can explain why
        an Agent saw or missed a context item without replaying its contents.
        """

        for method in sorted(CONTEXT_LIST_METHODS):
            self.list_context(method, {}, client_id=None, agent_id=agent_id)

        scope = get_agent_context_allowlist(get_policy_settings(), agent_id)
        with self._lock:
            rows = [
                dict(row)
                for entries in self._context_inventory.values()
                for row in entries.values()
            ]
            failures = {
                kind: [dict(item) for item in items]
                for kind, items in self._context_failures.items()
                if items
            }

        visible: list[dict[str, Any]] = []
        filtered: list[dict[str, Any]] = []
        for row in rows:
            kind = str(row.get("kind") or "")
            identifier = str(row.get("identifier") or "")
            if scope is None:
                reason = None
            elif kind == "resources":
                reasons = [
                    context_allowlist_reason("resources", identifier, scope),
                    context_allowlist_reason("resource_templates", identifier, scope),
                ]
                reason = next((item for item in reasons if item is None), reasons[0] if reasons else "MCP 上下文未登记。")
            elif kind == "resourceTemplates":
                reason = context_allowlist_reason("resource_templates", identifier, scope)
            else:
                reason = context_allowlist_reason("prompts", identifier, scope)
            candidate = row | {"status": "visible" if reason is None else "filtered"}
            if reason is not None:
                candidate["reason"] = reason
                filtered.append(candidate)
            else:
                visible.append(candidate)

        visible.sort(key=lambda item: (str(item.get("kind")), str(item.get("identifier")), str(item.get("route"))))
        filtered.sort(key=lambda item: (str(item.get("kind")), str(item.get("identifier")), str(item.get("route"))))
        routes_by_context: dict[tuple[str, str], set[str]] = {}
        for row in rows:
            kind = str(row.get("kind") or "")
            identifier = str(row.get("identifier") or "")
            route = str(row.get("route") or "")
            if kind and identifier and route:
                routes_by_context.setdefault((kind, identifier), set()).add(route)
        conflicts = [
            {
                "kind": kind,
                "identifier": identifier,
                "routes": sorted(routes),
            }
            for (kind, identifier), routes in routes_by_context.items()
            if len(routes) > 1
        ]
        conflicts.sort(key=lambda item: (str(item["kind"]), str(item["identifier"])))
        return {
            "schema_version": "mcp-context-operator-inventory.v1",
            "agent": agent_id or "anonymous-local",
            "scope_mode": "registered" if scope is not None else "compatibility",
            "summary": {
                "catalog_entry_count": len(rows),
                "visible_context_count": len(visible),
                "filtered_context_count": len(filtered),
                "resource_count": sum(1 for item in rows if item.get("kind") == "resources"),
                "resource_template_count": sum(1 for item in rows if item.get("kind") == "resourceTemplates"),
                "prompt_count": sum(1 for item in rows if item.get("kind") == "prompts"),
                "conflict_count": len(conflicts),
                "failed_route_count": sum(len(items) for items in failures.values()),
            },
            "visible_context": visible,
            "filtered_context": filtered,
            "conflicts": conflicts,
            "upstream_failures": failures,
        }

    def context_access_reason(self, method: str, params: dict[str, Any], agent_id: str) -> str | None:
        """Return a stable denial reason for an Agent's MCP context request."""
        scope = get_agent_context_allowlist(get_policy_settings(), agent_id)
        if scope is None:
            return None
        candidates: list[tuple[str, str]] = []
        if method.startswith("resources/"):
            uri = str(params.get("uri") or "").strip()
            candidates.append(("resources", uri))
            # A template scope may intentionally cover expanded resource URIs.
            candidates.append(("resource_templates", uri))
        elif method == "prompts/get":
            candidates.append(("prompts", str(params.get("name") or "").strip()))
        elif method == "completion/complete":
            ref = params.get("ref")
            if isinstance(ref, dict):
                if ref.get("uri"):
                    candidates.extend(
                        [
                            ("resources", str(ref.get("uri") or "").strip()),
                            ("resource_templates", str(ref.get("uri") or "").strip()),
                        ]
                    )
                if ref.get("name"):
                    candidates.append(("prompts", str(ref.get("name") or "").strip()))
        if not candidates:
            return "MCP 上下文请求缺少可授权的 URI 或名称。"
        reasons: list[str] = []
        for kind, value in candidates:
            reason = context_allowlist_reason(kind, value, scope)
            if reason is None:
                return None
            reasons.append(reason)
        return reasons[0] if reasons else "MCP 上下文未登记。"

    def context_item_allowed(self, result_key: str, entry: dict[str, Any], agent_id: str) -> bool:
        """Filter discovery items without removing them from the private route catalog."""
        scope = get_agent_context_allowlist(get_policy_settings(), agent_id)
        if scope is None:
            return True
        if result_key == "resources":
            uri = str(entry.get("uri") or "").strip()
            return (
                context_allowlist_reason("resources", uri, scope) is None
                or context_allowlist_reason("resource_templates", uri, scope) is None
            )
        if result_key == "resourceTemplates":
            uri_template = str(entry.get("uriTemplate") or "").strip()
            return context_allowlist_reason("resource_templates", uri_template, scope) is None
        return context_allowlist_reason("prompts", str(entry.get("name") or "").strip(), scope) is None

    def route_for_context(self, method: str, params: dict[str, Any]) -> tuple[str, StdioMcpUpstream] | None:
        """Resolve a context read/get request without silently choosing default."""
        if method not in CONTEXT_ROUTE_METHODS:
            return self._single_route_or_none()
        explicit = str(params.get("zhiAnRoute") or "").strip()
        with self._lock:
            routes: set[str] = set()
            if method.startswith("resources/"):
                key = str(params.get("uri") or "").strip()
                routes.update(self._context_routes_locked("resources", key))
                if not routes and key:
                    routes.update(self._template_routes_for_uri_locked(key))
            elif method == "prompts/get":
                key = str(params.get("name") or "").strip()
                routes.update(self._context_routes_locked("prompts", key))
            else:
                ref = params.get("ref")
                ref_name = ref.get("name") if isinstance(ref, dict) else ""
                ref_uri = ref.get("uri") if isinstance(ref, dict) else ""
                key = str(ref_name or ref_uri or "").strip()
                if ref_name:
                    routes.update(self._context_routes_locked("prompts", key))
                else:
                    routes.update(self._context_routes_locked("resources", key))
                    if not routes and key:
                        routes.update(self._template_routes_for_uri_locked(key))
            if explicit in self._upstreams:
                # A caller may echo the non-standard route marker returned by
                # discovery, but it cannot invent one to select an arbitrary
                # child. In a multi-upstream gateway the resource/name must be
                # present in the private catalog and belong to that route.
                if explicit in routes:
                    return explicit, self._upstreams[explicit]
                if not routes and len(self._upstreams) == 1:
                    return explicit, self._upstreams[explicit]
                return None
            if len(routes) == 1:
                route = next(iter(routes))
                return route, self._upstreams[route]
            if len(routes) > 1:
                return None
        return self._single_route_or_none()

    def _context_routes_locked(self, kind: str, identifier: str) -> set[str]:
        """Return all discovered routes for one exact context identifier."""

        if not identifier:
            return set()
        return {
            route
            for (candidate, route), _row in self._context_inventory.get(kind, {}).items()
            if candidate == identifier and route in self._upstreams
        }

    def _template_routes_for_uri_locked(self, uri: str) -> set[str]:
        """Return every discovered route whose URI template matches ``uri``."""

        routes: set[str] = set()
        for (template, route), _row in self._context_inventory.get("resourceTemplates", {}).items():
            if route in self._upstreams and _uri_matches_template(uri, template):
                routes.add(route)
        return routes

    def _single_route_or_none(self) -> tuple[str, StdioMcpUpstream] | None:
        with self._lock:
            if len(self._upstreams) == 1:
                route = next(iter(self._upstreams))
                return route, self._upstreams[route]
        return None

    def list_tools(self, *, agent_id: str = "") -> dict[str, Any]:
        """聚合可交给模型的工具清单。

        ``tools/list`` is a model-context boundary, not an operator report.
        Keep it limited to the standard MCP tool shape and bounded counts.  A
        caller must use :meth:`tool_inventory` through the authenticated
        management endpoint to inspect filtered/quarantined names.
        """
        self.refresh_catalog()
        with self._lock:
            catalog = dict(self._catalog)
            definitions = {name: dict(tool) for name, tool in self._tool_definitions.items()}
            verdicts = {name: dict(verdict) for name, verdict in self._skill_verdicts.items()}
            conflicts = {name: list(routes) for name, routes in self._catalog_conflicts.items()}
        tools: list[dict[str, Any]] = []
        quarantined: list[dict[str, Any]] = []
        filtered: list[dict[str, str]] = []
        # Keep scan facts independent from capability visibility.  A tool can
        # be both untrusted and outside the current Agent allowlist; reporting
        # only ``filteredTools`` would make an operator conclude that the
        # description scanner never saw it.  Counts and name hashes are safe
        # evidence for the model boundary while raw descriptions remain
        # internal to the gateway.
        scan_summary: dict[str, Any] = {
            "enabled": bool(self._catalog_skill_scan_enabled),
            "scanned_tool_count": len(verdicts),
            "quarantined_tool_count": 0,
            "warning_tool_count": 0,
            "clean_tool_count": 0,
            "quarantined_name_hashes": [],
        }
        for name, verdict in verdicts.items():
            verdict_name = str(verdict.get("verdict") or "")
            if verdict_name == VERDICT_QUARANTINE:
                scan_summary["quarantined_tool_count"] += 1
                scan_summary["quarantined_name_hashes"].append(
                    hashlib.sha256(name.encode("utf-8")).hexdigest()
                )
            elif verdict_name == VERDICT_WARN:
                scan_summary["warning_tool_count"] += 1
            else:
                scan_summary["clean_tool_count"] += 1
        allowed_tools = get_agent_tool_allowlist(get_policy_settings(), agent_id)
        for name, route in catalog.items():
            tool = definitions.get(name)
            if not isinstance(tool, dict):
                continue
            if allowed_tools is not None and not self._tool_visible_for_agent(name, agent_id, allowed_tools):
                filtered.append({"name": safe_model_tool_name(name), "route": route})
                continue
            tool_verdict = verdicts.get(name)
            if tool_verdict and tool_verdict.get("verdict") == VERDICT_QUARANTINE:
                # The tool remains in the internal catalog so a direct
                # tools/call can be rejected with a precise reason, but
                # its untrusted description/schema must never reach the
                # model through tools/list.
                quarantined.append(
                    {
                        "name": safe_model_tool_name(name),
                        "route": route,
                        "signals": list(tool_verdict.get("signals") or []),
                    }
                )
                continue
            # The raw upstream definition is retained privately for schema
            # validation, but only the bounded standard MCP shape crosses into
            # model context.  Scanning alone is not a data-flow control: an
            # unrecognised vendor extension could otherwise remain visible even
            # after a clean/warn decision.
            annotated = project_tool_definition(tool, route=route)
            if annotated is None:
                quarantined.append(
                    {
                        "name": safe_model_tool_name(name),
                        "route": route,
                        "signals": ["unsafe-model-projection"],
                    }
                )
                continue
            tools.append(annotated)
        # Tool names and routes in ``filtered``/``quarantined`` are useful to
        # an operator but are capability metadata when sent to a model.  Do
        # not reflect them in this protocol response.  The conflict count is
        # enough to make the model-side contract observable without disclosing
        # another Agent's or route's capability names.
        return {
            "tools": tools,
            "zhiAnSentinel": {
                "schema_version": "mcp-tools-context.v2",
                "projection": "standard-mcp-tool-shape",
                "visible_tool_count": len(tools),
                "filtered_tool_count": len(filtered),
                "quarantined_tool_count": len(quarantined),
                "conflict_count": len(conflicts),
                "scanSummary": {
                    "enabled": scan_summary["enabled"],
                    "scanned_tool_count": scan_summary["scanned_tool_count"],
                    "quarantined_tool_count": scan_summary["quarantined_tool_count"],
                    "warning_tool_count": scan_summary["warning_tool_count"],
                    "clean_tool_count": scan_summary["clean_tool_count"],
                },
            },
        }

    def tool_inventory(self, *, agent_id: str = "") -> dict[str, Any]:
        """Return operator-only capability evidence for the current catalog.

        This method is intentionally separate from ``tools/list``.  The
        management route may expose bounded tool names and scanner signals to
        an authenticated analyst/admin, while the model-facing MCP response
        never receives names of filtered or quarantined capabilities.
        """

        self.ensure_catalog()
        with self._lock:
            catalog = dict(self._catalog)
            verdicts = {name: dict(verdict) for name, verdict in self._skill_verdicts.items()}
            conflicts = {name: list(routes) for name, routes in self._catalog_conflicts.items()}
            definitions = {name: dict(tool) for name, tool in self._tool_definitions.items()}

        allowed_tools = get_agent_tool_allowlist(get_policy_settings(), agent_id)
        visible: list[dict[str, Any]] = []
        filtered: list[dict[str, Any]] = []
        quarantined: list[dict[str, Any]] = []
        projection_blocked: list[dict[str, Any]] = []
        for name, route in catalog.items():
            verdict = verdicts.get(name) or {}
            row: dict[str, Any] = {
                "name": name,
                "route": route,
                "verdict": str(verdict.get("verdict") or "disabled"),
                "signals": list(verdict.get("signals") or []),
            }
            if allowed_tools is not None and not self._tool_visible_for_agent(name, agent_id, allowed_tools):
                row["status"] = "filtered"
                filtered.append(row)
                continue
            if verdict.get("verdict") == VERDICT_QUARANTINE:
                row["status"] = "quarantined"
                quarantined.append(row)
                continue
            if project_tool_definition(definitions.get(name, {}), route=route) is None:
                row["status"] = "projection-blocked"
                projection_blocked.append(row)
                continue
            row["status"] = "visible"
            visible.append(row)

        return {
            "schema_version": "mcp-tools-operator-inventory.v1",
            "agent": agent_id or "anonymous-local",
            "summary": {
                "catalog_tool_count": len(catalog),
                "visible_tool_count": len(visible),
                "filtered_tool_count": len(filtered),
                "quarantined_tool_count": len(quarantined),
                "projection_blocked_tool_count": len(projection_blocked),
                "conflict_count": len(conflicts),
                "scanner_enabled": bool(self._catalog_skill_scan_enabled),
            },
            "visible_tools": visible,
            "filtered_tools": filtered,
            "quarantined_tools": quarantined,
            "projection_blocked_tools": projection_blocked,
            "conflicts": [
                {"name": name, "routes": routes}
                for name, routes in conflicts.items()
            ],
        }

    @staticmethod
    def _tool_visible_for_agent(name: str, agent_id: str, allowed_tools: list[str]) -> bool:
        """Match both an MCP framework name and its canonical capability.

        MCP discovery is model-visible.  The call-time supervisor already
        rejects an ungranted tool; filtering it here prevents the model from
        learning an Agent's unrelated capabilities in the first place.
        """
        normalized_name = str(name or "").strip().lower()
        allowed = {str(item).strip().lower() for item in allowed_tools if str(item).strip()}
        if normalized_name in allowed:
            return True
        try:
            capability = normalize_tool_call({"tool": normalized_name, "arguments": {}}).get("tool", "")
        except Exception:  # noqa: BLE001 - malformed discovery names stay hidden
            capability = ""
        if capability in allowed:
            return True
        settings = get_policy_settings()
        registry = settings.get("agent_tool_mappings", {})
        if not isinstance(registry, dict):
            return False
        merged: dict[str, Any] = {}
        wildcard = registry.get("*")
        if isinstance(wildcard, dict):
            merged.update(wildcard)
        scoped = registry.get(agent_id)
        if isinstance(scoped, dict):
            merged.update(scoped)
        mapping = merged.get(normalized_name)
        return isinstance(mapping, dict) and str(mapping.get("capability") or "").strip().lower() in allowed


def router_from_config(default: StdioMcpUpstream, routes: dict[str, StdioMcpUpstream]) -> UpstreamRouter:
    """构造路由：routes 中的 default 会被显式传入的 default 覆盖。"""
    merged = dict(routes)
    merged[DEFAULT_ROUTE] = default
    return UpstreamRouter(merged)
