# 网关组件

这里是运营网关的唯一组件边界，覆盖 OpenAI 兼容请求、MCP JSON-RPC、SSE、Trace、接入向导和服务端执行证据。

网关组件可以依赖 `src/app` 中的请求契约和控制器，也可以依赖 `components/ui`；不得反向依赖 `settings`、`audit` 或研究目录。页面只负责把它们组合到路由和抽屉中。
