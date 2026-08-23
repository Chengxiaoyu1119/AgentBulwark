# 智安哨 LLM 应用防火墙 —— 一键构建镜像
# 阶段 1：构建前端控制台（React + Vite）
# 阶段 2：Python 运行镜像（FastAPI 同时托管 API 与前端静态资源）

FROM node:22-alpine AS console-build
WORKDIR /repo
COPY apps/console/package.json apps/console/package-lock.json ./apps/console/
RUN cd apps/console && npm ci
COPY apps/console/ ./apps/console/
RUN cd apps/console && npm run build

FROM python:3.11-slim AS runtime
WORKDIR /repo
COPY apps/api/requirements.txt ./apps/api/requirements.txt
RUN pip install --no-cache-dir -r apps/api/requirements.txt

# apps/api/sandbox/fixtures 是运行时依赖（演练场景与夹具），必须随镜像分发
COPY apps/api/ ./apps/api/
COPY --from=console-build /repo/apps/console/dist ./apps/console/dist

# 运行时数据（SQLite 审计库等）写入独立卷，便于持久化
ENV AGENT_SUPERVISOR_RUNTIME_DIR=/data \
    AGENT_SUPERVISOR_API_HOST=0.0.0.0 \
    AGENT_SUPERVISOR_API_PORT=8012
RUN mkdir -p /data && useradd --system --no-create-home sentinel && chown -R sentinel /data /repo
USER sentinel
VOLUME /data
EXPOSE 8012

CMD ["python", "-m", "apps.api.dev_server"]
