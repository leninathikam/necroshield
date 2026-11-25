# One container: the FastAPI service serves the API and the static Next.js export.
# Synthetic data only; no outbound network access is needed unless a live model provider is configured.

FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    NECROSHIELD_STATIC=/app/frontend/out \
    NECROSHIELD_DB=/data/necroshield.db \
    PORT=8017
WORKDIR /app
COPY backend/requirements.txt backend/constraints.txt backend/
RUN pip install --no-cache-dir -r backend/requirements.txt -c backend/constraints.txt
COPY backend/necroshield backend/necroshield
COPY scripts/verify_evidence.py scripts/docker_entrypoint.py scripts/
COPY --from=web /web/out frontend/out
RUN useradd --system --uid 10001 --user-group necro && mkdir -p /data && chown necro:necro /data
WORKDIR /app/backend
EXPOSE 8017
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/health')"
# Starts as root only to give a mounted /data disk to uid 10001, then drops privileges and execs
# uvicorn on $PORT (Render assigns it; 8017 by default). See scripts/docker_entrypoint.py.
ENTRYPOINT ["python", "/app/scripts/docker_entrypoint.py"]
