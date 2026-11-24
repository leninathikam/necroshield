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
    PORT=8017 \
    FORWARDED_ALLOW_IPS=127.0.0.1
WORKDIR /app
COPY backend/requirements.txt backend/constraints.txt backend/
RUN pip install --no-cache-dir -r backend/requirements.txt -c backend/constraints.txt
COPY backend/necroshield backend/necroshield
COPY scripts/verify_evidence.py scripts/verify_evidence.py
COPY --from=web /web/out frontend/out
RUN useradd --system --uid 10001 necro && mkdir -p /data && chown necro /data
USER necro
WORKDIR /app/backend
EXPOSE 8017
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/health')"
# Trust X-Forwarded-For only from FORWARDED_ALLOW_IPS (set it to the hosting proxy's range);
# trusting every peer would let clients choose their own rate-limit key.
CMD ["sh", "-c", "exec python -m uvicorn necroshield.api.app:app_from_env --factory --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS}"]
