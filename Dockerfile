FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --system --create-home --uid 10001 commandcore
COPY requirements-server.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements-server.lock
COPY apps ./apps
COPY pyproject.toml VERSION ./
RUN pip install --no-cache-dir --no-deps .
RUN mkdir -p /data && chown -R commandcore:commandcore /data /app
USER commandcore
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz',timeout=3).read()"
CMD ["commandcore-server"]
