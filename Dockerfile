FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /app

COPY pyproject.toml README.md ./
COPY labpilot ./labpilot
RUN pip install --no-cache-dir . \
 && useradd --system --uid 10001 labpilot \
 && mkdir -p /data && chown labpilot /data

USER labpilot
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "labpilot.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
