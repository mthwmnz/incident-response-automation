FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    AUDIT_DB_PATH=/app/data/audit.db \
    HOST=0.0.0.0 \
    PORT=8000

COPY pyproject.toml ./
COPY src ./src
COPY playbooks ./playbooks
COPY serve.py ./

RUN pip install . \
 && useradd --create-home --uid 1000 appuser \
 && mkdir -p /app/data \
 && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://127.0.0.1:8000/').raise_for_status()" || exit 1

CMD ["python", "serve.py"]
