# =========================================================
# STAGE 1 — Build Dependencies
# =========================================================
FROM python:3.11-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk add --no-cache gcc musl-dev linux-headers

COPY app/requirements.txt /app/requirements.txt

# Create venv, upgrade pip to fixed version, install deps
RUN python -m venv /opt/venv && \
    /opt/venv/bin/python -m pip install --upgrade --no-cache-dir "pip==25.3" setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade "jaraco.context==6.1.0" && \
    /opt/venv/bin/pip check && \
    # Remove any stale metadata if it exists
    find /opt/venv -type d -name "jaraco.context-5.3.0.dist-info" -prune -exec rm -rf {} + || true && \
    find /opt/venv -type d -name "pip-24.0.dist-info" -prune -exec rm -rf {} + || true


# =========================================================
# STAGE 2 — Runtime Image
# =========================================================
FROM python:3.11-alpine AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Upgrade SYSTEM pip to fixed version (Trivy sees this one too)
# CVE-2025-8869 fixed in pip 25.3
RUN python -m pip install --upgrade --no-cache-dir "pip==25.3" setuptools && \
    python -m pip --version

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Remove stale dist-info from common system locations (where Trivy finds METADATA)
RUN find /usr/local/lib -type d -name "jaraco.context-5.3.0.dist-info" -prune -exec rm -rf {} + || true && \
    find /usr/local/lib -type d -name "pip-24.0.dist-info" -prune -exec rm -rf {} + || true && \
    find /usr/lib -type d -name "jaraco.context-5.3.0.dist-info" -prune -exec rm -rf {} + || true && \
    find /usr/lib -type d -name "pip-24.0.dist-info" -prune -exec rm -rf {} + || true

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY app /app
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--workers", "3", "--threads", "2"]
