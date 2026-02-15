# syntax=docker/dockerfile:1

# -----------------------------
# Production-grade container image (2-stage)
# - Minimal base (slim)
# - Pinned dependencies
# - Non-root runtime user
# - No build tools left behind
# - Fix: ensure usable temp dirs for gunicorn when readonlyRootFilesystem is enabled in ECS
# -----------------------------

# -----------------------------
# Stage 1: builder (install deps)
# -----------------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Keep OS packages minimal (only what we need)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip tooling (pinned for reproducibility)
RUN python -m pip install --upgrade pip==26.0.1 wheel==0.46.3 setuptools

# Install runtime deps into a staging directory (clean copy into runtime image)
COPY app/requirements.txt /app/requirements.txt
RUN python -m pip install --prefix=/install -r /app/requirements.txt


# -----------------------------
# Stage 2: runtime
# -----------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Ensure Python uses a writable temp directory
    TMPDIR=/tmp \
    # Ensure gunicorn writes worker temp files to a writable path
    GUNICORN_CMD_ARGS="--worker-tmp-dir /tmp"

WORKDIR /app

# Keep OS packages minimal (only what we need)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create temp dirs with sticky bit (world-writable, safe default)
# This prevents gunicorn/tempfile failures on read-only root filesystem setups.
RUN mkdir -p /tmp /var/tmp /usr/tmp \
    && chmod 1777 /tmp /var/tmp /usr/tmp

# Copy installed deps from builder into runtime
COPY --from=builder /install /usr/local

# Copy application
COPY app /app

# Create non-root user
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Gunicorn for production (WSGI)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
