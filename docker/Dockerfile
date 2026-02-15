# syntax=docker/dockerfile:1

# -----------------------------
# Stage 1: builder
# -----------------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip==26.0.1 wheel==0.46.3 setuptools

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
    TMPDIR=/tmp \
    GUNICORN_CMD_ARGS="--worker-tmp-dir /tmp"

WORKDIR /app

# We install gosu to drop privileges safely after fixing /tmp perms.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*

# Copy installed deps from builder
COPY --from=builder /install /usr/local

# Copy application
COPY app /app

# Create non-root user for the app process
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

# Entrypoint: fix permissions on mounted tmp dirs, then run gunicorn as appuser
RUN cat > /usr/local/bin/entrypoint.sh <<'EOF' \
  && chmod +x /usr/local/bin/entrypoint.sh
#!/bin/sh
set -eu

# These dirs may be volume-mounted in ECS and come in root-owned with restrictive perms.
# Make them usable for gunicorn tempfile usage.
mkdir -p /tmp /var/tmp /usr/tmp
chmod 1777 /tmp /var/tmp /usr/tmp || true

# Drop privileges and run the app as non-root
exec gosu appuser "$@"
EOF

EXPOSE 5000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
