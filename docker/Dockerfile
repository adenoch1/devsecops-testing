# syntax=docker/dockerfile:1

# -----------------------------
# Production-grade container image
# - Minimal base (slim)
# - Pinned dependencies
# - Non-root runtime user
# - No build tools left behind
# -----------------------------

FROM python:3.11-slim AS runtime

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

# Install runtime deps first (better layer caching)
COPY app/requirements.txt /app/requirements.txt
RUN python -m pip install -r /app/requirements.txt

# Copy application
COPY app /app

# Create non-root user
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Gunicorn for production (WSGI)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
