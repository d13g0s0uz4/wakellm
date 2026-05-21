# ── Runtime: pure Python ─────────────────────────────────────────────────────
FROM python:3.12-alpine AS runtime

# Disable Python output buffering so Cloud Run logs appear in real-time
ENV PYTHONUNBUFFERED=1

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Install system packages for SSL/TLS certificate verification
RUN apk add --no-cache ca-certificates

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python source and default sources config
COPY --chown=appuser:appgroup src/ ./src/
COPY --chown=appuser:appgroup config/ ./config/

USER appuser

# Cloud Run Jobs pass the command via the ARGS override in the job definition.
ENTRYPOINT ["python", "-m", "src"]

# ── Dev/test stage (adds pytest + test sources) ───────────────────────────────
FROM runtime AS dev

USER root
COPY pyproject.toml ./
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY --chown=appuser:appgroup tests/ ./tests/

USER appuser
