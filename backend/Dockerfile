# Memory Forensics Platform -- Backend (FastAPI + Volatility3 + YARA)
#
# NOTE: this Dockerfile has not been build-tested in an actual Docker
# environment (none was available while authoring it) -- please verify with
# `docker compose up --build` and report any issues before relying on it
# for deployment. It follows the deployment architecture described in
# SYSTEM_ARCHITECTURE_DESIGN_DOCUMENT.docx (section 7): a single,
# Dockerized application server.

FROM python:3.12-slim

# build-essential + libssl-dev cover the case where yara-python has no
# prebuilt wheel for the target platform/architecture and must compile from
# source; harmless (just unused) if a wheel is available instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install pinned dependencies first so this layer is cached across rebuilds
# that only change application code, not dependencies.
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt

COPY . .

# Runtime directories. uploads/reports/yara_rules and the SQLite DB file are
# expected to be mounted as volumes in docker-compose.yml for persistence
# and (for yara_rules) live editability without rebuilding the image
# (FR-14) -- these mkdir calls just ensure sane defaults exist if the
# container is run standalone without those mounts.
RUN mkdir -p /app/data /app/uploads /app/reports /app/yara_rules

ENV DATABASE_URL=sqlite:////app/data/memforensics.db
ENV UPLOAD_DIR=/app/uploads
ENV REPORTS_DIR=/app/reports
ENV YARA_RULES_DIR=/app/yara_rules

# Run as a non-root user rather than the container default (root) -- a
# process handling untrusted uploaded files should not run with root
# privileges inside its container. The chown happens before switching users
# (and before any named volumes are mounted at container start) so that
# when Docker Compose creates its named volumes on first run, they inherit
# this ownership from the image's existing directory content, rather than
# defaulting to root-owned and unwritable by appuser.
RUN groupadd --system appuser && useradd --system --gid appuser --home-dir /app appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
