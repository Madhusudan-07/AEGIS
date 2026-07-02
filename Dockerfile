# AEGIS live dashboard container — the Phase-3 dashboard, backed by a real Redis store.
FROM python:3.12-slim

# Least privilege: run as a non-root user.
RUN useradd --create-home --uid 10001 aegis
WORKDIR /app

# Pinned deps first (Docker layer cache), then the package + the extras the demo needs.
COPY requirements.txt pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install --no-cache-dir ".[django,sanitize]" "redis>=5.0"

USER aegis
EXPOSE 8008
ENV AEGIS_ENV=development \
    AEGIS_HOST=0.0.0.0

# AEGIS-protected SecureNotes app + live observability plane at /_aegis/
CMD ["python", "examples/dashboard/server.py"]
