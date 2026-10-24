# Multi-stage minimal container for Automated GitHub PR Security Audit Bot
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim AS runtime

# Install git for diff parsing and configure safe.directory for container mounts
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    git config --system --add safe.directory "*" && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed python dependencies from builder stage to system-wide site-packages
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY src/ /app/src/

# Create unprivileged non-root user (uid 1001)
RUN useradd -u 1001 -m botuser && \
    chown -R botuser:botuser /app

USER 1001

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.main"]
