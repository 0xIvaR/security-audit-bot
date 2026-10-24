# Multi-stage minimal container for Automated GitHub PR Security Audit Bot
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim AS runtime

# Install git for diff parsing
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create unprivileged non-root user (uid 1001)
RUN useradd -u 1001 -m botuser

# Copy installed python dependencies from builder stage
COPY --from=builder /root/.local /home/botuser/.local
COPY src/ /app/src/

# Set ownership to botuser
RUN chown -R botuser:botuser /app /home/botuser

USER 1001

ENV PATH=/home/botuser/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "src.main"]
