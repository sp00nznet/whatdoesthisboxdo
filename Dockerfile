# WhatDoesThisBoxDo - Server Documentation Tool
# Containerized Web Interface

FROM python:3.11-slim

LABEL maintainer="WhatDoesThisBoxDo"
LABEL description="Server analysis and documentation generation tool"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir flask gunicorn psycopg2-binary cryptography

# Remove build dependencies to reduce image size
RUN apt-get purge -y --auto-remove gcc

# Copy application code
COPY . .

# Create directories for web app
RUN mkdir -p /app/web/uploads /app/web/output /app/web/data

# Set permissions
RUN chmod -R 755 /app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "300", "web.app:app"]
