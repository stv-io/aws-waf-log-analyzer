# Multi-stage Dockerfile for AWS WAF Log Analyzer
# Base image: astral/uv:python3.13-trixie

# Build stage
FROM astral/uv:python3.13-trixie AS builder

# Set working directory
WORKDIR /app

# Copy package definition and source
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install dependencies
RUN uv pip install --system -e .

# Production stage
FROM astral/uv:python3.13-trixie AS production

# Set labels
LABEL maintainer="steve@stv.io"
LABEL description="AWS WAF Log Analyzer - High-performance log analysis tool"
LABEL version="0.1.0"

# Create non-root user
RUN groupadd -r wafanalyzer && useradd -r -g wafanalyzer wafanalyzer

# Set working directory
WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY examples/ ./examples/
COPY README.md ./

# Set permissions
RUN chown -R wafanalyzer:wafanalyzer /app

# Switch to non-root user
USER wafanalyzer

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV AWS_DEFAULT_REGION=us-east-1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -m aws_waf_log_analyzer.cli --version || exit 1

# Default command
ENTRYPOINT ["python3", "-m", "aws_waf_log_analyzer.cli"]
CMD ["--help"]
