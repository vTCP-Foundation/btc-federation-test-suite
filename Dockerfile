# Dockerfile for BTC Federation Test Suite
# Adapted from: https://github.com/vTCP-Foundation/vtcpd-test-suite/blob/main/Dockerfile
# Modified for single btc-federation-node binary execution

# Multi-stage build supporting both Ubuntu and Manjaro distributions
ARG DISTRO=ubuntu
FROM ubuntu:22.04 AS ubuntu-base
FROM manjarolinux/base:latest AS manjaro-base

# Select the appropriate base image
FROM ${DISTRO}-base AS base

# Install common dependencies
RUN if [ "$DISTRO" = "ubuntu" ]; then \
        apt-get update && \
        apt-get install -y \
            ca-certificates \
            curl \
            netcat-openbsd \
            procps \
            gettext-base && \
        rm -rf /var/lib/apt/lists/*; \
    elif [ "$DISTRO" = "manjaro" ]; then \
        pacman -Sy --noconfirm \
            ca-certificates \
            curl \
            netcat \
            procps-ng \
            gettext && \
        pacman -Scc --noconfirm; \
    fi

# Environment variables for node configuration
# These will be set by the test suite when creating containers
ENV PRIVATE_KEY=""
ENV IP_ADDRESS="0.0.0.0"
ENV PORT="9000"

# Environment variables for logging configuration
# Default values will be set if not provided
ENV LOGGING_FILE_NAME=""
ENV LOGGING_FILE_MAX_SIZE=""

# Set working directory
WORKDIR /btc-federation

# Copy BTC federation node binary from deps directory
# Following vtcpd-test-suite pattern for binary deployment
COPY deps/btc-federation-node /btc-federation/btc-federation-node
RUN chmod +x /btc-federation/btc-federation-node

# Create configuration generation script that uses environment variables
# Following vtcpd-test-suite pattern for environment variable substitution
RUN echo '#!/bin/bash' > /generate-config.sh && \
    echo '# Configuration generation script for BTC federation node' >> /generate-config.sh && \
    echo '# Adapted from vtcpd-test-suite configuration patterns' >> /generate-config.sh && \
    echo '# Uses environment variables set by the test suite' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo 'set -e' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo '# Validate required environment variables' >> /generate-config.sh && \
    echo 'if [ -z "$PRIVATE_KEY" ]; then' >> /generate-config.sh && \
    echo '    echo "Error: PRIVATE_KEY environment variable is required"' >> /generate-config.sh && \
    echo '    exit 1' >> /generate-config.sh && \
    echo 'fi' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo 'if [ -z "$IP_ADDRESS" ]; then' >> /generate-config.sh && \
    echo '    echo "Error: IP_ADDRESS environment variable is required"' >> /generate-config.sh && \
    echo '    exit 1' >> /generate-config.sh && \
    echo 'fi' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo 'if [ -z "$PORT" ]; then' >> /generate-config.sh && \
    echo '    echo "Error: PORT environment variable is required"' >> /generate-config.sh && \
    echo '    exit 1' >> /generate-config.sh && \
    echo 'fi' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo '# Set default values for logging configuration if not provided' >> /generate-config.sh && \
    echo 'if [ -z "$LOGGING_FILE_NAME" ]; then' >> /generate-config.sh && \
    echo '    LOGGING_FILE_NAME="btc-federation.log"' >> /generate-config.sh && \
    echo 'fi' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo 'if [ -z "$LOGGING_FILE_MAX_SIZE" ]; then' >> /generate-config.sh && \
    echo '    LOGGING_FILE_MAX_SIZE="10MB"' >> /generate-config.sh && \
    echo 'fi' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo '# Generate conf.yaml directly using environment variables' >> /generate-config.sh && \
    echo '# Following vtcpd-test-suite environment variable substitution pattern' >> /generate-config.sh && \
    echo 'cat > /btc-federation/conf.yaml << EOF' >> /generate-config.sh && \
    echo 'node:' >> /generate-config.sh && \
    echo '    private_key: '\$PRIVATE_KEY >> /generate-config.sh && \
    echo 'network:' >> /generate-config.sh && \
    echo '    addresses:' >> /generate-config.sh && \
    echo '        - /ip4/'\$IP_ADDRESS'/tcp/'\$PORT >> /generate-config.sh && \
    echo 'peers:' >> /generate-config.sh && \
    echo '    exchange_interval: 30s' >> /generate-config.sh && \
    echo '    connection_timeout: 10s' >> /generate-config.sh && \
    echo 'logging:' >> /generate-config.sh && \
    echo '    level: info' >> /generate-config.sh && \
    echo '    format: json' >> /generate-config.sh && \
    echo '    console_output: true' >> /generate-config.sh && \
    echo '    console_color: true' >> /generate-config.sh && \
    echo '    file_output: true' >> /generate-config.sh && \
    echo '    file_name: '\$LOGGING_FILE_NAME >> /generate-config.sh && \
    echo '    file_max_size: '\$LOGGING_FILE_MAX_SIZE >> /generate-config.sh && \
    echo 'EOF' >> /generate-config.sh && \
    echo '' >> /generate-config.sh && \
    echo 'echo "Configuration generated successfully:"' >> /generate-config.sh && \
    echo 'cat /btc-federation/conf.yaml' >> /generate-config.sh && \
    chmod +x /generate-config.sh

# Create startup script
RUN echo '#!/bin/bash' > /start-node.sh && \
    echo '# Startup script for BTC federation node' >> /start-node.sh && \
    echo '# Based on vtcpd-test-suite startup patterns' >> /start-node.sh && \
    echo '' >> /start-node.sh && \
    echo 'set -e' >> /start-node.sh && \
    echo '' >> /start-node.sh && \
    echo 'echo "Starting BTC federation node..."' >> /start-node.sh && \
    echo 'echo "Using configuration:"' >> /start-node.sh && \
    echo 'echo "  PRIVATE_KEY: [REDACTED]"' >> /start-node.sh && \
    echo 'echo "  IP_ADDRESS: '\$IP_ADDRESS'"' >> /start-node.sh && \
    echo 'echo "  PORT: '\$PORT'"' >> /start-node.sh && \
    echo 'echo "  LOGGING_FILE_NAME: '\$LOGGING_FILE_NAME'"' >> /start-node.sh && \
    echo 'echo "  LOGGING_FILE_MAX_SIZE: '\$LOGGING_FILE_MAX_SIZE'"' >> /start-node.sh && \
    echo '' >> /start-node.sh && \
    echo '# Generate configuration using environment variables' >> /start-node.sh && \
    echo '/generate-config.sh' >> /start-node.sh && \
    echo '' >> /start-node.sh && \
    echo '# Change to btc-federation directory and start the node' >> /start-node.sh && \
    echo 'cd /btc-federation' >> /start-node.sh && \
    echo 'exec ./btc-federation-node' >> /start-node.sh && \
    chmod +x /start-node.sh

# Health check using process check instead of port check for mock binary
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f "btc-federation" || exit 1

# Expose the default port (will be overridden by environment variable)
EXPOSE ${PORT}

# Use startup script as entrypoint
ENTRYPOINT ["/start-node.sh"] 