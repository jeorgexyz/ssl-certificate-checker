FROM elixir:1.14-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    openssl \
    build-base \
    git

WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Copy dependency files
COPY mix.exs mix.lock ./
RUN mix deps.get --only prod

# Copy application files
COPY lib ./lib
COPY config ./config

# Compile the application
RUN mix compile

# Runtime stage
FROM elixir:1.14-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    bash

WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Copy compiled files from builder
COPY --from=builder /app/_build /app/_build
COPY --from=builder /app/deps /app/deps
COPY --from=builder /app/mix.exs /app/mix.lock ./
COPY --from=builder /app/lib ./lib

# Set environment
ENV MIX_ENV=prod

# Default command
ENTRYPOINT ["mix", "run", "-e"]
CMD ["SslCertificateChecker.CLI.main(System.argv())"]

# Usage:
# Build: docker build -t ssl-certificate-checker .
# Run: docker run ssl-certificate-checker google.com
# Run with JSON: docker run ssl-certificate-checker "SslCertificateChecker.CLI.main([\"google.com\", \"--json\"])"
