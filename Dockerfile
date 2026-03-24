# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Planner stage: generate recipe.json for dependency caching
FROM rust:1.93-bookworm AS planner
RUN cargo install cargo-chef
WORKDIR /app
COPY . ./ohttp-relay
RUN cd ohttp-relay && cargo chef prepare --recipe-path /app/recipe.json

# Cook stage: build dependencies only (cached layer)
FROM rust:1.93-bookworm AS cook
RUN cargo install cargo-chef
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build stage: compile the actual source (deps already cached)
FROM rust:1.93-bookworm AS builder
WORKDIR /app
COPY --from=cook /app/target target
COPY --from=cook /usr/local/cargo /usr/local/cargo
COPY . ./ohttp-relay
RUN cd ohttp-relay && cargo build --release
# Prepare build metadata (distroless has no shell, so we do it here)
ARG BUILD_INFO='{"sha":"development","ref":"local","built":"unknown"}'
RUN echo "${BUILD_INFO}" > /tmp/build-info.json

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/cc-debian12:latest

COPY --from=builder /app/ohttp-relay/target/release/vauchi-ohttp-relay /usr/local/bin/
COPY --from=builder /tmp/build-info.json /usr/share/build-info.json

LABEL service="vauchi-ohttp-relay"

# Expose default port
EXPOSE 8082

# Run as non-root (distroless provides uid 65534/nobody)
USER nonroot

# Environment variables with defaults
ENV OHTTP_RELAY_LISTEN_ADDR=0.0.0.0:8082
ENV RUST_LOG=vauchi_ohttp_relay=info

# No HEALTHCHECK — distroless has no shell/curl.
ENTRYPOINT ["vauchi-ohttp-relay"]
