# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Defaults to the canonical Docker Hub path so `docker build .` works
# locally without any build args. CI overrides this to GitLab's
# group-level dependency proxy via
# `--build-arg HUB=${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}` so the
# Hub rate limit doesn't take builds down. Mirrors the relay
# Dockerfile pattern (see relay!270).
ARG HUB=docker.io/library

# Planner stage: generate recipe.json for dependency caching
FROM ${HUB}/rust:1.93-bookworm AS planner
# Pin cargo-chef so the planner binary is reproducible and not affected by a
# compromised future release.
RUN cargo install cargo-chef --version 0.1.77
WORKDIR /app
COPY . ./ohttp-relay
RUN cd ohttp-relay && cargo chef prepare --recipe-path /app/recipe.json

# Cook stage: build dependencies only (cached layer)
FROM ${HUB}/rust:1.93-bookworm AS cook
RUN cargo install cargo-chef --version 0.1.77
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build stage: compile the actual source (deps already cached)
FROM ${HUB}/rust:1.93-bookworm AS builder
WORKDIR /app
COPY --from=cook /app/target target
COPY --from=cook /usr/local/cargo /usr/local/cargo
COPY . ./ohttp-relay
RUN cd ohttp-relay && cargo build --release
# Prepare build metadata (distroless has no shell, so we do it here)
ARG BUILD_INFO='{"sha":"development","ref":"local","built":"unknown"}'
RUN echo "${BUILD_INFO}" > /tmp/build-info.json

# Stage libgcc_s.so.1 at its native multiarch path so the runtime COPY below
# is arch-agnostic: x86_64-linux-gnu on amd64, aarch64-linux-gnu on arm64.
# Required to build this image natively on the arm64 Pi runner.
RUN set -eux; \
    lib="$(find /lib /usr/lib -name 'libgcc_s.so.1' | head -n1)"; \
    mkdir -p "/staging$(dirname "$lib")"; \
    cp "$lib" "/staging$(dirname "$lib")/"

# Runtime stage — distroless glibc without unused OpenSSL libraries.
# Pinned by digest to prevent supply-chain drift from `latest` tag re-pointing.
FROM gcr.io/distroless/base-nossl-debian12@sha256:36e60081779eefd6a7dc9796e6aafaecd632bc282a8ba76fdb7c8f89a75ea6c7

# Rust binaries (and the C code in aws-lc-rs) still need libgcc_s for panic
# unwinding. base-nossl omits it; staged arch-agnostically in the builder above.
COPY --from=builder /staging/ /

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
