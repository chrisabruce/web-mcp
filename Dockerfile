# Base images are pulled via Google's public Docker Hub mirror, which is unaffected by
# Docker Hub outages and anonymous pull limits. Use `--build-arg REGISTRY=docker.io/library`
# to pull from Docker Hub directly.
ARG REGISTRY=mirror.gcr.io/library

# ---- build -----------------------------------------------------------------
FROM ${REGISTRY}/rust:1.99-bookworm AS build
# BoringSSL (used by wreq for browser TLS impersonation) needs cmake + clang to build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang libclang-dev git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/web-mcp /usr/local/bin/web-mcp

# ---- runtime ---------------------------------------------------------------
FROM ${REGISTRY}/debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin web-mcp \
 && install -d -o web-mcp -g web-mcp -m 0700 /data
COPY --from=build /usr/local/bin/web-mcp /usr/local/bin/web-mcp
USER web-mcp
ENV WEB_MCP_BIND=0.0.0.0:8787 \
    WEB_MCP_DATA_DIR=/data \
    RUST_LOG=info
# SQLite database: user keys, saved site logins, sessions. Mount a volume here.
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8787/health || exit 1
ENTRYPOINT ["web-mcp"]
CMD ["serve"]
