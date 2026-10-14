# probefleet coordinator image. Build context is the repository root:
#   docker build -f dist/Dockerfile .
# (docker-compose.yml in this directory does that for you.)

FROM docker.io/library/rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p probefleet \
 && install -Dm755 target/release/probefleet /out/probefleet

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin probefleet \
 && mkdir -p /data && chown probefleet:probefleet /data
COPY --from=build /out/probefleet /usr/local/bin/probefleet
COPY dist/entrypoint.sh /usr/local/bin/probefleet-entrypoint

# Everything persistent lives under /data. With these set, the XDG default
# paths resolve into the volume, so admin verbs (`coordinator user-token`,
# `coordinator auth-key`, ...) find the config without extra flags.
ENV HOME=/data \
    XDG_CONFIG_HOME=/data/config \
    XDG_DATA_HOME=/data/share \
    RUST_LOG=info
USER probefleet
VOLUME /data
EXPOSE 7000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://127.0.0.1:7000/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/probefleet-entrypoint"]
CMD ["probefleet", "coordinator"]
