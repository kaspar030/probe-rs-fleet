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
 && mkdir -p /data
# The real binary lives in libexec; /usr/local/bin/probefleet is a wrapper
# that drops root to PUID:PGID, so `docker compose exec coordinator
# probefleet ...` never leaves root-owned files in the data directory.
COPY --from=build /out/probefleet /usr/local/libexec/probefleet
COPY dist/entrypoint.sh /usr/local/bin/probefleet-entrypoint
COPY dist/probefleet-wrapper.sh /usr/local/bin/probefleet

# Everything persistent lives under /data. With these set, the XDG default
# paths resolve into the volume, so admin verbs (`coordinator user-token`,
# `coordinator auth-key`, ...) find the config without extra flags.
ENV HOME=/data \
    XDG_CONFIG_HOME=/data/config \
    XDG_DATA_HOME=/data/share \
    RUST_LOG=info \
    PUID=10001 \
    PGID=10001
# Starts as root only to fix ownership of /data (bind mounts arrive owned by
# whoever created them on the host), then runs everything as PUID:PGID.
VOLUME /data
EXPOSE 7000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://127.0.0.1:7000/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/probefleet-entrypoint"]
CMD ["probefleet", "coordinator"]
