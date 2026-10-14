#!/bin/sh
# Run probefleet as PUID:PGID even when invoked as root (e.g. via
# `docker compose exec`), so admin commands cannot create root-owned files
# (SQLite WAL/SHM, secrets) that the coordinator could then not open.
if [ "$(id -u)" = 0 ]; then
    exec setpriv --reuid="${PUID:-10001}" --regid="${PGID:-10001}" --clear-groups \
        /usr/local/libexec/probefleet "$@"
fi
exec /usr/local/libexec/probefleet "$@"
