#!/bin/sh
# Render the coordinator config from environment variables, creating the
# signing seed and cookie/CSRF secret on first start, then exec the command.
#
# The config is regenerated on every start, so the env file is the single
# source of truth. The secrets are generated once and kept in the volume.
set -eu

# Started as root: make /data writable for PUID:PGID (a bind-mounted host
# directory is typically owned by the host user or root), then re-run this
# script unprivileged. Only mismatched entries are touched.
if [ "$(id -u)" = 0 ]; then
    : "${PUID:=10001}" "${PGID:=10001}"
    if [ "$PUID" = 0 ]; then
        echo "refusing to run as root (PUID=0)" >&2
        exit 1
    fi
    find /data \( \! -user "$PUID" -o \! -group "$PGID" \) \
        -exec chown "$PUID:$PGID" {} +
    exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups "$0" "$@"
fi

if [ ! -w /data ]; then
    echo "/data is not writable by uid $(id -u); chown it on the host or set PUID/PGID" >&2
    exit 1
fi

: "${PROBEFLEET_PUBLIC_URL:?set PROBEFLEET_PUBLIC_URL (e.g. https://fleet.example)}"

config_dir="$XDG_CONFIG_HOME/probefleet/coordinator"
data_dir="$XDG_DATA_HOME/probefleet/coordinator"
config="$config_dir/coordinator.toml"
mkdir -p "$config_dir" "$data_dir"
umask 077

gen_secret() {
    if [ ! -s "$1" ]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$1"
        echo "generated $1" >&2
    fi
}
gen_secret "$data_dir/signing.seed"
gen_secret "$data_dir/csrf.secret"

# Quote a value as a TOML basic string.
q() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

tmp="$config.tmp"
{
    echo "# GENERATED from environment by probefleet-entrypoint on every start."
    echo "# Do not edit; change the env file (or PROBEFLEET_EXTRA_CONFIG) instead."
    echo "listen_addr = \"0.0.0.0:7000\""
    echo "public_url = $(q "$PROBEFLEET_PUBLIC_URL")"
    echo "sqlite_path = $(q "$data_dir/coordinator.sqlite")"
    echo "signing_key_path = $(q "$data_dir/signing.seed")"
    echo "csrf_secret_path = $(q "$data_dir/csrf.secret")"
    [ -n "${PROBEFLEET_DEFAULT_ORG:-}" ] && echo "default_org = $(q "$PROBEFLEET_DEFAULT_ORG")"
    [ -n "${PROBEFLEET_ALLOW_ORG_CREATION:-}" ] && echo "allow_org_creation = $PROBEFLEET_ALLOW_ORG_CREATION"
    [ -n "${PROBEFLEET_MAX_ORGS_PER_USER:-}" ] && echo "max_orgs_per_user = $PROBEFLEET_MAX_ORGS_PER_USER"
    [ -n "${PROBEFLEET_PING_INTERVAL_SECS:-}" ] && echo "ping_interval_secs = $PROBEFLEET_PING_INTERVAL_SECS"
    [ -n "${PROBEFLEET_PONG_TIMEOUT_SECS:-}" ] && echo "pong_timeout_secs = $PROBEFLEET_PONG_TIMEOUT_SECS"
    [ -n "${PROBEFLEET_SESSION_TTL_SECS:-}" ] && echo "session_ttl_secs = $PROBEFLEET_SESSION_TTL_SECS"

    # Free-form TOML for anything not covered above ([policy], more
    # providers, ...). Appended verbatim.
    if [ -n "${PROBEFLEET_EXTRA_CONFIG:-}" ]; then
        echo
        echo "# --- from $PROBEFLEET_EXTRA_CONFIG ---"
        cat "$PROBEFLEET_EXTRA_CONFIG"
        echo
    fi

    if [ -n "${PROBEFLEET_AUTH_KIND:-}" ]; then
        echo
        echo "[[auth.providers]]"
        echo "kind = $(q "$PROBEFLEET_AUTH_KIND")"
        [ -n "${PROBEFLEET_AUTH_NAME:-}" ] && echo "name = $(q "$PROBEFLEET_AUTH_NAME")"
        echo "client_id = $(q "${PROBEFLEET_AUTH_CLIENT_ID:?PROBEFLEET_AUTH_CLIENT_ID is required with PROBEFLEET_AUTH_KIND}")"
        echo "client_secret = $(q "${PROBEFLEET_AUTH_CLIENT_SECRET:?PROBEFLEET_AUTH_CLIENT_SECRET is required with PROBEFLEET_AUTH_KIND}")"
        [ -n "${PROBEFLEET_AUTH_ISSUER:-}" ] && echo "issuer = $(q "$PROBEFLEET_AUTH_ISSUER")"
    fi

    if [ -n "${PROBEFLEET_GITHUB_ACTIONS_AUDIENCE:-}" ]; then
        echo
        echo "[github_actions]"
        echo "audience = $(q "$PROBEFLEET_GITHUB_ACTIONS_AUDIENCE")"
    fi
    true
} > "$tmp"
mv "$tmp" "$config"

exec "$@"
