# Container deployment

`docker-compose.yml` runs the probefleet coordinator behind an HTTPS reverse
proxy. Configuration comes from `.env`; the container renders
`coordinator.toml` from it on every start and generates the signing seed and
cookie/CSRF secret once, in the `probefleet-data` volume (`/data`).

```sh
cd dist
cp .env.example .env     # set PROBEFLEET_PUBLIC_URL, optionally a login provider
docker compose up -d --build
```

## Reverse proxy

Terminate TLS at the proxy and forward all paths to the coordinator
(`127.0.0.1:7000` by default), including WebSocket upgrades (`/agent`,
`/client`). Use a long read timeout for those; the coordinator pings every
`PROBEFLEET_PING_INTERVAL_SECS` (20 s). `/healthz` is the liveness endpoint.

Caddy:

```
fleet.example {
    reverse_proxy 127.0.0.1:7000
}
```

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:7000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;  # map $http_upgrade
    proxy_set_header Host $host;
    proxy_read_timeout 1h;
}
```

## Admin commands

The host-shell admin verbs run inside the container and find the config
automatically:

```sh
docker compose exec coordinator probefleet coordinator user-token --username alice
docker compose exec coordinator probefleet coordinator auth-key --tag lab
docker compose exec coordinator probefleet coordinator org create team --admin alice
```

## Backups

Everything stateful (SQLite database, signing seed, CSRF secret) is in the
`probefleet-data` volume. Losing the signing seed invalidates outstanding
lease capabilities; losing the CSRF secret only logs browsers out.
