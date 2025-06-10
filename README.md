# DynDNS Docker Client

Ein einfacher DynDNS-Updater für mehrere Provider, konfigurierbar über eine YAML-Datei.

## Konfiguration

Bearbeite die Datei `config.yaml` und trage deine Provider und Zugangsdaten ein:

```yaml
providers:
  - name: duckdns
    url: "https://www.duckdns.org/update"
    params:
      domains: "example"
      token: "your-duckdns-token"
      ip: ""
  - name: noip
    url: "https://dynupdate.no-ip.com/nic/update"
    params:
      hostname: "example.ddns.net"
      username: "your-noip-username"
      password: "your-noip-password"
      ip: ""
```

## Nutzung mit Docker

```sh
docker build -t dyndns-client .
docker run --rm dyndns-client
```

## Nutzung mit Docker Compose

Erstelle eine `docker-compose.yml`:

```yaml
version: "3.8"
services:
  dyndns:
    build: .
    container_name: dyndns-client
    restart: unless-stopped
    volumes:
      - ./config.yaml:/app/config.yaml:ro
```

Starte den Container mit:

```sh
docker compose up -d
```

## Abhängigkeiten

- Python 3.11
- requests
- pyyaml

Diese werden automatisch im Docker-Image installiert.