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

## Abhängigkeiten

- Python 3.11
- requests
- pyyaml

Diese werden automatisch im Docker-Image installiert.