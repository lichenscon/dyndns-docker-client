# DynDNS Docker Client

Ein flexibler DynDNS-Updater für mehrere Provider, konfigurierbar über eine YAML-Datei. Unterstützt verschiedene Authentifizierungsarten und Protokolle (z.B. DynDNS2, Cloudflare, DuckDNS, No-IP, ipv64.net).

---

## Features

- **Mehrere Provider gleichzeitig** (DuckDNS, No-IP, Cloudflare, ipv64.net, beliebige DynDNS2-Provider)
- **Konfiguration über eine YAML-Datei**
- **Automatische Erkennung von IP-Änderungen** (IPv4, optional IPv6)
- **Flexible Authentifizierung:** Basic Auth, Token als Query, Bearer Token
- **Automatische Cloudflare-ID-Ermittlung** (nur Angabe von Zone und Record Name nötig)
- **Live-Reload:** Änderungen an der config.yaml werden sofort erkannt und angewendet
- **Ausführliches Logging** im Docker-Log

---

## Konfiguration (`config.yaml`)

Die Datei `config.yaml` steuert das Verhalten des Containers.  
Beispiel:

```yaml
timer: 300  # Intervall in Sekunden für die IP-Prüfung
ip_service: "https://api.ipify.org"  # Service zum Abrufen der öffentlichen IP

providers:
  - name: duckdns
    url: "https://www.duckdns.org/update"
    params:
      domains: "example"
      token: "your-duckdns-token"

  - name: noip
    url: "https://dynupdate.no-ip.com/nic/update"
    params:
      hostname: "example.ddns.net"
      username: "your-noip-username"
      password: "your-noip-password"

  - name: cloudflare
    zone: "deinedomain.tld"              # Deine Domain (z.B. example.com)
    api_token: "dein_cloudflare_api_token"
    record_name: "sub.domain.tld"        # Der zu aktualisierende DNS-Record

  - name: ipv64
    url: "https://ipv64.net/nic/update"
    auth_method: "token"                 # "token", "basic", "bearer"
    token: "dein_update_token"
    domain: "deinedomain.ipv64.net"

  - name: custom-dyndns2
    url: "https://example.com/nic/update"
    protocol: "dyndns2"
    auth_method: "basic"                 # "token", "basic", "bearer"
    username: "deinuser"                 # oder Token
    password: "deinpass"                 # oder Token
    domain: "deinedomain.example.com"
```

**Hinweise zur Konfiguration:**

- **timer:** Wie oft (in Sekunden) die IP geprüft und ggf. ein Update durchgeführt wird.
- **ip_service:** URL eines Dienstes, der die aktuelle öffentliche IP zurückliefert.
- **providers:** Liste der zu aktualisierenden Dienste. Jeder Eintrag beschreibt einen Provider.

### Authentifizierungsmöglichkeiten für DynDNS2-Provider

- **Basic Auth:**  
  ```yaml
  auth_method: "basic"
  username: "deinuser"   # oder Token
  password: "deinpass"   # oder Token
  ```
- **Token als Query-Parameter:**  
  ```yaml
  auth_method: "token"
  token: "deintoken"
  ```
- **Bearer Token:**  
  ```yaml
  auth_method: "bearer"
  token: "deintoken"
  ```

### Cloudflare

- Es reicht, `zone`, `api_token` und `record_name` anzugeben.
- Die Zone-ID und Record-ID werden automatisch per API ermittelt.
- Der API-Token benötigt DNS-Edit-Rechte für die Zone.

---

## Nutzung mit Docker

```sh
docker build -t dyndns-client .
docker run --rm -v $(pwd)/config.yaml:/app/config.yaml dyndns-client
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

---

## Logging & Verhalten

- **Alle Logs erscheinen im Docker-Log.**
- Beim Start und nach jeder Änderung an der `config.yaml` wird die Konfiguration neu geladen und ein Update-Durchlauf gestartet.
- Nach jedem Update-Durchlauf wird geloggt, wann der nächste Check erfolgt.
- Es wird geloggt, ob ein Update erfolgreich war, die IP gleich geblieben ist oder ein Fehler aufgetreten ist.
- Updatelimits (z.B. bei ipv64.net) werden erkannt und als Fehler geloggt.

---

## Abhängigkeiten

- Python 3.11
- requests
- pyyaml

Diese werden automatisch im Docker-Image installiert.

---

## Hinweise

- Die Datei `config.yaml` kann jederzeit geändert werden – der Container erkennt das automatisch.
- Für Provider mit DynDNS2-Protokoll kann die Authentifizierung flexibel gewählt werden.
- Die IP wird immer über den in der Config angegebenen Service ermittelt.
- IPv6-Unterstützung ist optional und kann bei Bedarf ergänzt werden.

