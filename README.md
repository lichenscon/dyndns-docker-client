# DynDNS Docker Client

## Übersicht

Dieses Projekt ist ein flexibler DynDNS-Client für verschiedene Provider (z.B. Cloudflare, ipv64, DuckDNS, NoIP, Dynu) und läuft als Docker-Container.  
Es unterstützt IPv4 und optional IPv6, prüft regelmäßig die öffentliche IP und aktualisiert die DNS-Einträge bei den konfigurierten Diensten.

---

## Features

- **Mehrere Provider:** Unterstützt Cloudflare, ipv64, DuckDNS, NoIP, Dynu und andere DynDNS2-kompatible Dienste.
- **IPv4 & IPv6:** Aktualisiert A- und AAAA-Records, wenn gewünscht.
- **Automatisches Nachladen:** Änderungen an der `config.yaml` werden automatisch erkannt und übernommen.
- **Flexible Konfiguration:** Jeder Provider kann beliebig benannt werden, der Typ wird über das Feld `protocol` gesteuert.
- **Detailliertes Logging:** Zeigt an, ob ein Update durchgeführt wurde, nicht nötig war oder ein Fehler auftrat.

---

## Konfiguration (`config.yaml`)

Die Datei `config.yaml` steuert das Verhalten des Containers.  
**Beispiel:**

```yaml
timer: 300  # Intervall in Sekunden für die IP-Prüfung
ip_service: "https://api.ipify.org"  # Service zum Abrufen der öffentlichen IPv4
ip6_service: "https://api64.ipify.org"  # (Optional) Service zum Abrufen der öffentlichen IPv6

providers:
  - name: duckdns
    protocol: dyndns2
    url: "https://www.duckdns.org/update"
    token: "your-duckdns-token"
    domain: "example"  # DuckDNS erwartet 'domain'

  - name: noip-home
    protocol: dyndns2
    url: "https://dynupdate.no-ip.com/nic/update"
    username: "your-noip-username"
    password: "your-noip-password"
    hostname: "example.ddns.net"  # NoIP erwartet 'hostname'

  - name: mein-cloudflare
    protocol: cloudflare
    zone: "deinedomain.tld"
    api_token: "dein_cloudflare_api_token"
    record_name: "sub.domain.tld"

  - name: mein-ipv64
    protocol: ipv64
    # url ist NICHT nötig für ipv64, wird im Code fest gesetzt!
    auth_method: "token"
    token: "dein_update_token"
    domain: "deinedomain.ipv64.net"  # ipv64 erwartet 'domain'

  - name: dynu
    protocol: dyndns2
    url: "https://api.dynu.com/nic/update"
    auth_method: "basic"
    username: "deinuser"
    password: "deinpass"
    hostname: "deinedomain.dynu.net"  # Dynu erwartet 'hostname'
```

### Hinweise zur Konfiguration

- **timer:** Wie oft (in Sekunden) die IP geprüft und ggf. ein Update durchgeführt wird.
- **ip_service:** URL eines Dienstes, der die aktuelle öffentliche IPv4 zurückliefert (z.B. [ipify.org](https://www.ipify.org/)).
- **ip6_service:** (Optional) URL eines Dienstes, der die aktuelle öffentliche IPv6 zurückliefert (z.B. [api64.ipify.org](https://api64.ipify.org/)).
- **providers:** Liste der zu aktualisierenden Dienste. Jeder Eintrag beschreibt einen Provider.
- **protocol:** Muss einer der folgenden Werte sein: `cloudflare`, `ipv64`, `dyndns2`.
- **IPv6:**  
  Um IPv6 zu nutzen, trage einen passenden Service unter `ip6_service` ein. Die Adresse wird dann automatisch an Provider übergeben, die IPv6 unterstützen.

#### Provider-spezifische Felder

- **Cloudflare:**  
  - `zone`: Deine Domain (z.B. `example.com`)
  - `api_token`: Cloudflare API-Token mit DNS-Rechten
  - `record_name`: Der zu aktualisierende DNS-Record (z.B. `sub.domain.tld`)
  - **Hinweis:** Die URL ist im Code fest hinterlegt, du musst sie NICHT angeben!

- **ipv64:**  
  - `auth_method`: `"token"`, `"basic"` oder `"bearer"`
  - `token`: Dein Update-Token
  - `domain`: Deine Domain bei ipv64.net
  - **Hinweis:** Die URL ist im Code fest hinterlegt, du musst sie NICHT angeben!

- **DynDNS2-kompatible Provider (DuckDNS, NoIP, Dynu, etc.):**  
  - `url`: Update-URL (Pflicht!)
  - `auth_method`: Optional, z.B. `"basic"` für Dynu
  - `username`, `password`, `token`: Zugangsdaten je nach Provider
  - **domain** oder **hostname**:  
    - `domain`: Wird von DuckDNS und ipv64 erwartet (z.B. `"example"` oder `"deinedomain.ipv64.net"`)
    - `hostname`: Wird von NoIP und Dynu erwartet (z.B. `"example.ddns.net"` oder `"deinedomain.dynu.net"`)
    - `host`: Manche Provider erwarten diesen Namen – siehe deren API-Doku.

---

## Authentifizierung (`auth_method`)

### Beschreibung der Authentifizierungsmethoden

- **token:**  
  Das Token wird als Parameter (z.B. `key`, `token`) in der URL übergeben.
  ```yaml
  auth_method: "token"
  token: "dein_token"
  ```
- **basic:**  
  HTTP Basic Auth. Username und Passwort (oder Token) werden als HTTP-Auth-Header gesendet.
  ```yaml
  auth_method: "basic"
  username: "deinuser"
  password: "deinpass"
  ```
- **bearer:**  
  Das Token wird als Bearer-Token im HTTP-Header gesendet.
  ```yaml
  auth_method: "bearer"
  token: "dein_token"
  ```
- **Hinweis:**  
  Die meisten DynDNS2-Provider (NoIP, Dynu, etc.) nutzen `basic`.  
  DuckDNS und ipv64 nutzen meist `token`.

---

## domain, hostname und host

### Was ist der Unterschied?

- **domain:**  
  Wird meist für Anbieter wie DuckDNS oder ipv64 verwendet.  
  Beispiel:  
  ```yaml
  domain: "example"  # DuckDNS
  domain: "deinedomain.ipv64.net"  # ipv64
  ```
- **hostname:**  
  Wird von klassischen DynDNS2-Providern wie NoIP oder Dynu verwendet.  
  Beispiel:  
  ```yaml
  hostname: "example.ddns.net"  # NoIP
  hostname: "deinedomain.dynu.net"  # Dynu
  ```
- **host:**  
  Manche Provider (z.B. ältere DynDNS-Implementierungen) erwarten den Parameter als `host`.  
  Dein Code prüft automatisch alle drei Felder und verwendet das, was in der Config steht.

**Wichtig:**  
- Immer das Feld verwenden, das der jeweilige Provider laut seiner API-Dokumentation verlangt!
- Dein Code ist so gebaut, dass er automatisch das richtige Feld (`hostname`, `domain`, `host`) erkennt und verwendet.

---

## Docker: Build & Run

### Offizielles Image von Docker Hub

Du kannst direkt das aktuelle, stabile Image von Docker Hub verwenden:

```sh
docker pull alexfl1987/dyndns:latest-stable
```

Starte den Container mit deiner eigenen Konfiguration:

```sh
docker run -d \
  --name dyndns-client \
  -v $(pwd)/config.yaml:/app/config.yaml \
  alexfl1987/dyndns:latest-stable
```

> **Hinweis:**  
> Wenn du keine eigene `config.yaml` mountest, wird die Standard-Config aus dem Image verwendet.  
> Existiert keine `config.yaml`, gibt der Container beim Start einen Fehler aus.

---

## Schnellstart mit Docker (lokal bauen)

1. **Beispiel-Konfiguration kopieren:**

   Kopiere die mitgelieferte Beispiel-Konfiguration und passe sie an:
   ```sh
   cp config.example.yaml config.yaml
   # ...bearbeite config.yaml nach deinen Bedürfnissen...
   ```

2. **Docker-Image bauen:**
   ```sh
   docker build -t dyndns-client .
   ```

3. **Container starten (mit eigener config.yaml):**
   ```sh
   docker run -d \
     --name dyndns-client \
     -v $(pwd)/config.yaml:/app/config.yaml \
     dyndns-client
   ```

---

## Beispiel-Konfiguration

Eine vollständige, auskommentierte Beispiel-Konfiguration findest du in der Datei  
**`config.example.yaml`** im Repository.

**Ausschnitt:**
```yaml
# Intervall in Sekunden für die IP-Prüfung (z.B. alle 5 Minuten)
timer: 300

# Service zum Abrufen der öffentlichen IPv4-Adresse
ip_service: "https://api.ipify.org"

# Service zum Abrufen der öffentlichen IPv6-Adresse (optional)
# ip6_service: "https://api64.ipify.org"

providers:
#   - name: duckdns
#     protocol: dyndns2
#     url: "https://www.duckdns.org/update"
#     token: "your-duckdns-token"
#     domain: "example"

#   - name: mein-cloudflare
#     protocol: cloudflare
#     zone: "deinedomain.tld"
#     api_token: "dein_cloudflare_api_token"
#     record_name: "sub.domain.tld"

#   - name: mein-ipv64
#     protocol: ipv64
#     auth_method: "token"
#     token: "dein_update_token"
#     domain: "deinedomain.ipv64.net"
```

Weitere Beispiele und alle Optionen findest du direkt in der `config.example.yaml`.

---

## Hinweise zur Konfiguration

- Für **dyndns2**-Provider ist das Feld `url` **Pflicht**!
- Für **cloudflare** und **ipv64** ist die URL im Code fest hinterlegt, du musst sie **nicht** angeben.
- Je nach Provider werden die Felder `domain`, `hostname` oder `host` benötigt.
- `auth_method` kann `"token"`, `"basic"` oder `"bearer"` sein (je nach Provider/API).
- IPv6 wird nur genutzt, wenn du `ip6_service` angibst und der Provider es unterstützt.

---

## Fehlerbehandlung

- Existiert keine `config.yaml`, gibt der Container beim Start einen Fehler aus und beendet sich.
- Fehlerhafte Konfigurationen werden beim Start und bei jeder Änderung erkannt und mit einer klaren Fehlermeldung im Log ausgegeben.

---

## Mehr Details

Siehe die ausführlichen Kommentare in `config.example.yaml` und die weiteren Abschnitte in dieser README für alle Optionen und Beispiele.

---

## Beispiel für IPv6 (optional)

```yaml
ip_service: "https://api.ipify.org"
ip6_service: "https://api64.ipify.org"
```
Im Code wird dann automatisch auch die IPv6-Adresse abgefragt und an die Provider übergeben, die IPv6 unterstützen.

---

## Support & Mitmachen

Pull Requests und Verbesserungen sind willkommen!  
Bei Fragen oder Problemen bitte ein Issue auf GitHub eröffnen.

---

### Nur IPv4, nur IPv6 oder beides aktualisieren

Du kannst steuern, ob nur IPv4, nur IPv6 oder beide Adressen aktualisiert werden:

- **Nur IPv4:**  
  ```yaml
  ip_service: "https://api.ipify.org"
  ```
- **Nur IPv6:**  
  ```yaml
  ip6_service: "https://api64.ipify.org"
  ```
- **Beides:**  
  ```yaml
  ip_service: "https://api.ipify.org"
  ip6_service: "https://api64.ipify.org"
  ```

Wenn du einen der beiden Einträge weglässt, wird nur die jeweils angegebene Adresse aktualisiert.  
**Hinweis:** Nicht alle Provider unterstützen IPv6!

