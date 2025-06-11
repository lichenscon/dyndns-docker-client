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

providers:
  - name: duckdns
    protocol: dyndns2
    url: "https://www.duckdns.org/update"
    token: "your-duckdns-token"
    domain: "example"

  - name: noip-home
    protocol: dyndns2
    url: "https://dynupdate.no-ip.com/nic/update"
    username: "your-noip-username"
    password: "your-noip-password"
    hostname: "example.ddns.net"

  - name: mein-cloudflare
    protocol: cloudflare
    zone: "deinedomain.tld"
    api_token: "dein_cloudflare_api_token"
    record_name: "sub.domain.tld"

  - name: mein-ipv64
    protocol: ipv64
    url: "https://ipv64.net/nic/update"
    auth_method: "token"
    token: "dein_update_token"
    domain: "deinedomain.ipv64.net"

  - name: dynu
    protocol: dyndns2
    url: "https://api.dynu.com/nic/update"
    auth_method: "basic"
    username: "deinuser"
    password: "deinpass"
    hostname: "deinedomain.dynu.net"
```

### Hinweise zur Konfiguration

- **timer:** Wie oft (in Sekunden) die IP geprüft und ggf. ein Update durchgeführt wird.
- **ip_service:** URL eines Dienstes, der die aktuelle öffentliche IPv4 zurückliefert (z.B. [ipify.org](https://www.ipify.org/)).
- **providers:** Liste der zu aktualisierenden Dienste. Jeder Eintrag beschreibt einen Provider.
- **protocol:** Muss einer der folgenden Werte sein: `cloudflare`, `ipv64`, `dyndns2`.
- **IPv6:**  
  Um IPv6 zu nutzen, kann ein zusätzlicher Service wie `https://api64.ipify.org` abgefragt und als `ip6` an die Update-Funktionen übergeben werden.  
  (Die Implementierung muss ggf. im Code ergänzt werden.)

#### Provider-spezifische Felder

- **Cloudflare:**  
  - `zone`: Deine Domain (z.B. `example.com`)
  - `api_token`: Cloudflare API-Token mit DNS-Rechten
  - `record_name`: Der zu aktualisierende DNS-Record (z.B. `sub.domain.tld`)

- **ipv64:**  
  - `url`: Update-URL
  - `auth_method`: "token", "basic" oder "bearer"
  - `token`: Dein Update-Token
  - `domain`: Deine Domain bei ipv64.net

- **DynDNS2-kompatible Provider (DuckDNS, NoIP, Dynu, etc.):**  
  - `url`: Update-URL
  - `auth_method`: Optional, z.B. "basic" für Dynu
  - `username`, `password`, `token`: Zugangsdaten je nach Provider
  - `hostname` oder `domain`: Je nach Provider (siehe deren API-Doku)

---

## Docker: Build & Run

### 1. **Builden des Containers**

Im Projektverzeichnis:

```sh
docker build -t dyndns-client .
```

### 2. **Starten des Containers**

```sh
docker run -d \
  --name dyndns-client \
  -v $(pwd)/config.yaml:/app/config.yaml \
  dyndns-client
```

- Das Volume-Mapping sorgt dafür, dass Änderungen an deiner lokalen `config.yaml` sofort im Container übernommen werden.

### 3. **Logs anzeigen**

```sh
docker logs -f dyndns-client
```

---

## Erweiterungsmöglichkeiten

- **IPv6-Unterstützung:**  
  Ergänze in der Konfiguration und im Code einen IPv6-Service (z.B. `https://api64.ipify.org`) und übergib die Adresse an die Provider, die AAAA-Records unterstützen.
- **Weitere Provider:**  
  Neue Provider können einfach durch Hinzufügen eines neuen Blocks mit entsprechendem `protocol` ergänzt werden.
- **Automatisches Reload:**  
  Änderungen an der `config.yaml` werden automatisch erkannt und angewendet, ohne den Container neu zu starten.

---

## Hinweise

- Die Felder `domain` und `hostname` sind je nach Provider unterschiedlich zu setzen.  
  Prüfe die jeweilige API-Dokumentation deines DynDNS-Anbieters!
- Das Projekt ist für den Dauerbetrieb als Docker-Container ausgelegt.
- Die Logs geben detailliert Auskunft über alle Update-Vorgänge und Fehler.

---

## Beispiel für IPv6 (optional)

```yaml
ip_service: "https://api.ipify.org"
ip6_service: "https://api64.ipify.org"
```
Im Code kannst du dann analog zu `get_public_ip` auch `get_public_ipv6` verwenden und an die Provider übergeben, die IPv6 unterstützen.

---

## Support & Mitmachen

Pull Requests und Verbesserungen sind willkommen!  
Bei Fragen oder Problemen bitte ein Issue auf GitHub eröffnen.

---

