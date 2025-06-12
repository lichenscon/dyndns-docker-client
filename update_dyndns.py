import sys
import os
import time
import requests
import yaml
import logging

def setup_logging(level_str):
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(name)s --> %(message)s',
        handlers=[logging.StreamHandler()]
    )

def log(msg, level="INFO", section="MAIN"):
    logger = logging.getLogger(section)
    level = level.upper()
    if level == "DEBUG":
        logger.debug(msg)
    elif level == "INFO":
        logger.info(msg)
    elif level == "WARNING":
        logger.warning(msg)
    elif level == "ERROR":
        logger.error(msg)
    elif level == "CRITICAL":
        logger.critical(msg)
    else:
        logger.info(msg)

def get_public_ip(ip_service):
    """
    Holt die öffentliche IPv4-Adresse vom angegebenen Service.
    """
    try:
        response = requests.get(ip_service, timeout=10)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        log(f"Fehler beim Abrufen der öffentlichen IP: {e}", "ERROR")
        return None

def get_public_ipv6(ip_service="https://api64.ipify.org"):
    """
    Holt die öffentliche IPv6-Adresse vom angegebenen Service.
    """
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        log(f"Fehler beim Abrufen der öffentlichen IPv6: {e}", "ERROR")
        return None

def get_cloudflare_zone_id(api_token, zone_name):
    """
    Holt die Zone-ID für eine Cloudflare-Zone anhand des Namens.
    """
    url = f"https://api.cloudflare.com/client/v4/zones?name={zone_name}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    if data.get("success") and data["result"]:
        return data["result"][0]["id"]
    raise Exception(f"Zone-ID für {zone_name} nicht gefunden: {data}")

def get_cloudflare_record_id(api_token, zone_id, record_name):
    """
    Holt die Record-ID für einen DNS-Record in einer Cloudflare-Zone.
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    if data.get("success") and data["result"]:
        return data["result"][0]["id"]
    raise Exception(f"DNS-Record-ID für {record_name} nicht gefunden: {data}")

def update_cloudflare(provider, ip, ip6=None):
    """
    Aktualisiert einen A- und ggf. AAAA-Record bei Cloudflare, falls sich die IP geändert hat.
    Gibt "updated", "nochg" oder False zurück.
    """
    api_token = provider['api_token']
    zone = provider['zone']
    record_name = provider['record_name']
    zone_id = get_cloudflare_zone_id(api_token, zone)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    updated = False
    nochg = True

    # --- IPv4 (A-Record) ---
    if ip:
        # Hole Record-ID für A-Record
        url_a = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}&type=A"
        resp_a = requests.get(url_a, headers=headers)
        data_a = resp_a.json()
        log(f"Cloudflare GET A response: {data_a}", section="CLOUDFLARE")
        if data_a.get("success") and data_a["result"]:
            record_a = data_a["result"][0]
            if record_a["content"] == ip:
                log(f"Kein Update notwendig (IPv4 bereits gesetzt: {ip}).", "INFO", section="CLOUDFLARE")
            else:
                # Update A-Record
                url_patch = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_a['id']}"
                data_patch = {
                    "type": "A",
                    "name": record_name,
                    "content": ip
                }
                resp_patch = requests.patch(url_patch, json=data_patch, headers=headers)
                log(f"Cloudflare PATCH A response: {resp_patch.text}", section="CLOUDFLARE")
                if resp_patch.ok:
                    updated = True
                    nochg = False
        else:
            log(f"A-Record {record_name} nicht gefunden oder Fehler: {data_a}", "ERROR", section="CLOUDFLARE")
            nochg = False

    # --- IPv6 (AAAA-Record) ---
    if ip6:
        url_aaaa = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}&type=AAAA"
        resp_aaaa = requests.get(url_aaaa, headers=headers)
        data_aaaa = resp_aaaa.json()
        log(f"Cloudflare GET AAAA response: {data_aaaa}", section="CLOUDFLARE")
        if data_aaaa.get("success") and data_aaaa["result"]:
            record_aaaa = data_aaaa["result"][0]
            if record_aaaa["content"] == ip6:
                log(f"Kein Update notwendig (IPv6 bereits gesetzt: {ip6}).", "INFO", section="CLOUDFLARE")
            else:
                # Update AAAA-Record
                url_patch = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_aaaa['id']}"
                data_patch = {
                    "type": "AAAA",
                    "name": record_name,
                    "content": ip6
                }
                resp_patch = requests.patch(url_patch, json=data_patch, headers=headers)
                log(f"Cloudflare PATCH AAAA response: {resp_patch.text}", section="CLOUDFLARE")
                if resp_patch.ok:
                    updated = True
                    nochg = False
        else:
            log(f"AAAA-Record {record_name} nicht gefunden oder Fehler: {data_aaaa}", "ERROR", section="CLOUDFLARE")
            nochg = False

    if updated:
        return "updated"
    if nochg:
        return "nochg"
    return False

def update_ipv64(provider, ip, ip6=None):
    """
    Aktualisiert einen Record bei ipv64.net.
    Unterstützt IPv4 und IPv6.
    Gibt "updated", "nochg" oder False zurück.
    Die URL ist fest im Code hinterlegt.
    """
    # Feste URL für ipv64.net
    url = "https://ipv64.net/nic/update"
    params = {}
    if 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    auth = None
    headers = {}
    auth_method = provider.get('auth_method', 'token')
    token = provider.get('token')
    if auth_method == "token":
        params['key'] = token
    elif auth_method == "basic":
        auth = ('none', token)
    elif auth_method == "bearer":
        headers['Authorization'] = f"Bearer {token}"
    if ip:
        params['ip'] = ip
    if ip6:
        params['ip6'] = ip6
    response = requests.get(url, params=params, auth=auth, headers=headers)
    log(f"ipv64 response: {response.text}", section="IPV64")
    resp_text = response.text.lower().strip()
    # Updatelimit-Check
    if "overcommited" in resp_text or response.status_code == 403:
        log("Updateintervall bei ipv64.net überschritten! Updatelimit erreicht.", "ERROR", section="IPV64")
        return False
    # Kein Update notwendig
    if "nochg" in resp_text or "no change" in resp_text:
        log("Kein Update notwendig (nochg).", "INFO", section="IPV64")
        return "nochg"
    # Erfolg
    if "good" in resp_text or "success" in resp_text:
        return "updated"
    # Fehler
    log(f"ipv64-Update fehlgeschlagen: {response.text}", "ERROR", section="IPV64")
    return False

def update_dyndns2(provider, ip, ip6=None):
    """
    Aktualisiert einen DynDNS2-kompatiblen Provider (z.B. DuckDNS, NoIP, Dynu).
    Unterstützt IPv4 und IPv6.
    Gibt "updated", "nochg" oder False zurück.
    """
    url = provider['url']
    params = {}
    # Domain/Host/Hostname
    if 'hostname' in provider:
        params['hostname'] = provider['hostname']
    elif 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    # IP
    if ip:
        params['myip'] = ip  # Dynu erwartet 'myip'
    if ip6:
        params['myipv6'] = ip6

    # Authentifizierung
    auth = None
    headers = {}
    auth_method = provider.get('auth_method', 'token')
    token = provider.get('token')
    username = provider.get('username')
    password = provider.get('password')

    if auth_method == "basic":
        auth = (username or token, password or token or "x")
    elif auth_method == "bearer":
        headers['Authorization'] = f"Bearer {token}"
    else:
        if 'key' in provider:
            params['key'] = provider['key']
        elif 'user' in provider:
            params['user'] = provider['user']
        elif 'token' in provider:
            params['token'] = provider['token']
        else:
            params['key'] = token

    response = requests.get(url, params=params, auth=auth, headers=headers)
    provider_name = provider.get('name', 'dyndns2')
    log(f"[{provider_name}] response: {response.text}", section="DYNDNS2")

    # Erfolg prüfen
    resp_text = response.text.lower().strip()
    if "nochg" in resp_text:
        log(f"[{provider_name}] Kein Update notwendig (nochg).", "INFO", section="DYNDNS2")
        return "nochg"
    elif any(success in resp_text for success in ["good", "success"]):
        return "updated"
    else:
        log(
            f"[{provider_name}] DynDNS2-Update fehlgeschlagen: {response.text}",
            "ERROR",
            section="DYNDNS2"
        )
        return False

def validate_config(config):
    """
    Prüft die config.yaml auf notwendige Felder und gibt Fehler mit Zeilenangabe aus.
    Gibt True zurück, wenn alles passt, sonst False.
    """
    required_top = ["timer", "providers"]
    allowed_protocols = ("cloudflare", "ipv64", "dyndns2")
    for key in required_top:
        if key not in config:
            log(f"Fehlender Schlüssel '{key}' in config.yaml.", "ERROR")
            return False
    if not isinstance(config["providers"], list):
        log("Das Feld 'providers' muss eine Liste sein.", "ERROR")
        return False
    for idx, provider in enumerate(config["providers"]):
        if "protocol" not in provider:
            log(f"Fehlendes Feld 'protocol' bei Provider #{idx+1} ({provider.get('name','?')}) in config.yaml.", "ERROR")
            return False
        if provider["protocol"] not in allowed_protocols:
            log(
                f"Ungültiges Feld 'protocol' ('{provider['protocol']}') bei Provider #{idx+1} ({provider.get('name','?')}) in config.yaml. "
                f"Erlaubt: {', '.join(allowed_protocols)}.",
                "ERROR"
            )
            return False
        # Nur für cloudflare und dyndns2 ist url Pflicht, nicht für ipv64!
        if "url" not in provider and provider["protocol"] not in ("cloudflare", "ipv64"):
            log(f"Fehlendes Feld 'url' bei Provider #{idx+1} ({provider.get('name','?')}) in config.yaml.", "ERROR")
            return False
        # Weitere Checks je nach protocol
        if provider["protocol"] == "cloudflare":
            for field in ("zone", "api_token", "record_name"):
                if field not in provider:
                    log(f"Fehlendes Feld '{field}' bei Cloudflare-Provider #{idx+1} ({provider.get('name','?')}) in config.yaml.", "ERROR")
                    return False
    return True

def update_provider(provider, ip, ip6=None, log_success_if_nochg=True):
    """
    Wählt anhand des Protokolls die passende Update-Funktion für den Provider.
    Loggt das Ergebnis und gibt True (Update/nochg) oder False (Fehler) zurück.
    """
    try:
        if provider.get("protocol") == "cloudflare":
            result = update_cloudflare(provider, ip)
            if result == "updated":
                log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section="CLOUDFLARE")
            elif result == "nochg":
                if log_success_if_nochg:
                    log(f"Provider '{provider.get('name')}' war bereits aktuell, kein Update durchgeführt.", "INFO", section="CLOUDFLARE")
            else:
                log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR", section="CLOUDFLARE")
            return result == "updated" or (log_success_if_nochg and result == "nochg")
        if provider.get("protocol") == "ipv64":
            result = update_ipv64(provider, ip, ip6)
            if result == "updated":
                log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section="IPV64")
            elif result == "nochg":
                if log_success_if_nochg:
                    log(f"Provider '{provider.get('name')}' war bereits aktuell, kein Update durchgeführt.", "INFO", section="IPV64")
            else:
                log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR", section="IPV64")
            return result == "updated" or (log_success_if_nochg and result == "nochg")
        if provider.get("protocol") == "dyndns2":
            result = update_dyndns2(provider, ip, ip6)
            if result == "updated":
                log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section="DYNDNS2")
            elif result == "nochg":
                if log_success_if_nochg:
                    log(f"Provider '{provider.get('name')}' war bereits aktuell, kein Update durchgeführt.", "INFO", section="DYNDNS2")
            else:
                log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR", section="DYNDNS2")
            return result == "updated" or (log_success_if_nochg and result == "nochg")
    except Exception as e:
        log(f"Update für Provider '{provider.get('name')}' fehlgeschlagen: {e}", "ERROR", section=provider.get("name", "PROVIDER").upper())
        return False

def main():
    config_path = 'config/config.yaml'
    if not os.path.exists(config_path):
        setup_logging("INFO")
        log("config/config.yaml nicht gefunden! Bitte eigene Konfiguration bereitstellen oder config.example.yaml kopieren.\n"
            "Siehe Anleitung im Repository: https://github.com/alex-1987/dyndns-docker-client\n"
            "Beispiel für Docker Compose:\n"
            "  volumes:\n"
            "    - ./config:/app/config\n"
            "und lege deine config.yaml in das Verzeichnis ./config auf dem Host.",
            "CRITICAL"
        )
        sys.exit(1)
    with open(config_path, 'r') as f:
        try:
            config = yaml.safe_load(f)
        except Exception as e:
            setup_logging("INFO")
            log(f"Fehler beim Laden der config.yaml: {e}", "ERROR")
            sys.exit(1)
    # Setze Logging-Level aus Config (Default: INFO)
    loglevel = config.get("loglevel", "INFO")
    setup_logging(loglevel)
    last_config_mtime = os.path.getmtime(config_path)
    if not config or not isinstance(config, dict):
        log(
            "config.yaml ist leer oder ungültig! Bitte prüfe die Datei und orientiere dich an config.example.yaml.\n"
            "Siehe Anleitung im Repository: https://github.com/alex-1987/dyndns-docker-client",
            "CRITICAL"
        )
        sys.exit(1)
    if "providers" not in config or not isinstance(config["providers"], list) or not config["providers"]:
        log(
            "config.yaml enthält keine Provider! Bitte trage mindestens einen Provider unter 'providers:' ein.\n"
            "Siehe Anleitung und Beispiele im Repository: https://github.com/alex-1987/dyndns-docker-client",
            "CRITICAL"
        )
        sys.exit(1)
    if not validate_config(config):
        log("Konfiguration ungültig. Programm wird beendet.", "CRITICAL")
        sys.exit(1)
    timer = config.get('timer', 300)
    ip_service = config.get('ip_service', 'https://api.ipify.org')
    ip6_service = config.get('ip6_service', None)
    providers = config['providers']

    log(f"Teste Erreichbarkeit von ip_service: {ip_service}", section="MAIN")
    test_ip = get_public_ip(ip_service) if ip_service else None
    test_ip6 = get_public_ipv6(ip6_service) if ip6_service else None
    if not test_ip and not test_ip6:
        log("Programm wird beendet, da weder ip_service noch ip6_service erreichbar ist.", "CRITICAL")
        return
    if test_ip:
        log(f"ip_service erreichbar. Öffentliche IP: {test_ip}", section="MAIN")
    if test_ip6:
        log(f"ip6_service erreichbar. Öffentliche IPv6: {test_ip6}", section="MAIN")

    log("Starte Initial-Update-Durchlauf für alle Provider...", section="MAIN")
    failed_providers = []
    for provider in providers:
        result = update_provider(provider, test_ip, test_ip6)
        section = provider.get('name', 'PROVIDER').upper()
        if not (result or result == "nochg"):
            log(f"Provider '{provider.get('name')}' konnte initial nicht aktualisiert werden.", "WARNING", section=section)
            failed_providers.append(provider)

    last_ip = test_ip
    last_ip6 = test_ip6
    elapsed = 0
    check_interval = 2  # Sekunden, wie oft auf Config-Änderung geprüft wird

    log(f"Nächster Durchlauf in {timer} Sekunden...", section="MAIN")

    while True:
        time.sleep(check_interval)
        elapsed += check_interval

        # Prüfe, ob sich die Config geändert hat
        current_mtime = os.path.getmtime(config_path)
        if current_mtime != last_config_mtime:
            log("Änderung an config.yaml erkannt. Lade neue Konfiguration und starte einen neuen Durchlauf.", section="MAIN")
            with open(config_path, 'r') as f:
                try:
                    config = yaml.safe_load(f)
                except Exception as e:
                    log(f"Fehler beim Laden der config.yaml nach Änderung: {e}\nBitte prüfe die Datei und orientiere dich an config.example.yaml.", "ERROR")
                    continue
            if not validate_config(config):
                log("Konfiguration ungültig nach Änderung. Warte auf nächste Änderung...", "ERROR")
                continue
            timer = config.get('timer', 300)
            ip_service = config.get('ip_service', 'https://api.ipify.org')
            ip6_service = config.get('ip6_service', None)
            providers = config['providers']
            last_config_mtime = current_mtime
            current_ip = get_public_ip(ip_service) if ip_service else None
            current_ip6 = get_public_ipv6(ip6_service) if ip6_service else None
            if current_ip:
                log(f"Aktuelle öffentliche IP: {current_ip}", section="MAIN")
            if current_ip6:
                log(f"Aktuelle öffentliche IPv6: {current_ip6}", section="MAIN")
            failed_providers = []
            for provider in providers:
                result = update_provider(provider, current_ip, current_ip6)
                section = provider.get('name', 'PROVIDER').upper()
                if not (result or result == "nochg"):
                    log(f"Provider '{provider.get('name')}' konnte nach Config-Änderung nicht aktualisiert werden.", "WARNING", section=section)
                    failed_providers.append(provider)
            last_ip = current_ip
            last_ip6 = current_ip6
            elapsed = 0
            log(f"Nächster Durchlauf in {timer} Sekunden...", section="MAIN")
            continue

        # Timer-Update wie gehabt
        if elapsed >= timer:
            current_ip = get_public_ip(ip_service) if ip_service else None
            current_ip6 = get_public_ipv6(ip6_service) if ip6_service else None
            if current_ip:
                log(f"Aktuelle öffentliche IP: {current_ip}", section="MAIN")
            if current_ip6:
                log(f"Aktuelle öffentliche IPv6: {current_ip6}", section="MAIN")
            # Prüfe auf IP-Änderung oder Fehler-Provider
            ip_changed = (current_ip != last_ip) if ip_service else False
            ip6_changed = (current_ip6 != last_ip6) if ip6_service else False
            if ip_changed or ip6_changed or failed_providers:
                if ip_changed:
                    log(f"Neue IP erkannt: {current_ip} (vorher: {last_ip}) – Update wird durchgeführt.", section="MAIN")
                if ip6_changed:
                    log(f"Neue IPv6 erkannt: {current_ip6} (vorher: {last_ip6}) – Update wird durchgeführt.", section="MAIN")
                # Prüfe alle Provider, aber Fehler-Provider immer erneut!
                retry_providers = failed_providers.copy()
                failed_providers = []
                for provider in providers:
                    # Wenn Provider in retry_providers oder IP geändert, erneut versuchen
                    if provider in retry_providers or ip_changed or ip6_changed:
                        result = update_provider(provider, current_ip, current_ip6)
                        section = provider.get('name', 'PROVIDER').upper()
                        # Entfernt: doppeltes Fehler-Log
                        if not (result or result == "nochg"):
                            failed_providers.append(provider)
                last_ip = current_ip
                last_ip6 = current_ip6
                elapsed = 0
                log(f"Nächster Durchlauf in {timer} Sekunden...", section="MAIN")
            else:
                if current_ip:
                    log(f"IP unverändert ({current_ip}), kein Update notwendig.", section="MAIN")
                if current_ip6:
                    log(f"IPv6 unverändert ({current_ip6}), kein Update notwendig.", section="MAIN")
                elapsed = 0
                log(f"Nächster Durchlauf in {timer} Sekunden...", section="MAIN")

if __name__ == "__main__":
    main()