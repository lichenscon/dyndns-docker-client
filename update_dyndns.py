import os
import time
import requests
import yaml

def log(msg, level="INFO", section="MAIN"):
    print(f"[{level}] {section} --> {msg}", flush=True)

def get_public_ip(ip_service):
    try:
        response = requests.get(ip_service, timeout=10)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        log(f"Fehler beim Abrufen der öffentlichen IP: {e}", "ERROR")
        return None

def get_public_ipv6(ip_service="https://api64.ipify.org"):
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        log(f"Fehler beim Abrufen der öffentlichen IPv6: {e}", "ERROR")
        return None

def get_cloudflare_zone_id(api_token, zone_name):
    url = f"https://api.cloudflare.com/client/v4/zones?name={zone_name}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    if data.get("success") and data["result"]:
        return data["result"][0]["id"]
    raise Exception(f"Zone-ID für {zone_name} nicht gefunden: {data}")

def get_cloudflare_record_id(api_token, zone_id, record_name):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}"
    headers = {"Authorization": f"Bearer {api_token}"}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    if data.get("success") and data["result"]:
        return data["result"][0]["id"]
    raise Exception(f"DNS-Record-ID für {record_name} nicht gefunden: {data}")

def update_cloudflare(provider, ip):
    api_token = provider['api_token']
    zone = provider['zone']
    record_name = provider['record_name']
    zone_id = get_cloudflare_zone_id(api_token, zone)
    record_id = get_cloudflare_record_id(api_token, zone_id, record_name)
    # Hole aktuellen Record
    url_get = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    resp_get = requests.get(url_get, headers=headers)
    data = resp_get.json()
    if data.get("success") and data["result"]:
        current_content = data["result"]["content"]
        if current_content == ip:
            log(f"Kein Update notwendig (IP bereits gesetzt: {ip}).", "INFO", section="CLOUDFLARE")
            return True
    # Update durchführen
    url_patch = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    data_patch = {
        "type": "A",
        "name": record_name,
        "content": ip
    }
    resp_patch = requests.patch(url_patch, json=data_patch, headers=headers)
    log(f"cloudflare response: {resp_patch.text}", section="CLOUDFLARE")
    return resp_patch.ok

def update_ipv64(provider, ip, ip6=None):
    url = provider['url']
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
    # Updatelimit-Check
    if "overcommited" in response.text or response.status_code == 403:
        log("Updateintervall bei ipv64.net überschritten! Updatelimit erreicht.", "ERROR", section="IPV64")
        return False
    return True

def update_dyndns2(provider, ip, ip6=None):
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
    # Rückgabewerte: "updated", "nochg", False
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

def update_provider(provider, ip, ip6=None):
    try:
        if provider.get("name") == "cloudflare":
            update_cloudflare(provider, ip)
            log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section="CLOUDFLARE")
            return True
        if provider.get("name") == "ipv64":
            result = update_ipv64(provider, ip, ip6)
            if result:
                log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section="IPV64")
            else:
                log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR", section="IPV64")
            return result
        if provider.get("protocol") == "dyndns2":
            result = update_dyndns2(provider, ip, ip6)
            if result == "updated":
                log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section="DYNDNS2")
            elif result == "nochg":
                log(f"Provider '{provider.get('name')}' war bereits aktuell, kein Update durchgeführt.", "INFO", section="DYNDNS2")
            else:
                log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR", section="DYNDNS2")
            return result == "updated"
        # Standard-Provider-Logik
        url = provider['url']
        params = provider.get('params', {}).copy()
        params['ip'] = ip
        auth = None
        if 'username' in params and 'password' in params:
            auth = (params.pop('username'), params.pop('password'))
        response = requests.get(url, params=params, auth=auth)
        log(f"{provider.get('name', 'provider')} response: {response.text}", section=provider.get('name', 'PROVIDER').upper())
        log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section=provider.get('name', 'PROVIDER').upper())
        return True
    except Exception as e:
        log(f"Update für Provider '{provider.get('name')}' fehlgeschlagen: {e}", "ERROR", section=provider.get("name", "PROVIDER").upper())
        return False

def main():
    log("DynDNS Client startet...", section="MAIN")
    config_path = 'config.yaml'
    last_config_mtime = os.path.getmtime(config_path)
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    timer = config.get('timer', 300)
    ip_service = config.get('ip_service', 'https://api.ipify.org')
    providers = config['providers']

    log(f"Teste Erreichbarkeit von ip_service: {ip_service}", section="MAIN")
    test_ip = get_public_ip(ip_service)
    if not test_ip:
        log("Programm wird beendet, da ip_service nicht erreichbar ist.", "ERROR")
        return
    log(f"ip_service erreichbar. Öffentliche IP: {test_ip}", section="MAIN")

    log("Starte Initial-Update-Durchlauf für alle Provider...", section="MAIN")
    for provider in providers:
        result = update_provider(provider, test_ip)
        section = provider.get('name', 'PROVIDER').upper()
        if result:
            log(f"Provider '{provider.get('name')}' initial erfolgreich aktualisiert.", "SUCCESS", section=section)
        else:
            log(f"Provider '{provider.get('name')}' konnte initial nicht aktualisiert werden.", "ERROR", section=section)

    last_ip = test_ip
    elapsed = 0
    check_interval = 2  # Sekunden, wie oft auf Config-Änderung geprüft wird

    while True:
        time.sleep(check_interval)
        elapsed += check_interval

        # Prüfe, ob sich die Config geändert hat
        current_mtime = os.path.getmtime(config_path)
        if current_mtime != last_config_mtime:
            log("Änderung an config.yaml erkannt. Lade neue Konfiguration und starte einen neuen Durchlauf.", section="MAIN")
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            timer = config.get('timer', 300)
            ip_service = config.get('ip_service', 'https://api.ipify.org')
            providers = config['providers']
            last_config_mtime = current_mtime
            current_ip = get_public_ip(ip_service)
            log(f"Aktuelle öffentliche IP: {current_ip}", section="MAIN")
            for provider in providers:
                result = update_provider(provider, current_ip)
                section = provider.get('name', 'PROVIDER').upper()
                if result:
                    log(f"Provider '{provider.get('name')}' nach Config-Änderung erfolgreich aktualisiert.", "SUCCESS", section=section)
                else:
                    log(f"Provider '{provider.get('name')}' konnte nach Config-Änderung nicht aktualisiert werden.", "ERROR", section=section)
            last_ip = current_ip
            elapsed = 0  # Timer zurücksetzen
            log(f"Nächster Durchlauf in {timer} Sekunden...", section="MAIN")
            continue

        # Timer-Update wie gehabt
        if elapsed >= timer:
            current_ip = get_public_ip(ip_service)
            log(f"Aktuelle öffentliche IP: {current_ip}", section="MAIN")
            if not current_ip:
                log("Konnte öffentliche IP nicht ermitteln. Warte auf nächsten Versuch.", "ERROR", section="MAIN")
            elif current_ip != last_ip:
                log(f"Neue IP erkannt: {current_ip} (vorher: {last_ip}) – Update wird durchgeführt.", section="MAIN")
                for provider in providers:
                    result = update_provider(provider, current_ip)
                    section = provider.get('name', 'PROVIDER').upper()
                    if result:
                        log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS", section=section)
                    else:
                        log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR", section=section)
                last_ip = current_ip
            else:
                log(f"IP unverändert ({current_ip}), kein Update notwendig.", section="MAIN")            elapsed = 0
            log(f"Nächster Durchlauf in {timer} Sekunden...", section="MAIN")
_ == "__main__":


    main()if __name__ == "__main__":    main()