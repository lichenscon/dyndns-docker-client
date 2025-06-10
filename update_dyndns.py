import requests
import yaml
import time

def log(msg, level="INFO"):
    print(f"[{level}] {msg}", flush=True)

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
    # IDs automatisch holen
    zone_id = get_cloudflare_zone_id(api_token, zone)
    record_id = get_cloudflare_record_id(api_token, zone_id, record_name)
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    data = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "proxied": provider.get("proxied", False)
    }
    resp = requests.patch(url, json=data, headers=headers)
    log(f"cloudflare response: {resp.text}")

def update_ipv64(provider, ip, ip6=None):
    url = provider['url']
    params = {}
    # Domain-Parameter
    if 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    # Authentifizierung
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
    # IP-Parameter
    if ip:
        params['ip'] = ip
    if ip6:
        params['ip6'] = ip6
    response = requests.get(url, params=params, auth=auth, headers=headers)
    log(f"ipv64 response: {response.text}")

def update_dyndns2(provider, ip, ip6=None):
    url = provider['url']
    params = {}
    # Domain-Parameter
    if 'domain' in provider:
        params['domain'] = provider['domain']
    elif 'host' in provider:
        params['host'] = provider['host']
    # Authentifizierung
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
    # IP-Parameter
    if ip:
        params['ip'] = ip
    if ip6:
        params['ip6'] = ip6
    response = requests.get(url, params=params, auth=auth, headers=headers)
    log(f"{provider.get('name', 'dyndns2')} response: {response.text}")

def update_provider(provider, ip, ip6=None):
    if provider.get("name") == "cloudflare":
        update_cloudflare(provider, ip)
        return
    if provider.get("name") == "ipv64":
        update_ipv64(provider, ip, ip6)
        return
    if provider.get("protocol") == "dyndns2":
        update_dyndns2(provider, ip, ip6)
        return
    # Standard-Provider-Logik
    url = provider['url']
    params = provider.get('params', {}).copy()
    params['ip'] = ip
    auth = None
    if 'username' in params and 'password' in params:
        auth = (params.pop('username'), params.pop('password'))
    response = requests.get(url, params=params, auth=auth)
    log(f"{provider.get('name', 'provider')} response: {response.text}")

def main():
    log("DynDNS Client startet...")
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    timer = config.get('timer', 300)
    ip_service = config.get('ip_service', 'https://api.ipify.org')
    providers = config['providers']

    log(f"Teste Erreichbarkeit von ip_service: {ip_service}")
    test_ip = get_public_ip(ip_service)
    if not test_ip:
        log("Programm wird beendet, da ip_service nicht erreichbar ist.", "ERROR")
        return
    log(f"ip_service erreichbar. Öffentliche IP: {test_ip}")

    log("Starte Initial-Update-Durchlauf für alle Provider...")
    for provider in providers:
        result = update_provider(provider, test_ip)
        if result:
            log(f"Provider '{provider.get('name')}' initial erfolgreich aktualisiert.", "SUCCESS")
        else:
            log(f"Provider '{provider.get('name')}' konnte initial nicht aktualisiert werden.", "ERROR")

    last_ip = test_ip
    while True:
        current_ip = get_public_ip(ip_service)
        log(f"Aktuelle öffentliche IP: {current_ip}")
        if not current_ip:
            log("Konnte öffentliche IP nicht ermitteln. Warte auf nächsten Versuch.", "ERROR")
        elif current_ip != last_ip:
            log(f"Neue IP erkannt: {current_ip} (vorher: {last_ip}) – Update wird durchgeführt.")
            for provider in providers:
                result = update_provider(provider, current_ip)
                if result:
                    log(f"Provider '{provider.get('name')}' erfolgreich aktualisiert.", "SUCCESS")
                else:
                    log(f"Provider '{provider.get('name')}' konnte nicht aktualisiert werden.", "ERROR")
            last_ip = current_ip
        else:
            log(f"IP unverändert ({current_ip}), kein Update notwendig.")
        time.sleep(timer)

if __name__ == "__main__":
    main()