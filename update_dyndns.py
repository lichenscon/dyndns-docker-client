import requests
import yaml
import time

def get_public_ip(ip_service):
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"Fehler beim Abrufen der öffentlichen IP: {e}")
        return None

def get_public_ipv6(ip_service="https://api64.ipify.org"):
    try:
        response = requests.get(ip_service)
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"Fehler beim Abrufen der öffentlichen IPv6: {e}")
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
    print(f"cloudflare response: {resp.text}")

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
    print(f"ipv64 response: {response.text}")

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
    print(f"{provider.get('name', 'dyndns2')} response: {response.text}")

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
    print(f"{provider.get('name', 'provider')} response: {response.text}")

def main():
    last_ip = None
    while True:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        timer = config.get('timer', 300)
        ip_service = config.get('ip_service', 'https://api.ipify.org')
        providers = config['providers']

        current_ip = get_public_ip(ip_service)
        print(f"[INFO] Aktuelle öffentliche IP: {current_ip}")

        if not current_ip:
            print("[ERROR] Konnte öffentliche IP nicht ermitteln. Warte auf nächsten Versuch.")
        elif current_ip != last_ip:
            print(f"[INFO] Neue IP erkannt: {current_ip} (vorher: {last_ip}) – Update wird durchgeführt.")
            for provider in providers:
                try:
                    update_provider(provider, current_ip)
                    print(f"[SUCCESS] Update für Provider '{provider.get('name')}' erfolgreich.")
                except Exception as e:
                    print(f"[ERROR] Update für Provider '{provider.get('name')}' fehlgeschlagen: {e}")
            last_ip = current_ip
        else:
            print(f"[INFO] IP unverändert ({current_ip}), kein Update notwendig.")

        time.sleep(timer)

if __name__ == "__main__":
    main()